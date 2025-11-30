import threading
import socket
import struct
import re
import paramiko
from collections import defaultdict

# ---- NetFlow v5 collector (simple, fixed-format parser) ----
# NetFlow v5 packet format reference
NFV5_HEADER_FMT = "!HHIIIIBBH"   # version(2), count(2), sys_uptime(4), unix_secs(4), unix_nsecs(4), flow_seq(4), engine_type(1), engine_id(1), sampling(2)
NFV5_RECORD_FMT = "!IIIHHIIIIHHBBBBHHBBH"  # 48 bytes per record
DEBUG = False

# --- [UTIL|FORMAT] ip_to_str ------------------------------------
def ip_to_str(ip_int: int) -> str:
    """Convert a 32-bit integer into dotted-quad IPv4 string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))

class NetflowV5Collector(threading.Thread):
    """
    Minimal NetFlow v5 collector; keeps cumulative TX bytes per 5-tuple
    keyed as (src_ip, src_port, dst_ip, dst_port, proto).
    We treat 'bytes' as sent from src_ip to dst_ip. For our purpose we care
    about LAN device src → remote dst (TCP proto=6).
    """

    # --- [NETFLOW|INIT] __init__ ------------------------------------
    def __init__(self, bind_ip, bind_port):
        super().__init__(daemon=True)
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.bytes_by_flow = defaultdict(int)  # key -> total_bytes

    # --- [NETFLOW|LOOP] run ------------------------------------
    def run(self):
        # Purpose: Collect v5 packets; accumulate bytes per 5-tuple
        self.bind_error = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # SO_REUSEADDR doesn't let two processes share the same UDP port on Windows;
            # we just try to bind and report a friendly message if it's taken.
            sock.bind((self.bind_ip, self.bind_port))
        except OSError as e:
            self.bind_error = f"NetFlow bind failed on {self.bind_ip}:{self.bind_port} — {e}"
            # Don't crash the whole app; just stop this collector thread.
            return
        sock.settimeout(1.0)
        while not self.stop.is_set():
            try:
                data, addr = sock.recvfrom(1500)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                if len(data) < 24:
                    continue
                header = struct.unpack(NFV5_HEADER_FMT, data[:24])
                version, count = header[0], header[1]
                if version != 5:
                    continue
                offset = 24
                for _ in range(count):
                    if offset + 48 > len(data):
                        break
                    rec = struct.unpack(NFV5_RECORD_FMT, data[offset:offset+48])
                    offset += 48
                    srcaddr = ip_to_str(rec[0])
                    dstaddr = ip_to_str(rec[1])
                    dOctets = rec[6]
                    srcport = rec[9]
                    dstport = rec[10]
                    proto   = rec[12]
                    key = (srcaddr, srcport, dstaddr, dstport, proto)
                    with self.lock:
                        self.bytes_by_flow[key] += dOctets
            except Exception:
                continue
            
        try:
            sock.close()
        except Exception:
            pass

    # --- [NETFLOW|QUERY] get_bytes_for ------------------------------------
    def get_bytes_for(self, src_ip, src_port, dst_ip, dst_port):
        key = (src_ip, src_port, dst_ip, dst_port, 6)  # TCP proto=6
        with self.lock:
            return self.bytes_by_flow.get(key, 0)

class ConntrackCollectorSSH(threading.Thread):
    """
    Polls the UDM over SSH and parses per-flow byte counters from conntrack.
    Tries 'device' creds first, then 'console' creds. Supports keyboard-interactive.
    Exposes get_bytes_for(...).
    """
    # --- [SSH|INIT] __init__ ------------------------------------
    def __init__(self, host, port, device_creds, console_creds, interval=3):
        super().__init__(daemon=True)
        self._acct_tried = False
        self.host = host
        self.port = port
        self.device = device_creds or {}
        self.console = console_creds or {}
        self.interval = interval
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.bytes_by_flow = defaultdict(int)
        self.status_msg = None
        self._ssh = None
        self._who = None  # "device" or "console"
        self._rx = re.compile(
            r"\btcp\b.*?\bsrc=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+sport=(?P<sp>\d+)\s+dport=(?P<dp>\d+).*?\bbytes=(?P<bytes>\d+)",
            re.IGNORECASE
        )

    # --- [SSH|AUTH] _kbdint ------------------------------------
    def _kbdint(self, title, instructions, prompt_list):
        # Attempt to return the right password for whichever account we tried last
        pwd = ""
        if self._who == "device":
            pwd = self.device.get("password") or ""
        elif self._who == "console":
            pwd = self.console.get("password") or ""
        responses = []
        for prompt, echo in prompt_list:
            # Most UDMs prompt like "Password:" (no echo)
            responses.append(pwd)
        return responses

    # --- [SSH|AUTH] _try_connect ------------------------------------
    def _try_connect(self, which: str):
        """
        Try normal password/key auth first. If the server only allows
        keyboard-interactive, fall back to Transport.auth_interactive().
        """
        if self._ssh:
            try: self._ssh.close()
            except Exception: pass
            self._ssh = None

        creds   = self.device if which == "device" else self.console
        user    = (creds.get("user") or "").strip()
        pwd     = creds.get("password") or ""
        keyfile = creds.get("keyfile") or ""
        keypass = creds.get("key_passphrase") or ""

        if not user:
            raise RuntimeError(f"{which} user not set")

        key_obj = None
        if keyfile:
            for KeyCls in (paramiko.RSAKey, paramiko.Ed25519Key):
                try:
                    key_obj = KeyCls.from_private_key_file(keyfile, password=(keypass or None))
                    break
                except Exception:
                    key_obj = None

        self._who = which

        # 1) Try normal auth (password/publickey)
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if DEBUG:
            print(f"[SSH DEBUG] trying {self.host}:{self.port} as user={user!r}")
        
        try:
            cli.connect(
                self.host,
                port=self.port,
                username=user,
                password=(pwd or None),
                pkey=key_obj,
                look_for_keys=False,
                allow_agent=False,
                auth_timeout=8.0,
                banner_timeout=8.0,
            )
            self._ssh = cli
            self.status_msg = f"OK ({which} auth: password/publickey)"
            return True

        except paramiko.ssh_exception.BadAuthenticationType as e:
            # 2) Keyboard-interactive fallback if offered by the server
            allowed = set((getattr(e, "allowed", None) or []))
            if "keyboard-interactive" not in allowed:
                raise

            t = paramiko.Transport((self.host, self.port))
            t.start_client(timeout=8.0)

            def _kbd_handler(title, instructions, prompts):
                # Provide password to each prompt
                return [pwd for _prompt, _echo in prompts]

            try:
                t.auth_interactive(user, _kbd_handler)
            except paramiko.ssh_exception.AuthenticationException as e2:
                t.close()
                raise e2

            cli2 = paramiko.SSHClient()
            cli2._transport = t
            self._ssh = cli2
            self.status_msg = f"OK ({which} auth: keyboard-interactive)"
            return True

        except Exception:
            # Let caller try the other cred set
            raise

    # --- [SSH|AUTH] _ensure_connected ------------------------------------
    def _ensure_connected(self):
        errors = []

        for which in ("device", "console"):
            creds = self.device if which == "device" else self.console
            if not (creds.get("user") or "").strip():
                # no username configured for this section; skip it gracefully
                continue
            try:
                if self._try_connect(which):
                    self.status_msg = f"OK ({which} auth)"
                    return
            except Exception as e:
                errors.append(f"{which}: {e}")
                if DEBUG:
                    print(f"[SSH DEBUG] error during connect: {errors}")

        if errors:
            raise RuntimeError("SSH connect failed — " + " ; ".join(errors))
        else:
            raise RuntimeError("SSH connect failed — no SSH credentials configured (device/console)")

    # --- [SSH|EXEC] _exec_once ------------------------------------
    def _exec_once(self, cmd_list):
        if self._ssh is None:
            self._ensure_connected()
        for cmd in cmd_list:
            stdin, stdout, stderr = self._ssh.exec_command(cmd, timeout=10.0)
            out = stdout.read().decode("utf-8", "replace")
            if out.strip():
                return out
        return ""

    # --- [SSH|POLL] _poll ------------------------------------
    # Purpose: SSH → conntrack; parse bytes=; update map
    def _poll(self):
        # Ensure conntrack accounting is on so we get bytes= fields
        if not self._acct_tried:
            try:
                self._exec_once([
                    "sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null",
                    "echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null",
                ])
            except Exception:
                pass
            self._acct_tried = True

        # Prefer native conntrack; fallback to /proc
        cmds = [
            "conntrack -L -p tcp -o extended 2>/dev/null",
            "cat /proc/net/nf_conntrack 2>/dev/null | grep -i 'tcp'",
        ]
        try:
            text = self._exec_once(cmds)
        except Exception as e:
            self.status_msg = f"SSH error: {e}"
            try:
                if self._ssh:
                    self._ssh.close()
            except Exception:
                pass
            self._ssh = None
            return

        counts = {}
        for line in text.splitlines():
            m = self._rx.search(line)
            if not m:
                continue
            src = m.group("src"); dst = m.group("dst")
            sp  = int(m.group("sp")); dp = int(m.group("dp"))
            b   = int(m.group("bytes"))
            key = (src, sp, dst, dp, 6)
            prev = counts.get(key, 0)
            counts[key] = b if b > prev else prev

        with self.lock:
            for k, b in counts.items():
                if b > self.bytes_by_flow.get(k, 0):
                    self.bytes_by_flow[k] = b

        if not self.status_msg or not self.status_msg.startswith("OK"):
            self.status_msg = "OK"

    # --- [SSH|LOOP] run ------------------------------------
    def run(self):
        if paramiko is None:
            self.status_msg = "paramiko not installed"
            return
        while not self.stop.is_set():
            self._poll()
            self.stop.wait(self.interval)

    # --- [SSH|QUERY] get_bytes_for ------------------------------------
    def get_bytes_for(self, src_ip, src_port, dst_ip, dst_port):
        key = (src_ip, src_port, dst_ip, dst_port, 6)
        with self.lock:
            return self.bytes_by_flow.get(key, 0)

    # --- [SSH|NEIGH] get_ip_neigh_snapshot ------------------------------------
    def get_ip_neigh_snapshot(self):
        """
        Returns [(ip, mac)] by asking the router: prefer 'ip -4 neigh', fallback 'arp -an'.
        """
        try:
            text = self._exec_once([
                "ip -4 neigh show 2>/dev/null",
                "arp -an 2>/dev/null",
            ]) or ""
        except Exception:
            return []

        rows = []
        for line in text.splitlines():
            line = line.strip()
            # ip neigh format: "192.168.1.50 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            m = re.search(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*?\blladdr\s+(?P<mac>[0-9a-f:]{17})\b", line, re.I)
            if m:
                rows.append((m.group("ip"), m.group("mac")))
                continue
            # arp -an format: "? (192.168.1.50) at aa:bb:cc:dd:ee:ff \[.*\] on br0"
            m = re.search(r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-f:]{17})", line, re.I)
            if m:
                rows.append((m.group("ip"), m.group("mac")))
        return rows

    # --- [SSH|DHCP/DNS] gfetch_dhcp_leases ------------------------------------
    def fetch_dhcp_leases(self):
        
        # Local import to avoid circular dependency with monitor_core
        from monitor_core import normalize_mac
        
        try:
            out = self._ssh_exec("cat /run/dnsmasq/leases")
            leases = {}
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    mac = normalize_mac(parts[1])
                    ip  = parts[2]
                    host = parts[3].strip("*")
                    leases[ip] = {"mac": mac, "hostname": host}
            return leases
        except:
            return {}
