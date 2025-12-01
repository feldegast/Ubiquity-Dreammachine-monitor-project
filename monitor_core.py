# monitor_core.py

# =============================================================================
# SECTION: IMPORTS & GLOBALS
# =============================================================================
# region IMPORTS & GLOBALS

from __future__ import annotations

# --- Standard library imports that MonitorCore uses ---
import csv
import ipaddress
import threading
import time
import socket
import queue
import struct
import traceback

#from datetime import datetime
from typing import Any, Iterable, Optional
from collections import defaultdict

# --- Project imports (SNMP helpers, collectors) ---
from collectors import ConntrackCollectorSSH   # if used inside MonitorCore
# from collectors import NetflowV5Collector    # only if MonitorCore touches it directly

from vendor_resolver import normalize_mac

# endregion IMPORTS & GLOBALS

# If MonitorCore calls any SNMP helpers / OID functions, import them:
# from snmp_helpers import (
#     _merge_ip2mac_from_snmp,
#     _get_snmp_table,
#     ...
# )

from app_paths import (
    BASE_DIR,
    DATA_DIR,
    CONFIG_FILE,
    SSH_SECRETS_FILE,
    LOG_FILENAME,
    ALERT_LOG_FILENAME,
    BASE_OUI_FILE,
    OVERRIDE_OUI_FILE,
    HOST_ALIAS_PATH,
    MAC_LABELS_PATH,
)

# If you had LOG_HEADERS / ALERT_HEADERS, move them here too:
# LOG_HEADERS = [...]
# ALERT_LOG_HEADERS = [...]

# =============================================================================
# MonitorCore tying SNMP + NetFlow together
# =============================================================================

# --- Constants used by MonitorCore ------------------------------------
# Treat these as unknown
ZERO_MACS = {"00:00:00:00:00:00", "00-00-00-00-00-00", "", None}
POLL_INTERVAL_SECONDS = 0  # 5 how often to poll SNMP - this needs to be passed in from main.py as it is in the config file
ALERT_THRESHOLD_BYTES = 0  # 1 MB per single connection  # 1 MB - this needs to be passed in from main.py as it is in the config file
ALERT_COOLDOWN_SECS = 0  # 5 minutes between alerts for same connection - this needs to be passed in from main.py as it is in the config file
ROUTER_IP: str = "0.0.0.0"
SNMP_COMMUNITY: str = "public"
_LAN_NETWORKS: list[ipaddress._BaseNetwork] = []

DEBUG: bool = False

OID_ipNetToMediaNetAddress: str = ""
OID_ipNetToMediaPhysAddress: str = ""
OID_ipNetToPhysicalPhysAddress: str = ""
OID_atNetAddress: str = ""
OID_atPhysAddress: str = ""

_WHITELIST_DESTS: set[str] = set()
_SILENCED_MACS: set[str] = set()

# --- [UTIL|IPRANGE] _is_lan_client_ip ------------------------------------
def _is_lan_client_ip(ip: str) -> bool:
    # Purpose: Filter to private/LAN IPs (or user-listed prefixes)
    try:
        ipobj = ipaddress.ip_address(ip)
        # Never treat loopback or the router itself as a client
        if ipobj.is_loopback or ip == ROUTER_IP:
            return False
        if _LAN_NETWORKS:
            return any(ipobj in net for net in _LAN_NETWORKS)
        else:
            # Auto-mode: accept any private address (10/8, 172.16/12, 192.168/16)
            return ipobj.is_private
    except Exception:
        return False

# --- [IP-MIB] _merge_ip2mac_from_snmp ------------------------------------
def _merge_ip2mac_from_snmp():
    """Build best-effort ip→mac map using all available tables."""
    ip2mac = {}
    # classic ipNetToMedia*
    for _ifidx, ip, mac in walk_arp_table():
        try:
            ipaddress.ip_address(ip)
            if mac and mac != "00:00:00:00:00:00":
                ip2mac[ip] = mac
        except Exception:
            continue
    # ipNetToPhysical*
    for ip, mac in _walk_ipnet_physical():
        try:
            ipaddress.ip_address(ip)
            ip2mac[ip] = mac
        except Exception:
            continue
    # AT-MIB fallback
    if not ip2mac:
        for ip, mac in _walk_at_mib():
            try:
                ipaddress.ip_address(ip)
                if mac and mac != "00:00:00:00:00:00":
                    ip2mac[ip] = mac
            except Exception:
                continue
    return ip2mac

def _parse_mac_from_val(val: Any) -> str:
    """Placeholder; real implementation is wired in from main.py."""
    return "00:00:00:00:00:00"

def snmp_walk(host: str, community: str, oid: str) -> Iterable[tuple[str, Any]]:
    """Placeholder; real implementation is wired in from main.py."""
    raise RuntimeError("monitor_core.snmp_walk has not been bound by main.py")

# --- [SNMP|ARP] walk_arp_table ------------------------------------
# Purpose: Build (ifIndex, ip, mac) rows by merging ipNetToMedia* and ipNetToPhysical*
def walk_arp_table():
    return []

# --- [IP-MIB] _walk_at_mib ------------------------------------
def _walk_at_mib():
    """Legacy AT-MIB fallback: returns [(ip, mac)]."""
    ips, macs = {}, {}
    # First pass: collect IP addresses seen in atNetAddress
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_atNetAddress):
            parts = str(oid).split(".")
            if len(parts) < 4:
                continue
            try:
                ip = ".".join(parts[-4:])
                ips[ip] = True
            except Exception:
                continue
    except Exception:
        pass

    # Second pass: collect MAC addresses from atPhysAddress
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_atPhysAddress):
            parts = str(oid).split(".")
            if len(parts) < 4:
                continue
            try:
                ip = ".".join(parts[-4:])
                mac = _parse_mac_from_val(val)
                macs[ip] = mac
            except Exception:
                continue
    except Exception:
        pass

    rows = []
    for ip in set(ips) | set(macs):
        rows.append((ip, macs.get(ip, "00:00:00:00:00:00")))
    return rows

# --- [IP-MIB|NEIGHBOR] _walk_ipnet_physical ------------------------------------
def _walk_ipnet_physical():
    """Return [(ip, mac)] via IP-MIB ipNetToPhysicalPhysAddress (IPv4 only)."""
    rows = []
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_ipNetToPhysicalPhysAddress):
            parts = [int(x) for x in str(oid).split(".")]
            if len(parts) < 6: continue
            addr_len = parts[-5]; addr_type = parts[-6]
            if addr_type != 1 or addr_len != 4:  # IPv4 only
                continue
            a,b,c,d = parts[-4:]
            ip = f"{a}.{b}.{c}.{d}"
            mac = _parse_mac_from_val(val)
            if mac and mac != "00:00:00:00:00:00":
                rows.append((ip, mac))
    except Exception:
        pass
    return rows

def walk_tcp_connections() -> list[dict[str, Any]]:
    """Placeholder; real implementation is wired in from main.py."""
    return []

def vendor_for_mac(mac: Optional[str]) -> str:
    """
    Placeholder so monitor_core can call vendor_for_mac without NameError.
    main.py will overwrite monitor_core.vendor_for_mac with the real implementation.
    """
    return "Unknown"

# ---- Monitor core tying SNMP + NetFlow together ----
class MonitorCore:
    # --- [CORE|INIT] __init__ ------------------------------------
    def __init__(self, nf_collector=None):
        self.stop = threading.Event()
        self.data_lock = threading.Lock()
        self.conn_map = {}  # key -> record (augmented)
        self.aggregates = defaultdict(
            lambda: defaultdict(lambda: {"sightings": 0, "bytes": 0})
        )
        self.ip2mac = {}
        self._last_ip2mac_count = None
        self.nf = nf_collector

        # Lightweight debug counters for the status line
        self.last_counts = {"arp": 0, "tcp": 0, "flows": 0}

        # Startup progress state (read by the UI for the 6-step dialog)
        self.startup_total_steps = 6
        self.startup_step_index = 0
        self.startup_step_label = ""
        self.startup_done = False

        self._log_init()

        self.alert_q = queue.Queue()
        self._alerts_last_sent = {}  # key -> last_alert_epoch
        
        # Init alert CSV
        try:
            with open(ALERT_LOG_FILENAME, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if f.tell() == 0:
                    w.writerow(["timestamp","local_ip","local_port","local_mac","vendor",
                                "remote_ip","remote_port","hostname","bytes_tx","note"])
        except Exception:
            pass

    # --- [CORE|INIT] _set_startup_step ------------------------------------
    def _set_startup_step(self, index: int, label: str) -> None:
        """
        Record the current startup phase for the UI.
        Called only from the core thread; the UI reads these fields.
        """
        self.startup_step_index = index
        self.startup_step_label = label

    # --- MAC Lookup (simple version) ------------------------------------
    def get_mac_for_ip(self, ip: str) -> str | None:
        # Return cached value if present
        mac = self.ip2mac.get(ip)
        if mac:
            return mac

        # Otherwise try to refresh ARP table
        try:
            self._refresh_arp()
            mac = self.ip2mac.get(ip)
            return mac
        except Exception:
            return None

    # =============================================================================
    # SECTION: STORAGE (files, CSV/JSON, load/save)
    # =============================================================================
    # region STORAGE

   # --- [ALERT] _alert_emit ------------------------------------
   # Purpose: Queue + CSV persist for threshold hits
    def _alert_emit(self, rec, note="≥ threshold"):
        nowiso = datetime.now().isoformat(timespec="seconds")
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(rec["remote_ip"])[0]
        except Exception:
            hostname = ""
        # enqueue for UI
        alert = {
            "time": nowiso,
            "local": f'{rec["local_ip"]}:{rec["local_port"]}',
            "mac": rec["local_mac"],
            "vendor": rec["vendor"],
            "remote": f'{rec["remote_ip"]}:{rec["remote_port"]}',
            "hostname": hostname,
            "bytes": rec.get("bytes_tx") or 0,
            "note": note,
        }
        try:
            self.alert_q.put_nowait(alert)
        except Exception:
            pass
        # persist
        try:
            with open(ALERT_LOG_FILENAME, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    nowiso, rec["local_ip"], rec["local_port"], rec["local_mac"], rec["vendor"],
                    rec["remote_ip"], rec["remote_port"], hostname, rec.get("bytes_tx") or 0, note
                ])
        except Exception:
            pass

    # --- [STORAGE|CSVINIT] _log_init ------------------------------------
    def _log_init(self):
        try:
            with open(LOG_FILENAME, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if f.tell() == 0:
                    w.writerow(["timestamp","local_ip","local_port","local_mac","vendor",
                                "remote_ip","remote_port","state","bytes_tx","over_1mb"])
        except Exception:
            pass

    # --- [STORAGE|CSVAPPEND] _log_row ------------------------------------
    def _log_row(self, row):
        try:
            with open(LOG_FILENAME, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)
        except Exception:
            pass
 
    # endregion STORAGE

    # --- [SNMP|ARP] _refresh_arp ------------------------------------
    def _refresh_arp(self):
        # SNMP-first
        ip2mac = _merge_ip2mac_from_snmp()

        # SSH fallback (see next step) — only if still empty
        if not ip2mac and isinstance(self.nf, ConntrackCollectorSSH):
            for ip, mac in self.nf.get_ip_neigh_snapshot():
                try:
                    ipaddress.ip_address(ip)
                    if mac and mac != "00:00:00:00:00:00":
                        ip2mac[ip] = mac.upper()
                except Exception:
                    continue

        self.last_counts["arp"] = len(ip2mac)
        self.ip2mac = ip2mac

    # --- [FALLBACK|FLOWS] _flows_from_conntrack ------------------------------------
    def _flows_from_conntrack(self):
        """
        If we have an SSH conntrack collector but SNMP returned no connections,
        synthesize rows from the conntrack bytes map.
        Returns a list of dicts like walk_tcp_connections() would.
        """
        flows = []
        if not isinstance(self.nf, ConntrackCollectorSSH):
            return flows

        # Snapshot keys to avoid locking for long
        try:
            with self.nf.lock:
                items = list(self.nf.bytes_by_flow.items())
        except Exception:
            items = []

        for (src_ip, src_port, dst_ip, dst_port, proto), _b in items:
            if proto != 6:  # TCP only
                continue

            # Heuristic: LAN client is the private IP
            def _is_priv(ip):
                try:
                    return ipaddress.ip_address(ip).is_private
                except Exception:
                    return False

            if _is_priv(src_ip) and not _is_priv(dst_ip):
                local_ip, local_port = src_ip, src_port
                remote_ip, remote_port = dst_ip, dst_port
            elif _is_priv(dst_ip) and not _is_priv(src_ip):
                # rare case: reverse (download). Still show from local → remote
                local_ip, local_port = dst_ip, dst_port
                remote_ip, remote_port = src_ip, src_port
            else:
                # both private or both public — skip (can’t tell)
                continue

            # Respect LAN filter
            if not _is_lan_client_ip(local_ip):
                continue

            flows.append({
                "local_ip": local_ip,
                "local_port": int(local_port),
                "remote_ip": remote_ip,
                "remote_port": int(remote_port),
                "state": "established"  # we don't have states from conntrack listing here
            })
        return flows

    # =============================================================================
    # SECTION: AGGREGATION (flows, bytes, top-N)
    # =============================================================================
    # region AGGREGATION

    # --- [CORE|UPDATE] _update_connections ------------------------------------
    # Purpose: Build connections from NetFlow/conntrack; update conn_map, aggregates, alerts
    def _update_connections(self, startup: bool = False):
        now_iso = datetime.now().isoformat(timespec="seconds")

        if startup:
            # Step 4: we’re about to read conntrack / NetFlow / TCP stats
            try:
                self._set_startup_step(4, "Read conntrack / netstat / NetFlow")
            except Exception:
                pass

        conns: list[dict[str, Any]] = []
        flow_map_size = 0

        # --- Build "connection" dicts from nf.bytes_by_flow (NetFlow or conntrack SSH) ---
        if self.nf:
            try:
                with self.nf.lock:
                    items = list(getattr(self.nf, "bytes_by_flow", {}).items())
            except Exception:
                items = []

            flow_map_size = len(items)

            for (s_ip, s_po, d_ip, d_po, proto), _bytes in items:
                # TCP only
                if proto != 6:
                    continue

                # Only flows from LAN clients
                if not _is_lan_client_ip(s_ip):
                    continue

                if d_ip == "0.0.0.0":
                    continue

                conns.append(
                    {
                        "local_ip": s_ip,
                        "local_port": int(s_po),
                        "remote_ip": d_ip,
                        "remote_port": int(d_po),
                        "state": "established",
                    }
                )

        # record counters for status line
        self.last_counts["tcp"] = len(conns)
        self.last_counts["flows"] = flow_map_size

        if DEBUG:
            print(
                f"[DEBUG] SNMP connections used this cycle: {len(conns)}, "
                f"flow-derived count: {flow_map_size}"
            )

        # --- Merge into conn_map + aggregates + alerts ---
        with self.data_lock:
            for c in conns:
                local_ip    = c.get("local_ip")
                local_port  = c.get("local_port")
                remote_ip   = c.get("remote_ip")
                remote_port = c.get("remote_port")
                state       = c.get("state", "unknown")

                # Skip junk
                if not local_ip or not remote_ip:
                    continue

                # Only treat LAN clients as "local"
                if not _is_lan_client_ip(local_ip):
                    continue

                # MAC + vendor
                mac = self.get_mac_for_ip(local_ip) or "00:00:00:00:00:00"
                vendor = vendor_for_mac(mac)

                key = (local_ip, local_port, remote_ip, remote_port)

                # --- Optional suppressors (whitelist/silence) ---
                dest_tag = f"{remote_ip}:{remote_port}"
                if dest_tag in _WHITELIST_DESTS:
                    continue

                if mac in _SILENCED_MACS:
                    continue

                # --- Upsert connection record ---
                rec = self.conn_map.get(key)
                if rec is None:
                    rec = {
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "local_mac": mac,
                        "vendor": vendor,
                        "first_seen": now_iso,
                        "last_seen": now_iso,
                        "bytes_tx": 0,
                        "over_1mb": False,
                    }
                    self.conn_map[key] = rec
                else:
                    rec["last_seen"] = now_iso
                    rec["state"] = state
                    rec["local_mac"] = mac
                    rec["vendor"] = vendor

                # --- Bytes from nf collector ---
                if self.nf:
                    try:
                        b = self.nf.get_bytes_for(local_ip, local_port, remote_ip, remote_port)
                    except Exception:
                        b = rec.get("bytes_tx", 0)
                    rec["bytes_tx"] = b

                    # Threshold detection
                    if b >= ALERT_THRESHOLD_BYTES and not rec.get("over_1mb", False):
                        rec["over_1mb"] = True
                        last_alert = self._alerts_last_sent.get(key, 0.0)
                        now_mono = time.monotonic()
                        if now_mono - last_alert >= ALERT_COOLDOWN_SECS:
                            self._alerts_last_sent[key] = now_mono
                            self._alert_emit(rec)

                # --- Aggregates per (MAC, remote_ip:port) ---
                agg = self.aggregates[mac][(remote_ip, remote_port)]
                agg["sightings"] += 1
                agg["bytes"] = max(agg["bytes"], rec["bytes_tx"] or 0)

        if startup:
            # Step 5: enrichment finished (MAC / vendor / labels applied)
            try:
                self._set_startup_step(5, "Enrich rows with MAC/vendor/labels")
            except Exception:
                pass

            if DEBUG:
                print("[DEBUG] core conn_map size:", len(self.conn_map))

    # endregion  # AGGREGATION

    # --- [CORE] Provide rows for UI / clipboard ----------------------------------
    def get_active_rows(self, limit: int = 200) -> list[dict]:
        """
        Return a list of 'active connection' dicts.
        Expected keys (best-effort): local_ip, local_port, remote_ip, remote_port,
        tcp_state/state, first_seen, last_seen, bytes/bytes_tx, local_mac.
        """
        try:
            # If your engine already maintains a map/dict; otherwise adapt here.
            # This assumes self.conn_map is a dict of {key: rec}
            base = list(getattr(self, "conn_map", {}).values())
        except Exception:
            base = []

        # Sort by last_seen desc if available
        def _key(rec):
            return rec.get("last_seen") or rec.get("first_seen") or ""
        base.sort(key=_key, reverse=True)
        return base[:limit]

    def prepare_row_for_ui(self, rec: dict) -> dict:
        """
        Normalize one record for UI:
        - ensure local_mac normalized
        - add vendor
        """
        out = dict(rec)
        lip = out.get("local_ip") or out.get("src_ip")
        mac = out.get("local_mac") or out.get("src_mac")

        # If you have a helper that resolves MAC by IP, use it; otherwise skip
        if not mac and lip and hasattr(self, "get_mac_for_ip"):
            try:
                mac = self.get_mac_for_ip(lip)
            except Exception:
                mac = None

        out["local_mac"] = normalize_mac(mac)
        out["vendor"] = vendor_for_mac(out["local_mac"])
        return out

    def get_active_rows_prepared(self, limit: int = 200) -> list[dict]:
        rows = self.get_active_rows(limit=limit)
        return [self.prepare_row_for_ui(r) for r in rows]

    # --- [CORE|LOOP] run ------------------------------------
    def run(self):
        """
        Core loop:

        - First, perform a one-time startup cycle and expose progress in 6 steps:
            1/6 Starting backend data collection
            2/6 Initialise the data backend
            3/6 Initial ARP/IP-MIB/neighbor walk
            4/6 Read conntrack / netstat / NetFlow
            5/6 Enrich rows with MAC/vendor/labels
            6/6 Waiting for data...

        - Then, enter the normal polling loop (refresh ARP + connections).
        """
        # --- One-time startup sequence (for UI progress dialog) ------------
        try:
            # 1/6
            self._set_startup_step(1, "Starting backend data collection")

            # 2/6
            self._set_startup_step(2, "Initialise the data backend")
            # (Backend init largely happens lazily inside the SNMP helpers.)

            # 3/6
            self._set_startup_step(3, "Initial ARP/IP-MIB/neighbor walk")
            self._refresh_arp()

            # 4/6 and 5/6 are driven from inside _update_connections(startup=True)
            self._update_connections(startup=True)

            # 6/6
            self._set_startup_step(6, "Waiting for data...")

        except Exception as e:
            print("[CORE STARTUP EXCEPTION]", e)
            traceback.print_exc()
            # In case of failure, mark startup done so UI doesn’t wait forever
        finally:
            self.startup_done = True

        # --- Normal polling loop ------------------------------------------
        while not self.stop.is_set():
            try:
                self._refresh_arp()
                cnt = len(self.ip2mac)
                if self._last_ip2mac_count != cnt:
                    msg = f"[SNMP] ip2mac entries: {cnt}"
                    if DEBUG:
                        print(msg)
                    self._last_ip2mac_count = cnt
                self._update_connections()
            except Exception as e:
                print("[CORE EXCEPTION]", e)
                traceback.print_exc()
            time.sleep(POLL_INTERVAL_SECONDS)