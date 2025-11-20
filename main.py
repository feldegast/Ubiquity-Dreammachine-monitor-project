# =============================================================================
# SECTION: IMPORTS & GLOBALS
# =============================================================================
# region IMPORTS & GLOBALS

# --- Standard library ---
import csv
import ctypes
import ipaddress
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import webbrowser

from datetime import datetime
from collections import defaultdict
from importlib import import_module
from pathlib import Path
from typing import Iterable, Dict, Optional
from vendor_resolver import vendor_for_display as lookup_vendor, update_vendor_db_now
#from vendors_offline import vendor_for_mac

# Optional offline fallback (does not hit network)
try:
    from manuf import manuf  # pip install manuf
    _MANUF = manuf.MacParser(update=False)
except Exception:
    _MANUF = None

_SPLIT_RE = re.compile(r"[,\|\t ]+")

# =============================================================================
# SECTION: ENRICHMENT (Vendor lookup, Device naming)
# =============================================================================
# region ENRICHMENT

# ---- Vendor lookup (optional) ----
from mac_vendor_lookup import VendorNotFoundError

import warnings
warnings.filterwarnings(
    "ignore",
    message=r"pkg_resources is deprecated.*",
    category=UserWarning,
)

try:
    import paramiko
except Exception:
    paramiko = None
# endregion IMPORTS & GLOBALS

'''
try:
    from engine.vendors import VendorDB
    from engine.device_names import DeviceNamer
except Exception:
    class VendorDB:
        def __init__(self, *a, **k): pass
        def lookup(self, mac): return "Unknown"
    class DeviceNamer:
        def __init__(self, *a, **k): pass
        def name_for(self, mac, ip): return None
        def set_name(self, name, mac=None, ip=None): pass '''

# =============================================================================
# SECTION: CONSTANTS & SETTINGS
# =============================================================================
# region CONSTANTS & SETTINGS

#App name and version information
APP_NAME = "Ubiquiti SNMP + NetFlow Monitor (LAN → WAN)"
VERSION = "5.11.0"
VERSION_DATE = "2025.11.20"

#uaser data defaults
ENABLE_CONNTRACK_SSH = True   # ← make sure this is here and not commented out
ENABLE_NETFLOW_V5_COLLECTOR = False  # set False to disable when enabled i get no data
POLL_INTERVAL_SECONDS = 5
RESOLVE_RDNS = True
DEFAULT_SHOW_IDLE_DEVICES = False   # Show MACs with no destinations/bytes in Aggregates table?
ROUTER_IP = "192.168.1.1"
LOG_FILENAME = "traffic_log.csv"
COPY_LIMIT_ROWS = 200
DEBUG_LOG_TAIL_LINES = 200
DEBUG = False
# ---- Windows toast (optional) ----
ENABLE_TOASTS = False  # ← turn off the flaky win10toast path

# ========= USER CONFIG =========
CONFIG_FILE = Path(__file__).with_name("config.json")

_DEFAULT_CFG = {
    "router_ip": ROUTER_IP,
    "enable_conntrack_ssh": ENABLE_CONNTRACK_SSH,
    "enable_netflow_v5_collector": ENABLE_NETFLOW_V5_COLLECTOR,
    "poll_interval_seconds": POLL_INTERVAL_SECONDS,
    "show_idle_devices": DEFAULT_SHOW_IDLE_DEVICES,
    "resolve_rdns": RESOLVE_RDNS,
    "copy_limit_rows": COPY_LIMIT_ROWS,
    "debug_log_tail_lines": DEBUG_LOG_TAIL_LINES,
    "enable_toasts": ENABLE_TOASTS,   # keep False unless you really want the Win hook
    # add any other user-tunable settings here
    
    "window_geometry": None,        # e.g. "1488x964+100+50"
    "window_state": "normal",       # "normal" or "zoomed"
    "column_widths": {              # per-table column widths
        "active": {},
        "agg": {},
        "alerts": {},
    },
    "details_width": 380,   # default right-hand details panel width in pixels
}

# ======================================================================
# UI Layout Tunables (right-hand details panel)
# Change these to experiment with layout without hunting through code.
# ======================================================================
DETAILS_PANEL_WIDTH_DEFAULT  = 290  # default sidebar width in pixels
DETAILS_WRAP_LENGTH          = 140  # label wrap width for values in details panel
DETAILS_LABEL_MINSIZE        = 80   # min width of left "label" column ("Destination:", etc.) #110
DETAILS_VALUE_MINSIZE        = 120  # min width of right value column
DETAILS_LABEL_PADX           = (4, 4)
DETAILS_VALUE_PADX           = (0, 4)
DETAILS_ROW_PADY             = 2

#table highlights
UNKNOWN_VENDOR_BACKGROUND = "#FFECEC"
HIGH_VOLUME_BACKGROUND    = "#D2F5FF"
NEW_DEVICE_BACKGROUND     = "#F7FFD2"

# --- Enable SSH conntrack collector ---
SSH_SECRETS_FILE = "ssh_secrets.json"
UDM_SSH_HOST = ROUTER_IP
UDM_SSH_PORT = 22           # usually 22
# If your UDM lacks the "conntrack" binary, we’ll fall back to reading /proc
CONNTRACK_POLL_SECS = 3

try:
    from win10toast import ToastNotifier
    _TOASTER = ToastNotifier() if ENABLE_TOASTS else None
except Exception:
    _TOASTER = None
# end Windows toast

SNMP_COMMUNITY = "public"

# Which LANs count as "client devices"
#LAN_PREFIXES = ["192.168.1.0/24", "10.27.10.0/24"]
LAN_PREFIXES = []
try:
    _LAN_NETWORKS = [ipaddress.ip_network(p, strict=False) for p in LAN_PREFIXES]
except Exception:
    _LAN_NETWORKS = []


# NetFlow v5 collector (UDP)
NETFLOW_LISTEN_IP = "0.0.0.0"
NETFLOW_LISTEN_PORT = 2055
RDNS_TIMEOUT = 1.0  # seconds per lookup
# ===============================

# ---------- ALERTING ----------
ALERT_THRESHOLD_BYTES = 1_048_576  # 1 MB per single connection
ALERT_COOLDOWN_SECS   = 300        # don't repeat alert for the same 5-tuple within this cooldown
ALERT_LOG_FILENAME    = "alerts_log.csv"

# Optional: suppress noisy/known traffic
WHITELIST_DESTS = {
    # Examples (exact string match):
    # "8.8.8.8:53",
    # "44.240.212.91:8883",
}
SILENCED_MACS = {
    # E.g. "AA:BB:CC:DD:EE:FF"
}

_WHITELIST_DESTS = set(WHITELIST_DESTS)  # as-is (exact ip:port strings)
_SILENCED_MACS = {m.upper() for m in SILENCED_MACS}

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

HOST_ALIAS_PATH = (BASE_DIR / "data" / "host_aliases.json") if "BASE_DIR" in globals() else Path("data/host_aliases.json")
HOST_ALIAS_PATH.parent.mkdir(parents=True, exist_ok=True)

# Per-device custom labels (MAC → friendly name)
MAC_LABELS_PATH = DATA_DIR / "mac_labels.json" # was mac-vendor-overrides.txt before changed to JSON
MAC_LABELS_PATH.parent.mkdir(parents=True, exist_ok=True)

#VENDOR_DB = VendorDB(base_dir=BASE_DIR)
#DEVICE_NAMER = DeviceNamer(base_dir=BASE_DIR)
# endregion ENRICHMENT

# endregion CONSTANTS & SETTINGS

# === BEGIN: Unified Vendor Resolver (drop-in) ================================

BUILTIN_OUI = {
    "00:1A:11": "Ubiquiti Networks",
    "00:1C:BF": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "44:D9:E7": "Ubiquiti Networks",
    "FC:EC:DA": "Ubiquiti Networks",
    "00:1B:63": "Apple",
    "3C:5A:B4": "Apple",
    "D8:BB:2C": "Apple",
    "F0:18:98": "Samsung",
    "FC:45:C3": "Samsung",
}

# Optional local overrides you want to force (OUI = first 3 bytes)
LOCAL_OUI_OVERRIDES = {
    "6C:1F:F7": "Apple, Inc.",
    "B0:F7:C4": "Ubiquiti Inc.",
    "52:6D:8F": "Samsung Electronics",
}

# Treat these as unknown
ZERO_MACS = {"00:00:00:00:00:00", "00-00-00-00-00-00", "", None}

# Safe, dependency-tolerant imports
try:
    from manuf import manuf as _manuf_mod  # pip install manuf
except Exception:
    _manuf_mod = None

try:
    #from mac_vendor_lookup import MacLookup, AsyncMacLookup  # pip install mac-vendor-lookup aiofiles
    from mac_vendor_lookup import AsyncMacLookup  # pip install mac-vendor-lookup aiofiles
except Exception:
    #MacLookup = None
    AsyncMacLookup = None

# Normalize MAC to "AA:BB:CC:DD:EE:FF"
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}")

# --- [NET] load_mac_labels ------------------------------------
def load_mac_labels() -> dict[str, str]:
    """
    Load MAC → label mappings from disk.

    Reads data from ``data/mac_labels.json`` (if present) and returns a mapping
    of normalized MAC addresses (``AA:BB:CC:DD:EE:FF``) to user-defined labels.

    The file format is a simple JSON object:

        {
          "AA:BB:CC:DD:EE:FF": "Lee's PC",
          "11:22:33:44:55:66": "NAS"
        }

    Any malformed or missing file is treated as "no labels" and returns an empty
    dict. This function never raises on I/O errors.
    """
    labels: dict[str, str] = {}
    path = MAC_LABELS_PATH

    if not path.is_file():
        return labels

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                if not k:
                    continue
                mac = str(k).strip().upper()
                # Store empty-string labels as "no label"
                labels[mac] = "" if v is None else str(v)
    except Exception:
        # Stay resilient if file is malformed
        pass

    return labels

# --- [NET] save_mac_labels ------------------------------------
def save_mac_labels(labels: dict[str, str]) -> None:
    """
    Persist MAC → label mappings to disk.

    Writes the provided mapping to ``data/mac_labels.json``. Empty labels are
    pruned so the file only contains actively named devices. Any errors are
    swallowed so the UI keeps running even if disk writes fail.

    Parameters
    ----------
    labels : dict[str, str]
        Mapping of normalized MAC addresses to user-defined labels.
    """
    path = MAC_LABELS_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Optionally drop empty labels from disk to keep the file tidy
        clean = {k: v for k, v in labels.items() if v}
        with path.open("w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, sort_keys=True)
    except Exception:
        # Fail silently – UI should keep working even if write fails
        pass
    
# --- [NET] _normalize_mac ----------------------------------------
def _normalize_mac(mac: str) -> str:
    """
    Normalize a MAC address into ``AA:BB:CC:DD:EE:FF`` form.

    Any hyphens are replaced with colons, and plain 12-hex strings are split
    into pairs. Zero/empty MACs (e.g. ``00:00:00:00:00:00``) are returned as
    an empty string.

    Parameters
    ----------
    mac : Any
        Raw MAC value from SNMP/NetFlow/conntrack (bytes, string, etc).

    Returns
    -------
    str
        Normalized MAC string or ``""`` if the value is empty/invalid.
    """
    if not mac:
        return ""
    parts = _MAC_RE.findall(mac)
    parts = [p.upper() for p in parts[:6]]
    return ":".join(parts) if len(parts) == 6 else ""

# --- [NET] _norm_mac ----------------------------------------
def _norm_mac(mac: str) -> str:
    if not mac:
        return ""
    mac = mac.strip().upper().replace("-", ":")
    parts = [p for p in mac.split(":") if p]
    # force 6 bytes if possible
    if len(parts) >= 6:
        parts = parts[:6]
    return ":".join(parts)

# --- [NET] _mac_oui ----------------------------------------
def _mac_oui(mac: str) -> str:
    mac_norm = _norm_mac(mac)
    parts = mac_norm.split(":")
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])  # "AA:BB:CC"

# --- [HOSTNAME|CORE] _HostnameResolver ---------------------------------
class _HostnameResolver:
    """
    Caches reverse-DNS results and supports user-defined hostname aliases.
    Precedence: alias > rDNS > ''.
    Thread-safe via a single RLock.
    """
    # --- [INIT] __init__  ------------------------------------
    def __init__(self, alias_path: Path):
        import threading, json
        self._alias_path = Path(alias_path)
        self._lock = threading.RLock()
        self._aliases: dict[str, str] = {}
        self._rdns_cache: dict[str, str] = {}
        self._pending: set[str] = set()
        self._load_aliases()  # load once on init

    # ---------- persistence ----------
    # --- [NET|UI] _load_aliases  ------------------------------------
    def _load_aliases(self) -> None:
        try:
            if self._alias_path.exists():
                with self._alias_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    with self._lock:
                        # normalize keys to ip strings
                        self._aliases = {str(k): str(v) for k, v in data.items() if v}
        except Exception:
            # don't crash UI if file is malformed
            pass

    # --- [NET|UI] _save_aliases  ------------------------------------
    def _save_aliases(self) -> None:
        # call only while holding self._lock
        try:
            self._alias_path.parent.mkdir(parents=True, exist_ok=True)
            with self._alias_path.open("w", encoding="utf-8") as f:
                json.dump(self._aliases, f, indent=2, sort_keys=True)
        except Exception:
            pass

    # ---------- public API ----------
    # --- [NET|UI] aliases ------------------------------------
    def aliases(self) -> dict[str, str]:
        with self._lock:
            return dict(self._aliases)
        
    # --- [NET|UI] set_alias  ------------------------------------
    def set_alias(self, ip: str, name: str | None) -> None:
        ip = (ip or "").strip()
        with self._lock:
            if name and name.strip():
                self._aliases[ip] = name.strip()
            else:
                self._aliases.pop(ip, None)
        self._save_aliases()

    # --- [NET] clear_cache  ------------------------------------
    def clear_cache(self) -> None:
        """Clear rDNS cache, keep aliases."""
        with self._lock:
            self._rdns_cache.clear()

    # --- [NET] _ip_from_hostport ------------------------------------
    @staticmethod
    def _ip_from_hostport(local_hostport: str) -> str:
        # "A.B.C.D:port" -> "A.B.C.D"
        s = (local_hostport or "").strip()
        if not s:
            return ""
        parts = s.rsplit(":", 1)
        return parts[0] if parts else s

    # --- [NET] name_for_ip ------------------------------------
    def name_for_ip(self, ip: str) -> str:
        """Return alias if set, else cached rDNS, else ''. Non-blocking."""
        with self._lock:
            if ip in self._aliases:
                return self._aliases[ip]
            return self._rdns_cache.get(ip, "")

    # --- [NET] put_rdns ------------------------------------
    def put_rdns(self, ip: str, hostname: str) -> None:
        with self._lock:
            # don't override alias
            if ip not in self._aliases and hostname:
                self._rdns_cache[ip] = hostname

# === END: Unified Vendor Resolver ===========================================

# =============================================================================
# SECTION: DATA MODELS (types, dataclasses)
# =============================================================================
# region DATA MODELS
# (none yet)# (none yet — core uses dicts for records)
# endregion DATA MODELS

# =============================================================================
# SECTION: STORAGE (files, CSV/JSON, load/save)
# =============================================================================
# region STORAGE
# (storage lives inside MonitorCore; placeholder here for future refactor)``
# endregion STORAGE

# --- [CONFIG] _load_secrets ------------------------------------
def _load_secrets():
    global UDM_SSH_HOST, UDM_SSH_USER, UDM_SSH_PASS, UDM_SSH_KEYFILE, UDM_SSH_KEY_PASSPHRASE

    if not os.path.exists(SSH_SECRETS_FILE):
        print(f"[WARN] No {SSH_SECRETS_FILE} file found. SSH will not function.")
        return False

    try:
        with open(SSH_SECRETS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        UDM_SSH_HOST = d.get("host", UDM_SSH_HOST)
        UDM_SSH_USER = d.get("username", "")
        UDM_SSH_PASS = d.get("password", "")
        UDM_SSH_KEYFILE = d.get("keyfile", "")
        UDM_SSH_KEY_PASSPHRASE = d.get("key_passphrase", "")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to load {SSH_SECRETS_FILE}: {e}")
        return False

# --- [CONFIG] _load_ssh_secrets --------------------------------
def _load_ssh_secrets(path: str):
    cfg = {
        "device": {"user": "", "password": "", "keyfile": "", "key_passphrase": ""},
        "console": {"user": "", "password": "", "keyfile": "", "key_passphrase": ""},
        "port": 22,
    }
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k in ("device", "console"):
            if k in data and isinstance(data[k], dict):
                cfg[k].update({kk: data[k].get(kk, cfg[k][kk]) for kk in cfg[k]})
        if "port" in data and isinstance(data["port"], int):
            cfg["port"] = data["port"]
    except Exception:
        pass
    return cfg

# --- [CONFIG] _save_ssh_secrets ------------------------------------
def _save_ssh_secrets(path: str, data: dict):
    """Persist SSH credentials to JSON.

    Shape:
      {
        "device":  {"user": "...", "password": "...", "keyfile": "", "key_passphrase": ""},
        "console": {"user": "root", "password": "", "keyfile": "", "key_passphrase": ""},
        "port": 22
      }
    """
    try:
        # ensure minimal shape & avoid leaking unexpected keys
        safe = {
            "device": {
                "user":       (data.get("device", {}) or {}).get("user", ""),
                "password":   (data.get("device", {}) or {}).get("password", ""),
                "keyfile":    (data.get("device", {}) or {}).get("keyfile", ""),
                "key_passphrase": (data.get("device", {}) or {}).get("key_passphrase", ""),
            },
            "console": {
                # root username is fixed/readonly per user request
                "user":       ((data.get("console", {}) or {}).get("user") or "root"),
                "password":   (data.get("console", {}) or {}).get("password", ""),
                # keep these fields but they are not editable in UI
                "keyfile":    (data.get("console", {}) or {}).get("keyfile", ""),
                "key_passphrase": (data.get("console", {}) or {}).get("key_passphrase", ""),
            },
            "port": int((data or {}).get("port", 22)),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2)
        return True
    except Exception as e:
        print(f"[SSH|SAVE] Failed to write secrets: {e}")
        return False

# =============================================================================
# SECTION: ENRICHMENT (Vendor lookup, Device naming)
# =============================================================================
# region ENRICHMENT

# --- [ENRICH|OUI] lookup_vendor ------------------------------------
# Purpose: Resolve MAC → vendor via mac_vendor_lookup or built-in OUI
def lookup_vendor(mac: str) -> str:
    # Keep old name around, but delegate to the new pipeline.
    return vendor_for_mac(mac)

# Quick SNMP sanity check (optional)
# --- [SNMP|CHECK] snmp_sanity ------------------------------------
def snmp_sanity():
    ok = False
    ifnames = 0
    try:
        # IF-MIB::ifName — most UniFi boxes expose this
        for _oid, _val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_ifName):
            ifnames += 1
            if ifnames >= 1:
                ok = True
                break
    except Exception:
        pass
    return ok, ifnames

# =============================================================================
# SECTION: NETWORK CORE (SNMP, ARP, conn tracking)
# =============================================================================
# region NETWORK CORE

# =============================================================================
# SECTION: SNMP BACKEND (selection + helpers)
# =============================================================================
# region SNMP BACKEND

# --- SNMP backend globals (module-level) ---
_snmp_backend = None
_snmp_backend_name = "off"  # label shown in the UI if nothing loads

# --- [SNMP] _snmp_walk_v2_pythonic ------------------------------------
def _snmp_walk_v2_pythonic(host, community, oid):
    m = import_module("puresnmp.api.pythonic")
    Client = getattr(m, "Client")
    client = Client(host, community=community)
    for vb in client.walk(oid):
        yield str(vb.oid), vb.value

# --- [SNMP] _snmp_walk_v2_raw ------------------------------------
def _snmp_walk_v2_raw(host, community, oid):
    m = import_module("puresnmp.api.raw")
    Client = getattr(m, "Client")
    client = Client(host, community=community)
    for vb in client.walk(oid):
        yield str(vb.oid), vb.value

# --- [SNMP] _snmp_walk_v1 ------------------------------------
def _snmp_walk_v1(host, community, oid):
    m = import_module("puresnmp.api.v2c")
    walk_fn = getattr(m, "walk")
    for oid_, val in walk_fn(host, community, oid):
        yield str(oid_), val

_snmp_init_lock = threading.Lock()

# --- [SNMP|INIT] _init_snmp_backend ------------------------------------
# Purpose: Pick usable puresnmp API and label for UI
def _init_snmp_backend():
    """Pick the first available puresnmp API and record a label for the UI."""
    global _snmp_backend, _snmp_backend_name
    with _snmp_init_lock:
        if _snmp_backend is not None:
            return
        for _try in ("puresnmp.api.pythonic", "puresnmp.api.raw", "puresnmp.api.v2c"):
            try:
                import_module(_try)
                if _try == "puresnmp.api.pythonic":
                    _snmp_backend = _snmp_walk_v2_pythonic
                    _snmp_backend_name = "pythonic"
                elif _try == "puresnmp.api.raw":
                    _snmp_backend = _snmp_walk_v2_raw
                    _snmp_backend_name = "raw"
                else:
                    _snmp_backend = _snmp_walk_v1
                    _snmp_backend_name = "v2c"
                break
            except Exception:
                continue

# Initialize once at import time (after globals are defined)
_init_snmp_backend()

# --- [SNMP|INFO] get_snmp_backend_name ------------------------------------
def get_snmp_backend_name() -> str:
    # Safe getter used by the status line
    return _snmp_backend_name or "off"

# --- [SNMP|FACADE] snmp_walk ------------------------------------
# Purpose: Unified SNMP walk using the chosen backend (or no-op if absent)
def snmp_walk(host, community, oid):
    # Unified entry for the rest of the codebase
    if _snmp_backend is None:
        return iter(())  # graceful no-op if puresnmp unavailable
    return _snmp_backend(host, community, oid)

# endregion SNMP BACKEND

# numeric OIDs (no MIB files needed)
OID_ifName                  = "1.3.6.1.2.1.31.1.1.1.1"      # IF-MIB::ifName
OID_ipNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2"        # IP-MIB::ipNetToMediaPhysAddress
OID_ipNetToMediaNetAddress  = "1.3.6.1.2.1.4.22.1.3"        # IP-MIB::ipNetToMediaNetAddress
OID_tcpConnState            = "1.3.6.1.2.1.6.13.1.1"        # TCP-MIB::tcpConnState

TCP_STATE = {
    1: 'closed', 2: 'listen', 3: 'synSent', 4: 'synReceived',
    5: 'established', 6: 'finWait1', 7: 'finWait2', 8: 'closeWait',
    9: 'lastAck', 10: 'closing', 11: 'timeWait', 12: 'deleteTCB'
}

# =============================================================================
# SECTION: NETWORK CORE (SNMP, ARP, conn tracking)
# =============================================================================
# region NETWORK CORE

# Additional MAC source: IP-MIB::ipNetToPhysicalPhysAddress
# OID: 1.3.6.1.2.1.4.35.1.4 .<ifIndex>.<addrType>.<addrLen>.<addrOctets...>
# For IPv4 rows: addrType=1, addrLen=4, then a.b.c.d

# ====== ARP / NEIGHBOR TABLES (robust) ======

# Additional tables & OIDs
OID_ipNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4"
# Legacy AT-MIB (some firmwares still populate this)
OID_atPhysAddress = "1.3.6.1.2.1.3.1.1.2"
OID_atNetAddress  = "1.3.6.1.2.1.3.1.1.3"

# --- [SNMP|ARP] _parse_mac_from_val ------------------------------------
# Purpose: robust MAC parser
def _parse_mac_from_val(val) -> str:
    """Parse MAC from puresnmp values (OctetString, '0x…', 'aa:bb:…')."""
    try:
        raw = bytes(val)
    except Exception:
        raw = None
    if raw is None:
        sval = str(val)
        if sval.startswith("0x"):
            try:
                raw = bytes.fromhex(sval[2:])
            except Exception:
                raw = b""
        elif ":" in sval:
            try:
                raw = bytes(int(x,16) for x in sval.split(":"))
            except Exception:
                raw = b""
        else:
            raw = b""
    mac = ":".join(f"{b:02X}" for b in raw)
    return mac or "00:00:00:00:00:00"

# --- [SNMP|ARP] walk_arp_table ------------------------------------
# Purpose: Build (ifIndex, ip, mac) rows by merging ipNetToMedia* and ipNetToPhysical*
def walk_arp_table():
    """Return [(ifIndex, ip, mac)] via IP-MIB ipNetToMedia* (classic ARP)."""
    ip_entries, mac_entries = {}, {}
    # ipNetToMediaNetAddress — use index for IP
    try:
        for oid, _val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_ipNetToMediaNetAddress):
            parts = str(oid).split(".")
            if len(parts) < 5: continue
            try:
                ifIndex = int(parts[-5])
                ip = ".".join(parts[-4:])
                ip_entries[(ifIndex, ip)] = True
            except Exception:
                continue
    except Exception:
        pass
    # ipNetToMediaPhysAddress — MAC
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_ipNetToMediaPhysAddress):
            parts = str(oid).split(".")
            if len(parts) < 5: continue
            try:
                ifIndex = int(parts[-5])
                ip = ".".join(parts[-4:])
                mac = _parse_mac_from_val(val)
                mac_entries[(ifIndex, ip)] = mac
            except Exception:
                continue
    except Exception:
        pass
    rows = []
    for key in set(ip_entries.keys()) | set(mac_entries.keys()):
        ifIndex, ip = key
        mac = mac_entries.get(key, "00:00:00:00:00:00")
        rows.append((ifIndex, ip, mac))
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

# --- [IP-MIB] _walk_at_mib ------------------------------------
def _walk_at_mib():
    """Legacy AT-MIB fallback: returns [(ip, mac)]."""
    ips, macs = {}, {}
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_atNetAddress):
            parts = str(oid).split(".")
            if len(parts) < 1: continue
            try:
                ip = ".".join(parts[-4:])
                ips[ip] = True
            except Exception:
                continue
    except Exception:
        pass
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_atPhysAddress):
            mac = _parse_mac_from_val(val)
            parts = str(oid).split(".")
            if len(parts) < 1: continue
            try:
                ip = ".".join(parts[-4:])
                macs[ip] = mac
            except Exception:
                continue
    except Exception:
        pass
    rows = []
    for ip in set(ips) | set(macs):
        rows.append((ip, macs.get(ip, "00:00:00:00:00:00")))
    return rows

# --- [IP-MIB] normalize_mac ------------------------------------
def normalize_mac(mac) -> str:
    """Return normalized 'AA:BB:CC:DD:EE:FF' or '' for empties/zeros."""
    if mac is None:
        return ""
    s = str(mac).strip().upper().replace("-", ":")
    if not s:
        return ""
    if ":" not in s and len(s) == 12:
        s = ":".join(s[i:i+2] for i in range(0, 12, 2))
    if s in ZERO_MACS:
        return ""
    return s

# --- [IP-MIB] normalize_mac ------------------------------------
def prepare_row_for_ui(row: dict) -> dict:
    """
    Ensure each UI row has normalized MAC + resolved vendor.

    - Normalizes MAC into 'AA:BB:CC:DD:EE:FF'
    - Fills in row['vendor'] if missing/empty using lookup_vendor()
    """
    if row is None:
        return {}

    # Work on a shallow copy so we don’t mutate core structures unexpectedly
    out = dict(row)

    # Try a few possible keys for MAC (depending on which table)
    mac = (
        out.get("mac")
        or out.get("local_mac")
        or out.get("client_mac")
        or ""
    )
    mac = normalize_mac(mac)
    out["mac"] = mac  # keep a consistent key for MAC for the UI

    # Only compute vendor if not already set
    vendor = out.get("vendor")
    if not vendor:
        vendor = lookup_vendor(mac)
        out["vendor"] = vendor

    return out

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

# --- [SNMP|TCP] walk_tcp_connections ------------------------------------
# Purpose: Reconstruct TCP rows from TCP-MIB indices
def walk_tcp_connections():
    """
    Return list of dict: {local_ip, local_port, remote_ip, remote_port, state}
    We reconstruct from tcpConnState row indexes.
    """
    conns = []
    try:
        for oid, val in snmp_walk(ROUTER_IP, SNMP_COMMUNITY, OID_tcpConnState):
            idx = str(oid).split(".")
            try:
                remote_port = int(idx[-1])
                remote_ip = ".".join(idx[-5:-1])
                local_port = int(idx[-6])
                local_ip = ".".join(idx[-10:-6])
                state = TCP_STATE.get(int(val), f"state({int(val)})")
                conns.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state
                })
            except Exception:
                continue
    except Exception:
        pass
    return conns

# =============================================================================
# SECTION: UTILITIES (helpers, formatting, parsing)
# =============================================================================
# region UTILITIES
# --- [UTIL|IPRANGE] _is_lan_client_ip ------------------------------------
# Purpose: Filter to private/LAN IPs (or user-listed prefixes)
def _is_lan_client_ip(ip: str) -> bool:
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

# --- [UTIL|FORMAT] ip_to_str ------------------------------------
def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

# --- [DNS|UTIL] _rdns_lookup ------------------------------------
# Purpose: Bound reverse DNS via worker thread, cached
def _rdns_lookup(ip: str, timeout: float) -> str | None:
    # Bound resolver time using a helper thread, so UI never stalls
    result = [None]
    
    def _work():
        try:
            # keep lookups quick; not all resolvers honor this, so we still run in a worker
            old = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(timeout)
                name, _, _ = socket.gethostbyaddr(ip)
                result[0] = name
            finally:
                socket.setdefaulttimeout(old)
        except Exception:
            result[0] = None

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout + 0.1)  # small cushion
    return result[0]

# --- [DNS|WORKER] dns_worker ------------------------------------
def dns_worker(dns_q: "queue.Queue[str]"):
    """Background rDNS resolver that consumes IPs from dns_q and fills the caches."""
    while True:
        ip = dns_q.get()
        if ip is None:
            break
        with _dns_lock:
            if ip in _dns_cache:
                continue
        name = _rdns_lookup(ip, RDNS_TIMEOUT)
        with _dns_lock:
            _dns_cache[ip] = name  # may be None
            _dns_pending.discard(ip)

# --- [UTIL|FILEIO|TAIL] tail_file ------------------------------------
def tail_file(path: str, max_lines: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            return "".join(lines[-max_lines:])
    except Exception:
        return ""

# clipboard helpers
# endregion UTILITIES

# ---- NetFlow v5 collector (simple, fixed-format parser) ----
# NetFlow v5 packet format reference
NFV5_HEADER_FMT = "!HHIIIIBBH"   # version(2), count(2), sys_uptime(4), unix_secs(4), unix_nsecs(4), flow_seq(4), engine_type(1), engine_id(1), sampling(2)
NFV5_RECORD_FMT = "!IIIHHIIIIHHBBBBHHBBH"  # 48 bytes per record

# endregion  # NETWORK CORE

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
    # Purpose: Collect v5 packets; accumulate bytes per 5-tuple
    def run(self):
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

# endregion NETWORK CORE

# =============================================================================
# SECTION: DATA MODELS (types, dataclasses)
# =============================================================================
# region DATA MODELS
# (Currently using dict-based records; could later promote to dataclasses)
# endregion

# =============================================================================
# SECTION: AGGREGATION (flows, bytes, top-N)
# =============================================================================
# region AGGREGATION
    
# ---- Monitor core tying SNMP + NetFlow together ----
class MonitorCore:
    
    # --- [CORE|INIT] __init__ ------------------------------------
    def __init__(self, nf_collector=None):
        self.stop = threading.Event()
        self.data_lock = threading.Lock()
        self.conn_map = {}  # key -> record (augmented)
        self.aggregates = defaultdict(lambda: defaultdict(lambda: {"sightings":0, "bytes":0}))
        self.ip2mac = {}
        self._last_ip2mac_count = None
        self.nf = nf_collector
        
        # Lightweight debug counters for the status line
        self.last_counts = {"arp": 0, "tcp": 0, "flows": 0}

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

    # --- MAC Lookup (simple version) ------------------------------------
    def get_mac_for_ip(self, ip: str) -> str | None:
        # Return cached value if present
        mac = self.ip2mac.get(ip)
        if mac:
            return mac

        # Otherwise try to refresh ARP table
        try:
            self._refresh_arp()  # Safe, already exists in your code
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

# --- [NET] normalize_mac ------------------------------------
    def normalize_mac(mac):
        if not mac: return None
        mac = str(mac).strip().upper().replace("-", ":")
        return None if mac in ZERO_MACS else mac

    # --- [CORE|UPDATE] _update_connections ------------------------------------
    # Purpose: Merge SNMP/flows; update conn_map, aggregates, alerts
    def _update_connections(self):
        now = datetime.now().isoformat(timespec="seconds")

        # Primary source: SNMP TCP-MIB
        conns = walk_tcp_connections()
        self.last_counts["tcp"] = len(conns)

        # Fallback: if router doesn't expose TCP-MIB, synthesize connections
        # from the flow source (Conntrack SSH or NetFlow v5)
        if not conns and self.nf:
            flows = []
            try:
                with self.nf.lock:
                    for (s_ip, s_po, d_ip, d_po, proto), b in self.nf.bytes_by_flow.items():
                        if proto != 6:
                            continue
                        if not _is_lan_client_ip(s_ip):
                            continue
                        if d_ip == "0.0.0.0":
                            continue
                        flows.append((s_ip, s_po, d_ip, d_po))
            except Exception:
                pass

            self.last_counts["flows"] = len(flows)

            # Synthesize "established" connection rows from flows
            conns = [
                {
                    "local_ip": s_ip,
                    "local_port": int(s_po),
                    "remote_ip": d_ip,
                    "remote_port": int(d_po),
                    "state": "established",
                }
                for (s_ip, s_po, d_ip, d_po) in flows
            ]
        else:
            # If we *did* get SNMP connections, just report the flow-map size (if any)
            if self.nf:
                try:
                    with self.nf.lock:
                        self.last_counts["flows"] = len(getattr(self.nf, "bytes_by_flow", {}))
                except Exception:
                    self.last_counts["flows"] = 0
            else:
                self.last_counts["flows"] = 0

        # --- Update conn_map + aggregates + alert logic ---
        now = datetime.now().isoformat(timespec="seconds")
        for c in conns:
            local_ip    = c["local_ip"]
            local_port  = c["local_port"]
            remote_ip   = c["remote_ip"]
            remote_port = c["remote_port"]
            state       = c["state"]

            if not _is_lan_client_ip(local_ip):
                continue

            
            #mac = (self.ip2mac.get(local_ip, "00:00:00:00:00:00") or "").upper() # old
            #mac = self.ip2mac.get(local_ip, "00:00:00:00:00:00") or self.get_mac_for_ip(local_ip, "00:00:00:00:00:00") # new
            mac = self.get_mac_for_ip(local_ip) or "00:00:00:00:00:00"
            vendor = vendor_for_mac(mac)
            key = (local_ip, local_port, remote_ip, remote_port)

            # --- Optional suppressors (whitelist/silence) ---
            dest_tag = f"{remote_ip}:{remote_port}"
            if dest_tag in _WHITELIST_DESTS:
                #If you’d prefer whitelisted rows to show but never alert, switch the continue to no_alert = True:
                # no_alert = True
                continue  # skip completely

            if mac in _SILENCED_MACS:
                #If you’d prefer whitelisted rows to show but never alert, switch the continue to no_alert = True:
                # no_alert = True
                continue  # skip completely

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
                    "first_seen": now,
                    "last_seen": now,
                    "bytes_tx": 0,
                    "over_1mb": False
                }
                self.conn_map[key] = rec
            else:
                rec["last_seen"] = now
                rec["state"] = state
                rec["local_mac"] = mac
                rec["vendor"] = vendor

            # bytes from NetFlow or conntrack
            if self.nf:
                b = self.nf.get_bytes_for(local_ip, local_port, remote_ip, remote_port)
                rec["bytes_tx"] = b

                # threshold detection
                if b >= ALERT_THRESHOLD_BYTES and not rec["over_1mb"]:
                    rec["over_1mb"] = True
                    last_alert = self._alerts_last_sent.get(key, 0.0)
                    now_mono = time.monotonic()
                    if now_mono - last_alert >= ALERT_COOLDOWN_SECS:
                        self._alerts_last_sent[key] = now_mono
                        self._alert_emit(rec)

            # Aggregates
            agg = self.aggregates[mac][(remote_ip, remote_port)]
            agg["sightings"] += 1
            agg["bytes"] = max(agg["bytes"], rec["bytes_tx"] or 0)
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
        while not self.stop.is_set():
            try:
                self._refresh_arp()
                cnt = len(self.ip2mac)
                if self._last_ip2mac_count != cnt:
                    print(f"[SNMP] ip2mac entries: {cnt}")
                    self._last_ip2mac_count = cnt
                self._update_connections()
            except Exception:
                pass
            time.sleep(POLL_INTERVAL_SECONDS)

# endregion AGGREGATION

_dns_lock = threading.Lock()
_dns_cache = {}       # ip -> hostname or None if not found
_dns_pending = set()  # to avoid queueing the same IP many times

# ---- Tk UI ----
# =============================================================================
# SECTION: UI LAYER (Tk app)
# =============================================================================
# region UI LAYER

from tkinter import simpledialog  # ensure this exists if you use the naming prompt
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox

class App(tk.Tk):

    # --- [UI|INIT] __init__ ------------------------------------
    def __init__(self):
        super().__init__()
        
        # Apply DPI scaling before we build any UI or set fonts
        self._auto_dpi_scaling()
        
        # Load config early so window prefs are available
        self.cfg = self.load_config()       

        self.title(f"{APP_NAME} — {VERSION} ({VERSION_DATE})")

        # 1) Restore window geometry if saved
        default_geo = "1488x964"   # your WinSpy size
        geo = self.cfg.get("window_geometry") or default_geo
        try:
            self.geometry(geo)
        except Exception:
            self.geometry(default_geo)
        
        # 2) Enforce min size
        self.minsize(1100, 650)

        # 3) Restore state (normal / zoomed)
        state = self.cfg.get("window_state", "normal")
        if state == "zoomed":
            try:
                self.state("zoomed")
            except Exception:
                pass

        # --- placeholders so attributes always exist ---
        self.top = None
        self.paned = None
        self.alertf = None
        self.connf = None
        self.aggf = None
        self.foot = None
        self.note_lbl = None
        # ------------------------------------------------
        
        self._last_ssh_status = None # to detect changes
        self._last_ssh_print_ts = 0.0

        self.nf = None
        secrets = _load_ssh_secrets(SSH_SECRETS_FILE)
        ssh_port = secrets.get("port", UDM_SSH_PORT)

        if ENABLE_NETFLOW_V5_COLLECTOR:
            self.nf = NetflowV5Collector(NETFLOW_LISTEN_IP, NETFLOW_LISTEN_PORT)
            self.nf.start()
        elif ENABLE_CONNTRACK_SSH:
            self.nf = ConntrackCollectorSSH(
                host=UDM_SSH_HOST,
                port=ssh_port,
                device_creds=secrets.get("device", {}),
                console_creds=secrets.get("console", {}),
                interval=CONNTRACK_POLL_SECS
            )
            self.nf.start()
        else:
            self.nf = None
        
        self.core = MonitorCore(self.nf)

        self._dns_q = queue.Queue()
        self._dns_thread = threading.Thread(target=dns_worker, args=(self._dns_q,), daemon=True)
        self._dns_thread.start()
        
        self.cfg = getattr(self, "cfg", dict(_DEFAULT_CFG))  # fallback if not yet loaded
        self.show_idle_var = tk.BooleanVar(
            value=bool(self.cfg.get("show_idle_devices", DEFAULT_SHOW_IDLE_DEVICES))
        )

        self._build_ui()
        self._ui_ready = True 
        # Give Tk a beat to compute sizes, then place sashes
        self.after(50, self._init_layout)  # place sashes once sizes are known
        self.after(0, lambda: self._center_window(-80))  # nudge up as needed
        
        self.thread = threading.Thread(target=self.core.run, daemon=True)
        self.thread.start()
        
        # Ensure we save prefs on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Kick off the refresh loop AFTER widgets exist
        self.after(100, self._refresh_ui)
    
    # =============================================================================
    # SECTION: UI WIDGETS (tables, dialogs, menus)
    # =============================================================================
    # region UI WIDGETS

    # --- [UI|INIT] _auto_dpi_scaling ------------------------------------
    def _auto_dpi_scaling(self) -> None:
        """
        Automatically adjust Tk scaling based on system DPI.

        On Windows, this uses the system DPI so fonts and widgets are not tiny
        on high-DPI displays. On other platforms it ensures a sane minimum.
        """
        try:
            if sys.platform.startswith("win"):
                try:
                    user32 = ctypes.windll.user32
                    # Try to make this process DPI aware (no-op on some builds)
                    try:
                        user32.SetProcessDPIAware()
                    except Exception:
                        pass

                    # Prefer GetDpiForSystem if available
                    try:
                        dpi = user32.GetDpiForSystem()
                    except Exception:
                        # Fallback via GetDeviceCaps
                        hdc = user32.GetDC(0)
                        LOGPIXELSX = 88
                        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, LOGPIXELSX)

                    factor = float(dpi) / 96.0 if dpi else 1.0
                    # Clamp to a reasonable range
                    if factor < 1.0:
                        factor = 1.0
                    if factor > 2.0:
                        factor = 2.0
                    self.tk.call("tk", "scaling", factor)
                except Exception:
                    # If anything fails, leave scaling at default
                    pass
            else:
                # Non-Windows: ensure at least 1.0 scaling
                try:
                    current = float(self.tk.call("tk", "scaling"))
                except Exception:
                    current = 1.0
                if current < 1.0:
                    self.tk.call("tk", "scaling", 1.0)
        except Exception:
            # Never let DPI logic break the UI
            pass

    # --- [UI|LAYOUT] _init_layout ------------------------------------
    def _init_layout(self):
        """
        Apply config values to globals and any layout-related settings.
        Called once after the UI has been built and Tk has computed sizes.
        """
        # Apply config from self.cfg (loaded in __init__)
        cfg = getattr(self, "cfg", {}) or {}

        # Make sure we’re updating the same globals the rest of the code uses
        global ROUTER_IP
        global UDM_SSH_HOST
        global ENABLE_CONNTRACK_SSH
        global ENABLE_NETFLOW_V5_COLLECTOR
        global POLL_INTERVAL_SECONDS
        global COPY_LIMIT_ROWS
        global DEBUG_LOG_TAIL_LINES
        global RESOLVE_RDNS
        global ENABLE_TOASTS
        global _TOASTER

        # Router / SNMP settings
        ROUTER_IP = str(cfg.get("router_ip", ROUTER_IP))
        UDM_SSH_HOST = ROUTER_IP  # keep SSH host consistent with router_ip

        # Backend toggles
        ENABLE_CONNTRACK_SSH        = bool(cfg.get("enable_conntrack_ssh", ENABLE_CONNTRACK_SSH))
        ENABLE_NETFLOW_V5_COLLECTOR = bool(cfg.get("enable_netflow_v5_collector", ENABLE_NETFLOW_V5_COLLECTOR))

        # Timings & limits
        try:
            POLL_INTERVAL_SECONDS = int(cfg.get("poll_interval_seconds", POLL_INTERVAL_SECONDS))
        except Exception:
            pass

        try:
            COPY_LIMIT_ROWS = int(cfg.get("copy_limit_rows", COPY_LIMIT_ROWS))
        except Exception:
            pass

        try:
            DEBUG_LOG_TAIL_LINES = int(cfg.get("debug_log_tail_lines", DEBUG_LOG_TAIL_LINES))
        except Exception:
            pass

        # rDNS + toasts
        RESOLVE_RDNS  = bool(cfg.get("resolve_rdns", RESOLVE_RDNS))
        ENABLE_TOASTS = bool(cfg.get("enable_toasts", ENABLE_TOASTS))

        # Re-initialise the toast notifier based on ENABLE_TOASTS
        try:
            from win10toast import ToastNotifier
            _TOASTER = ToastNotifier() if ENABLE_TOASTS else None
        except Exception:
            _TOASTER = None
        
        # (If you later have sash / details-panel placement, it can also live here)


    # --- [UI|SEARCH] _apply_alert_filter ------------------------------------
    def _apply_alert_filter(self, *_):
        """
        Filter all three tables (Alerts, Active, Aggregates) using the text
        in self.alert_filter_var. Matches on any visible column text.
        """
        sv = getattr(self, "alert_filter_var", None)
        pattern = (sv.get() if sv is not None else "") or ""
        pattern = pattern.strip().lower()

        # Tables to filter: (name, treeview attribute)
        tables = [
            ("alerts", getattr(self, "alerts", None)),
            ("active", getattr(self, "tree", None)),
            ("agg",    getattr(self, "agg", None)),
        ]

        # Helper: ensure we have a detached-list for each table
        def _get_detached(name: str):
            attr = f"_detached_{name}"
            if not hasattr(self, attr):
                setattr(self, attr, [])
            return getattr(self, attr), attr

        # If filter is empty, just reattach anything we've previously detached
        if not pattern:
            for name, tv in tables:
                if tv is None:
                    continue
                detached, attr = _get_detached(name)
                for iid in list(detached):
                    try:
                        tv.reattach(iid, "", "end")
                    except Exception:
                        pass
                setattr(self, attr, [])
            return

        # Non-empty pattern: reattach everything we know about, then detach non-matching
        for name, tv in tables:
            if tv is None:
                continue

            detached, attr = _get_detached(name)

            # 1) Reattach anything previously detached so we start from full set
            for iid in list(detached):
                try:
                    tv.reattach(iid, "", "end")
                except Exception:
                    pass
            detached.clear()

            # 2) Walk all rows and detach those that don't match
            for iid in tv.get_children(""):
                try:
                    vals = tv.item(iid, "values")
                except Exception:
                    continue

                text = " ".join(str(v).lower() for v in vals)
                if pattern not in text:
                    try:
                        tv.detach(iid)
                        detached.append(iid)
                    except Exception:
                        continue

    # --- [UI|LAYOUT] _apply_saved_column_widths ---------------------
    def _apply_saved_column_widths(self, table_name: str, tv: ttk.Treeview) -> None:
        """Apply per-column widths loaded from config to a Treeview."""
        try:
            cfg = self.cfg or {}
            col_cfg = cfg.get("column_widths", {})
            widths = col_cfg.get(table_name) or {}
            if not widths:
                return
            for cid, w in widths.items():
                if cid in tv["columns"]:
                    try:
                        tv.column(cid, width=int(w))
                    except Exception:
                        pass
        except Exception:
            pass

    # --- [UI|DETAILS] _build_details_panel ------------------------------------
    def _build_details_panel(self, parent) -> None:
        """
        Build the right-hand details panel that shows information about
        the currently selected alert/connection/aggregate row.
        """
        import tkinter as tk
        from tkinter import ttk

        # Use tunables so you can experiment easily
        frame = ttk.LabelFrame(
            parent,
            text="Selected Device / Connection",
            width=DETAILS_PANEL_WIDTH_DEFAULT,
        )
        # Minimal padding so it sits close to the table scrollbars
        frame.pack(fill="both", expand=True, padx=(2, 4), pady=4)
        self.details_frame = frame

        # Backing StringVars for fields
        self.detail_table  = getattr(self, "detail_table",  tk.StringVar(value="(none)"))
        self.detail_when   = getattr(self, "detail_when",   tk.StringVar(value=""))
        self.detail_ip     = getattr(self, "detail_ip",     tk.StringVar(value=""))
        self.detail_mac    = getattr(self, "detail_mac",    tk.StringVar(value=""))
        self.detail_vendor = getattr(self, "detail_vendor", tk.StringVar(value=""))
        self.detail_name   = getattr(self, "detail_name",   tk.StringVar(value=""))
        self.detail_dest   = getattr(self, "detail_dest",   tk.StringVar(value=""))
        self.detail_bytes  = getattr(self, "detail_bytes",  tk.StringVar(value=""))
        self.detail_note   = getattr(self, "detail_note",   tk.StringVar(value=""))

        rows = [
            ("Source",       self.detail_table),
            ("IP address",   self.detail_ip),
            ("MAC address",  self.detail_mac),
            ("Vendor",       self.detail_vendor),
            ("Name / alias", self.detail_name),
            ("Destination",  self.detail_dest),
            ("Bytes",        self.detail_bytes),
            ("When",         self.detail_when),
            ("Note",         self.detail_note),
        ]

        for r, (label, var) in enumerate(rows):
            ttk.Label(frame, text=label + ":").grid(
                row=r,
                column=0,
                sticky="nw",
                padx=DETAILS_LABEL_PADX,
                pady=DETAILS_ROW_PADY,
            )
            ttk.Label(
                frame,
                textvariable=var,
                anchor="w",
                wraplength=DETAILS_WRAP_LENGTH,
                justify="left",
            ).grid(
                row=r,
                column=1,
                sticky="nw",
                padx=DETAILS_VALUE_PADX,
                pady=DETAILS_ROW_PADY,
            )

        # Column 0: small, fixed-ish label column
        frame.columnconfigure(0, weight=0, minsize=DETAILS_LABEL_MINSIZE)
        # Column 1: value column that grows and wraps
        frame.columnconfigure(1, weight=1, minsize=DETAILS_VALUE_MINSIZE)

    # --- [UI|DETAILS] _wrap_friendly_uri ---------------------------------------
    def _wrap_friendly_uri(self, uri: str) -> str:
        """
        Insert zero-width break hints into a URI/hostname so the Tk label
        can wrap nicely at dots and slashes, without visually changing
        the string.
        """
        s = str(uri)
        # Zero-width space (U+200B) after '.' and '/'
        s = s.replace(".", ".\u200b")
        s = s.replace("/", "/\u200b")
        return s
        
    # --- [UI|DETAILS] _update_details_from_tree --------------------------------
    def _update_details_from_tree(self, tree, table_name: str) -> None:
        """
        Update the right-hand details panel from the currently selected row
        in a Treeview.
        """
        from tkinter import ttk
        try:
            if not isinstance(tree, ttk.Treeview):
                return
            selection = tree.selection()
            if not selection:
                return
            iid = selection[0]
            cols = list(tree["columns"])
            values = tree.item(iid, "values") or ()
            row = {
                col: (values[idx] if idx < len(values) else "")
                for idx, col in enumerate(cols)
            }
        except Exception:
            return

        # Derive common fields
        src = table_name
        local = row.get("local", "")
        dest = row.get("dest", row.get("destination", ""))
        mac = row.get("mac", row.get("client_mac", ""))
        vendor = row.get("vendor", "")
        bytes_val = (
            row.get("bytes")
            or row.get("Total Bytes")
            or row.get("bytes_tx")
            or ""
        )
        note = row.get("note", "")

        # IP from local field "ip[:port]" or "ip [host]:port"
        ip = ""
        if isinstance(local, str) and local:
            base = local.split()[0]
            ip = base.split(":", 1)[0]

        when = ""
        if "time" in row:
            when = row.get("time", "")
        elif "last" in row:
            when = row.get("last", "")
        elif "first" in row:
            when = row.get("first", "")

        # Keep When as a single string now that it's no longer the problem
        when_display = str(when)

        # Friendly name / alias via DeviceNamer, if available
        name = ""
        try:
            namer = getattr(self.core, "namer", None)
            if namer is not None:
                name = namer.name_for(mac or None, ip or None) or ""
        except Exception:
            name = ""

        # Make destination wrap-friendly (dots and slashes)
        dest_display = self._wrap_friendly_uri(dest)

        # Push into the StringVars
        try:
            self.detail_table.set(str(src).capitalize())
            self.detail_ip.set(str(ip))
            self.detail_mac.set(str(mac))
            self.detail_vendor.set(str(vendor))
            self.detail_name.set(str(name))
            self.detail_dest.set(dest_display)
            self.detail_bytes.set(str(bytes_val))
            self.detail_when.set(when_display)
            self.detail_note.set(str(note))
        except Exception:
            # If details panel not yet built, ignore
            pass

    # --- [UI] notify ------------------------------------
    def notify(self, title, msg):
        if _TOASTER:
            try:
                _TOASTER.show_toast(title, msg, threaded=True)
            except Exception:
                pass

    # --- [UI|LAYOUT] _post_build_column_fix ------------------------------------    
    def _post_build_column_fix(self):
        """Normalize column #1 widths across the three tables after they exist."""
        try:
            # Keep in sync with your build_ui constants
            COL_W_FIRST = 140
            for tv in (self.alerts, self.tree, self.agg):
                try:
                    first_col = tv["columns"][0]
                    tv.column(first_col, width=COL_W_FIRST)
                except Exception:
                    pass
        except Exception:
            pass

    # --- [UI|LAYOUT] _center_window ------------------------------------
    def _center_window(self, offset_y: int = -80):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2 + offset_y)
        self.geometry(f"{w}x{h}+{x}+{y}")

    # --- [HOSTNAME|UI] _on_manage_hostname_aliases -------------------------
    # Purpose: Manage hostname aliases (add/edit/delete/clear-cache)
    def _on_manage_hostname_aliases(self):
        import tkinter as tk
        import tkinter.ttk as ttk
        import tkinter.simpledialog as sd
        import tkinter.messagebox as mb

        # build dialog
        dlg = tk.Toplevel(self)
        dlg.title("Manage Hostname Aliases")
        dlg.transient(self)
        dlg.grab_set()
        dlg.lift()
        dlg.focus_force()
        try:
            dlg.attributes("-topmost", True)
            dlg.after(10, lambda: dlg.attributes("-topmost", False))
        except Exception:
            pass
    
        # Layout
        frm = ttk.Frame(dlg); frm.pack(fill="both", expand=True, padx=10, pady=10)
        tree = ttk.Treeview(frm, columns=("ip", "name"), show="headings", height=12)
        tree.heading("ip", text="IP")
        tree.heading("name", text="Name")
        tree.column("ip", width=160, anchor="w")
        tree.column("name", width=260, anchor="w")
        y = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=y.set)
        tree.grid(row=0, column=0, sticky="nsew"); y.grid(row=0, column=1, sticky="ns")
        frm.grid_rowconfigure(0, weight=1); frm.grid_columnconfigure(0, weight=1)

        btns = ttk.Frame(frm); btns.grid(row=1, column=0, sticky="e", pady=(8, 0))

        def _refresh_tree():
            tree.delete(*tree.get_children())
            try:
                data = _HOSTNAMES.aliases()
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}
            for ip, name in sorted(data.items(), key=lambda kv: kv[0]):
                tree.insert("", "end", values=(ip, name))

        def _add():
            ip = sd.askstring("Add Alias", "IP address:", parent=dlg)
            if ip is None or not ip.strip():
                return
            name = sd.askstring("Add Alias", "Friendly name:", parent=dlg)
            if name is None:
                return
            _HOSTNAMES.set_alias(ip.strip(), name.strip())
            _refresh_tree()
            # small UI hint
            self.status.set(f"Alias set for {ip.strip()}")

        def _edit():
            sel = tree.selection()
            if not sel:
                mb.showinfo("Edit Alias", "Select a row first.", parent=dlg)
                return
            ip, cur_name = tree.item(sel[0], "values")
            name = sd.askstring("Edit Alias", f"IP: {ip}\nFriendly name:", initialvalue=cur_name, parent=dlg)
            if name is None:
                return
            _HOSTNAMES.set_alias(ip, name.strip())
            _refresh_tree()
            self.status.set(f"Alias updated for {ip}")

        def _delete():
            sel = tree.selection()
            if not sel:
                mb.showinfo("Delete Alias", "Select a row first.", parent=dlg)
                return
            ip, _ = tree.item(sel[0], "values")
            if mb.askyesno("Delete", f"Remove alias for {ip}?", parent=dlg):
                _HOSTNAMES.set_alias(ip, None)
                _refresh_tree()
                self.status.set(f"Alias removed for {ip}")

        # Buttons + simple key bindings
        ttk.Button(btns, text="Add", command=_add).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Edit", command=_edit).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Delete", command=_delete).pack(side="left")
        ttk.Button(btns, text="Close", command=dlg.destroy).pack(side="left", padx=(12, 0))

        tree.bind("<Delete>", lambda e: _delete())
        tree.bind("<Return>", lambda e: _edit())

        _refresh_tree()

    # --- [UI|TREEVIEW] _make_treeview_sortable ------------------------------------
    def _make_treeview_sortable(self, tree, col_types=None):
        """
        Enable click-to-sort for a ttk.Treeview.
        col_types: optional dict mapping column name -> 'num' | 'text'
                If omitted, tries to infer by looking at the first row.
        """
        cols = tree["columns"]
        sort_state = {c: None for c in cols}  # None/True/False

        def _coerce(v, kind):
            if kind == "num":
                # handle ints that may be '', '-', 'Yes/No', etc.
                if isinstance(v, (int, float)):
                    return v
                s = str(v).strip()
                if s.lower() in {"yes", "true"}: return 1
                if s.lower() in {"no", "false"}: return 0
                try:
                    return int(s.replace(",", ""))
                except Exception:
                    try:
                        return float(s.replace(",", ""))
                    except Exception:
                        return 0
            return str(v)

        def _infer_kind(col):
            # Peek at first non-empty cell
            for iid in tree.get_children(""):
                vals = tree.item(iid, "values")
                if not vals: 
                    continue
                try:
                    idx = cols.index(col)
                    probe = vals[idx]
                except Exception:
                    probe = ""
                # quick numeric check
                s = str(probe).strip().replace(",", "")
                if s and (s.isdigit() or s.lower() in {"yes","no","true","false"}):
                    return "num"
                try:
                    float(s)
                    return "num"
                except Exception:
                    pass
                break
            return "text"

        def _sort_by(col):
            kind = (col_types or {}).get(col) or _infer_kind(col)
            # toggle asc/desc
            asc = sort_state[col] is not True
            sort_state[col] = asc

            rows = []
            for iid in tree.get_children(""):
                vals = tree.item(iid, "values")
                key = _coerce(vals[cols.index(col)] if vals else "", kind)
                rows.append((key, iid))

            rows.sort(key=lambda x: x[0], reverse=not asc)

            for idx, (_, iid) in enumerate(rows):
                tree.move(iid, "", idx)

        # attach commands
        for c in cols:
            tree.heading(c, text=tree.heading(c, "text"), command=lambda cc=c: _sort_by(cc))

    # --- [UI|DIALOG] _open_settings_dialog ------------------------------------
    def _open_settings_dialog(self):
        """Open a modal Settings dialog for core app options."""
        import tkinter as tk
        from tkinter import ttk, messagebox

        # Current values from config (with sensible fallbacks)
        cfg = self.cfg if hasattr(self, "cfg") and isinstance(self.cfg, dict) else {}
        router_ip      = str(cfg.get("router_ip", ROUTER_IP))
        poll_secs      = int(cfg.get("poll_interval_seconds", POLL_INTERVAL_SECONDS))
        copy_limit     = int(cfg.get("copy_limit_rows", COPY_LIMIT_ROWS))
        tail_lines     = int(cfg.get("debug_log_tail_lines", DEBUG_LOG_TAIL_LINES))
        show_idle      = bool(cfg.get("show_idle_devices", DEFAULT_SHOW_IDLE_DEVICES))
        resolve_rdns   = bool(cfg.get("resolve_rdns", RESOLVE_RDNS))
        use_conntrack  = bool(cfg.get("enable_conntrack_ssh", ENABLE_CONNTRACK_SSH))
        use_netflow    = bool(cfg.get("enable_netflow_v5_collector", ENABLE_NETFLOW_V5_COLLECTOR))
        enable_toasts  = bool(cfg.get("enable_toasts", ENABLE_TOASTS))

        # --- build dialog window ---
        win = tk.Toplevel(self)
        win.title("Settings")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        body = ttk.Frame(win, padding=10)
        body.grid(row=0, column=0, sticky="nsew")

        row = 0

        # Router IP
        ttk.Label(body, text="Router IP / SSH host:").grid(row=row, column=0, sticky="w")
        router_var = tk.StringVar(value=router_ip)
        ttk.Entry(body, textvariable=router_var, width=20).grid(row=row, column=1, sticky="w")
        row += 1

        # Poll interval
        ttk.Label(body, text="Poll interval (seconds):").grid(row=row, column=0, sticky="w")
        poll_var = tk.StringVar(value=str(poll_secs))
        ttk.Entry(body, textvariable=poll_var, width=8).grid(row=row, column=1, sticky="w")
        row += 1

        # Copy limit
        ttk.Label(body, text="Copy/export row limit:").grid(row=row, column=0, sticky="w")
        copy_var = tk.StringVar(value=str(copy_limit))
        ttk.Entry(body, textvariable=copy_var, width=8).grid(row=row, column=1, sticky="w")
        row += 1

        # Debug log tail
        ttk.Label(body, text="Debug log tail (lines):").grid(row=row, column=0, sticky="w")
        tail_var = tk.StringVar(value=str(tail_lines))
        ttk.Entry(body, textvariable=tail_var, width=8).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Separator(body, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4)
        )
        row += 1

        # Checkboxes
        show_idle_var     = tk.BooleanVar(value=show_idle)
        resolve_rdns_var  = tk.BooleanVar(value=resolve_rdns)
        conntrack_var     = tk.BooleanVar(value=use_conntrack)
        netflow_var       = tk.BooleanVar(value=use_netflow)
        toasts_var        = tk.BooleanVar(value=enable_toasts)

        ttk.Checkbutton(body, text="Show idle devices in Aggregates", variable=show_idle_var).grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1

        ttk.Checkbutton(body, text="Resolve rDNS for IPs",
            variable=resolve_rdns_var).grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1

        ttk.Checkbutton(body, text="Use conntrack SSH collector",
            variable=conntrack_var).grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1

        ttk.Checkbutton(body, text="Use NetFlow v5 collector",
            variable=netflow_var).grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1

        ttk.Checkbutton(body, text="Enable Windows toast notifications (experimental)",
            variable=toasts_var).grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1

        # Buttons
        btns = ttk.Frame(body)
        btns.grid(row=row, column=0, columnspan=2, pady=(12, 0), sticky="e")
        row += 1

        def on_ok():
            nonlocal router_ip, poll_secs, copy_limit, tail_lines
            # Validate numeric fields
            try:
                new_poll  = int(poll_var.get() or poll_secs)
                new_copy  = int(copy_var.get() or copy_limit)
                new_tail  = int(tail_var.get() or tail_lines)
                if new_poll <= 0:
                    raise ValueError("Poll interval must be > 0")
                if new_copy <= 0:
                    raise ValueError("Copy limit must be > 0")
                if new_tail <= 0:
                    raise ValueError("Debug tail lines must be > 0")
            except Exception as e:
                messagebox.showerror("Invalid value", f"Please check numeric fields:\n{e}", parent=win)
                return

            # Update cfg dict
            self.cfg["router_ip"]                   = router_var.get().strip() or router_ip
            self.cfg["poll_interval_seconds"]       = new_poll
            self.cfg["copy_limit_rows"]             = new_copy
            self.cfg["debug_log_tail_lines"]        = new_tail
            self.cfg["show_idle_devices"]           = bool(show_idle_var.get())
            self.cfg["resolve_rdns"]                = bool(resolve_rdns_var.get())
            self.cfg["enable_conntrack_ssh"]        = bool(conntrack_var.get())
            self.cfg["enable_netflow_v5_collector"] = bool(netflow_var.get())
            self.cfg["enable_toasts"]               = bool(toasts_var.get())

            # Persist to config.json
            self.save_config()

            # Apply immediately where safe
            global ROUTER_IP, UDM_SSH_HOST
            global POLL_INTERVAL_SECONDS, COPY_LIMIT_ROWS, DEBUG_LOG_TAIL_LINES
            global RESOLVE_RDNS, ENABLE_TOASTS, _TOASTER
            global ENABLE_CONNTRACK_SSH, ENABLE_NETFLOW_V5_COLLECTOR

            ROUTER_IP                    = self.cfg["router_ip"]
            UDM_SSH_HOST                 = ROUTER_IP
            POLL_INTERVAL_SECONDS        = self.cfg["poll_interval_seconds"]
            COPY_LIMIT_ROWS              = self.cfg["copy_limit_rows"]
            DEBUG_LOG_TAIL_LINES         = self.cfg["debug_log_tail_lines"]
            RESOLVE_RDNS                 = self.cfg["resolve_rdns"]
            ENABLE_TOASTS                = self.cfg["enable_toasts"]
            ENABLE_CONNTRACK_SSH         = self.cfg["enable_conntrack_ssh"]
            ENABLE_NETFLOW_V5_COLLECTOR  = self.cfg["enable_netflow_v5_collector"]

            # sync Tk vars that already exist
            try:
                self.show_idle_var.set(self.cfg["show_idle_devices"])
            except Exception:
                pass

            # re-init toaster
            _TOASTER = None
            if ENABLE_TOASTS:
                try:
                    from win10toast import ToastNotifier  # type: ignore
                    _TOASTER = ToastNotifier()
                except Exception:
                    _TOASTER = None

            summary = [
                f"Router IP: {ROUTER_IP}",
                f"Poll interval: {POLL_INTERVAL_SECONDS}s",
                f"Copy limit: {COPY_LIMIT_ROWS} rows",
                f"Debug tail: {DEBUG_LOG_TAIL_LINES} lines",
                f"rDNS: {'ON' if RESOLVE_RDNS else 'OFF'}",
                f"Show idle devices: {'Yes' if self.cfg['show_idle_devices'] else 'No'}",
                f"Conntrack SSH: {'ON' if ENABLE_CONNTRACK_SSH else 'OFF'} (restart may be required)",
                f"NetFlow v5: {'ON' if ENABLE_NETFLOW_V5_COLLECTOR else 'OFF'} (restart may be required)",
                f"Toasts: {'ON' if ENABLE_TOASTS else 'OFF'}",
            ]

            self._set_status("Settings saved.")
            messagebox.showinfo("Settings saved", "\n".join(summary), parent=win)

            win.destroy()

        def on_cancel():
            win.destroy()

        ttk.Button(btns, text="Cancel", command=on_cancel).pack(side="right", padx=(4, 0))
        ttk.Button(btns, text="OK", command=on_ok).pack(side="right")

    # --- [UI|MENU] _build_menu ------------------------------------
    def _build_menu(self):
        import tkinter as tk
        menubar = tk.Menu(self)

        # File
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        view_menu = tk.Menu(menubar, tearoff=False)
        view_menu.add_checkbutton(
            label="Show idle devices (no traffic)",
            variable=self.show_idle_var,
            command=self._on_toggle_show_idle,
        )
        
        menubar.add_cascade(label="View", menu=view_menu)

        # Tools
        tools_menu = tk.Menu(menubar, tearoff=False)
        tools_menu.add_command(label="Edit SSH Credentials…", command=self._on_edit_ssh_credentials)
        tools_menu.add_separator()
        tools_menu.add_command(label="Copy Unknown Vendors to Clipboard", command=self._on_copy_unknown_vendors_menu)
        tools_menu.add_separator()
        tools_menu.add_command(label="Manage Hostname Aliases…", command=self._on_manage_hostname_aliases)
        tools_menu.add_command(label="Set Hostname Alias (from selection)", command=self._on_set_hostname_alias)
        tools_menu.add_separator()
        tools_menu.add_command(label="Test SSH Credentials…", command=self._on_test_ssh)

        rdns_var = tk.BooleanVar(value=self.cfg.get("resolve_rdns", True))
        tools_menu.add_checkbutton(label="Resolve rDNS", onvalue=True, offvalue=False, variable=rdns_var, command=self._toggle_rdns)
        
        conntrack_var = tk.BooleanVar(value=self.cfg.get("enable_conntrack_ssh", ENABLE_CONNTRACK_SSH))
        tools_menu.add_checkbutton(label="Use conntrack SSH collector", variable=conntrack_var, command=self._toggle_conntrack_ssh,)

        netflow_var = tk.BooleanVar(value=self.cfg.get("enable_netflow_v5_collector", ENABLE_NETFLOW_V5_COLLECTOR))
        tools_menu.add_checkbutton(label="Use NetFlow v5 collector", variable=netflow_var, command=self._toggle_netflow_v5,)

        tools_menu.add_separator()
        tools_menu.add_command(label="Settings…", command=self._open_settings_dialog)
        
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help
        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="About", command=self._on_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    # --- [UI|TREEVIEW] _ensure_headings ------------------------------------
    def _ensure_headings(self, tv, cols_tuple):
        # Keep columns, displaycolumns, and show in sync so headings never disappear
        tv["columns"] = cols_tuple
        tv["displaycolumns"] = cols_tuple
        tv["show"] = "headings"

    # --- [UI|BUILD] _build_ui --------------------------------------------------
    # Purpose: MENUBAR + CONTENT (Alerts + Active + Aggregates + Details)
    #          + STATUS (bottom) + FOOTER (above status)
    def _build_ui(self):
        import tkinter as tk
        from tkinter import ttk

        # ----- wipe existing widgets (hot reload safety) -----
        for child in self.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        # Ensure note/status vars exist
        if not hasattr(self, "note"):
            self.note = tk.StringVar(value="")
        if not hasattr(self, "status"):
            self.status = tk.StringVar(value="Ready")

        # ----- menubar (optional) -----
        if hasattr(self, "_build_menu"):
            try:
                self._build_menu()
            except Exception:
                pass

        # ===== shared widths so first 4 columns align across tables =====
        COL_W_FIRST = 140
        COL_W_MAC   = 160
        COL_W_VEND  = 220
        COL_W_DEST  = 420
        COL_W_LOCAL = 160
        COL_W_LAST  = 140
        COL_W_BYTES = 110

        def _force_headings(tv: ttk.Treeview, labels: dict[str, str]):
            cols = tuple(labels.keys())
            tv["columns"] = cols
            tv["displaycolumns"] = cols
            tv["show"] = "headings"
            for cid, txt in labels.items():
                tv.heading(cid, text=txt)

            def _reassert():
                for cid, txt in labels.items():
                    tv.heading(cid, text=txt)

            tv.after_idle(_reassert)

        # =========================================================================
        # === FOOTER (buttons above statusbar) ====================================
        # =========================================================================
        foot = ttk.Frame(self)
        foot.pack(side="bottom", fill="x", padx=8, pady=(0, 6))
        self.foot = foot

        # right cluster
        ttk.Button(
            foot,
            text="Copy Alerts",
            command=self._copy_alerts,
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            foot,
            text="Copy Active",
            command=self._copy_active,
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            foot,
            text="Copy Aggregates",
            command=self._copy_aggregates,
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            foot,
            text="Export Snapshot (CSV)",
            command=self._export_snapshot,
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            foot,
            text="Manage Hostname Aliases",
            command=self._on_manage_hostname_aliases,
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            foot,
            text="Set Hostname Alias (from selection)",
            command=self._on_set_hostname_alias,
        ).pack(side="right", padx=(8, 12))

        # left cluster (always visible)
        ttk.Button(
            foot,
            text="Export unknown MAC addresses",
            command=self._on_copy_unknown_vendors_menu,
        ).pack(side="left")
        ttk.Button(
            foot,
            text="Copy Debug Bundle",
            command=self._copy_debug_bundle,
        ).pack(side="left", padx=(8, 12))

        # =========================================================================
        # === Statusbar (very bottom) =============================================
        # =========================================================================
        statusf = ttk.Frame(self)
        statusf.pack(side="bottom", fill="x", padx=8, pady=(2, 4))

        # Left side: note + status text
        note_label = ttk.Label(statusf, textvariable=self.note, anchor="w")
        note_label.pack(side="left", fill="x", expand=True)

        status_label = ttk.Label(statusf, textvariable=self.status, anchor="w")
        status_label.pack(side="left", padx=(8, 0))

        # Right side: metrics
        self.status_conn = tk.StringVar(value="Active: 0 | MACs: 0")
        self.status_flow = tk.StringVar(value="Flow: off")
        self.status_ssh = tk.StringVar(value="SSH: off")
        self.status_clock = tk.StringVar(value="Clock: n/a")

        ttk.Label(statusf, textvariable=self.status_conn, anchor="e").pack(
            side="right", padx=(8, 0)
        )
        ttk.Label(statusf, textvariable=self.status_flow, anchor="e").pack(
            side="right", padx=(8, 0)
        )
        ttk.Label(statusf, textvariable=self.status_ssh, anchor="e").pack(
            side="right", padx=(8, 0)
        )
        ttk.Label(statusf, textvariable=self.status_clock, anchor="e").pack(
            side="right", padx=(8, 0)
        )

        # =========================================================================
        # === UI.CONTENT (everything that scrolls/expands) ========================
        # =========================================================================
        # Outer horizontal paned: left = tables, right = details panel
        main_paned = ttk.PanedWindow(self, orient="horizontal")
        # Tighten padding so sidebar sits closer to the tables
        main_paned.pack(fill="both", expand=True, padx=2, pady=2)
        self.main_paned = main_paned  # keep a reference so we can restore sash
        self.main_paned.bind("<B1-Motion>", self._on_sash_drag)

        # Left content (tables)
        content = ttk.Frame(main_paned)
        main_paned.add(content, weight=3)

        # Inside left content: vertical paned for Alerts + Active
        # Less right padding so the right edge is close to the sash
        paned = ttk.PanedWindow(content, orient="vertical")
        paned.pack(fill="both", expand=True, padx=(8, 0), pady=4)

        # Right-hand details panel (width hint; acts like fixed sidebar)
        details_outer = ttk.Frame(main_paned, width=380)
        main_paned.add(details_outer, weight=0)
        self._build_details_panel(details_outer)

        # Kick off restoration of details width from config
        self.after(50, self._restore_details_width)

        # =========================================================================
        # === Alerts SECTION (top of left content) ================================
        # =========================================================================
        alert_outer = ttk.Frame(paned)
        paned.add(alert_outer, weight=1)

        # Global filter row sits at the very top so it visually applies to everything,
        # not just the Alerts table.
        filter_row = ttk.Frame(alert_outer)
        filter_row.pack(fill="x", pady=(4, 0))

        ttk.Label(filter_row, text="Filter (all tables):").pack(side="left")

        self.alert_filter_var = tk.StringVar()
        entry = ttk.Entry(filter_row, textvariable=self.alert_filter_var, width=30)
        entry.pack(side="left", padx=(4, 8))

        # live filtering as the user types (global across all tables)
        self.alert_filter_var.trace_add(
            "write", lambda *args: self._apply_alert_filter()
        )

        ttk.Button(
            filter_row,
            text="Clear",
            command=lambda: self.alert_filter_var.set(""),
        ).pack(side="left")

        # Alerts title now comes *below* the filter row
        self.alerts_title = tk.StringVar(value="Alerts")
        ttk.Label(
            alert_outer,
            textvariable=self.alerts_title,
            anchor="w",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="top", anchor="w", pady=(2, 0))

        alertf = ttk.Frame(alert_outer)
        alertf.pack(fill="both", expand=True)

        alerts_labels = {
            "time":   "Time",
            "mac":    "MAC",
            "vendor": "Vendor/Host",
            "dest":   "Destination",
            "local":  "Local",
            "bytes":  "Bytes (TX)",
            "note":   "Note",
        }
        self.alerts = ttk.Treeview(
            alertf,
            columns=tuple(alerts_labels),
            show="headings",
            height=8,
        )
        _force_headings(self.alerts, alerts_labels)

        self.alerts.column("time",   width=COL_W_FIRST, minwidth=COL_W_FIRST, stretch=False, anchor="w")
        self.alerts.column("mac",    width=COL_W_MAC,   minwidth=COL_W_MAC,   stretch=False, anchor="w")
        self.alerts.column("vendor", width=COL_W_VEND,  minwidth=COL_W_VEND,  stretch=False, anchor="w")
        self.alerts.column("dest",   width=COL_W_DEST,  minwidth=COL_W_DEST,  stretch=False, anchor="w")
        self.alerts.column("local",  width=COL_W_LOCAL, minwidth=COL_W_LOCAL, stretch=False, anchor="w")
        self.alerts.column("bytes",  width=COL_W_BYTES, minwidth=COL_W_BYTES, stretch=False, anchor="e")
        self.alerts.column("note",   width=180,         minwidth=120,         stretch=True,  anchor="w")

        self._apply_saved_column_widths("alerts", self.alerts)

        self.alerts.tag_configure("unknown_vendor", background=UNKNOWN_VENDOR_BACKGROUND)
        self.alerts.tag_configure("high_volume",    background=HIGH_VOLUME_BACKGROUND)
        self.alerts.tag_configure("new_device",     background=NEW_DEVICE_BACKGROUND)

        scry1 = ttk.Scrollbar(alertf, orient="vertical", command=self.alerts.yview)
        self.alerts.configure(yscrollcommand=scry1.set)
        self.alerts.pack(side="left", fill="both", expand=True, pady=8)
        scry1.pack(side="left", fill="y", padx=(0, 4), pady=8)  # smaller gap to the right

        if hasattr(self, "_bind_edit_on_doubleclick"):
            self._bind_edit_on_doubleclick(
                self.alerts,
                mac_col="mac",
                vendor_col="vendor",
                local_col="local",
            )

        self.alerts.bind("<Button-3>", self._on_right_click_active)

        # Update details panel when selection changes in Alerts
        self.alerts.bind(
            "<<TreeviewSelect>>",
            lambda e: self._update_details_from_tree(self.alerts, "alerts"),
        )

        # =========================================================================
        # === Active Connections SECTION (middle of left content) =================
        # =========================================================================
        active_outer = ttk.Frame(paned)
        paned.add(active_outer, weight=2)

        self.active_title = tk.StringVar(value="Active Connections (top 200)")
        ttk.Label(
            active_outer,
            textvariable=self.active_title,
            anchor="w",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="top", anchor="w", pady=(4, 0))

        midf = ttk.Frame(active_outer)
        midf.pack(fill="both", expand=True)

        active_labels = {
            "first":  "First Seen",
            "mac":    "MAC",
            "vendor": "Vendor/Host",
            "dest":   "Destination",
            "local":  "Local",
            "last":   "Last Seen",
            "bytes":  "Bytes (TX)",
            "over1mb":">1MB?",
            "state":  "State",  # hidden unless DEBUG
        }
        self.tree = ttk.Treeview(
            midf,
            columns=tuple(active_labels),
            show="headings",
            height=14,
        )
        _force_headings(self.tree, active_labels)

        self._setup_sorting(
            self.tree,
            table_name="active",
            default_col="last",      # default sort by 'Last seen'
            default_reverse=False,   # newest last
        )

        # Lock first four to match Alerts
        self.tree.column("first",   width=COL_W_FIRST, minwidth=COL_W_FIRST, stretch=False, anchor="w")
        self.tree.column("mac",     width=COL_W_MAC,   minwidth=COL_W_MAC,   stretch=False, anchor="w")
        self.tree.column("vendor",  width=COL_W_VEND,  minwidth=COL_W_VEND,  stretch=False, anchor="w")
        self.tree.column("dest",    width=COL_W_DEST,  minwidth=COL_W_DEST,  stretch=False, anchor="w")
        self.tree.column("local",   width=COL_W_LOCAL, minwidth=COL_W_LOCAL, stretch=False, anchor="w")
        self.tree.column("last",    width=COL_W_LAST,  minwidth=COL_W_LAST,  stretch=False, anchor="w")
        self.tree.column("bytes",   width=COL_W_BYTES, minwidth=COL_W_BYTES, stretch=False, anchor="e")
        self.tree.column("over1mb", width=70,          minwidth=70,          stretch=False, anchor="center")
        self.tree.column("state",   width=110,         minwidth=80,          stretch=False, anchor="w")

        self.tree.tag_configure("unknown_vendor", background=UNKNOWN_VENDOR_BACKGROUND)
        self.tree.tag_configure("high_volume",    background=HIGH_VOLUME_BACKGROUND)
        self.tree.tag_configure("new_device",     background=NEW_DEVICE_BACKGROUND)

        self.tree.bind("<Button-3>", self._on_right_click_active)

        self._apply_saved_column_widths("active", self.tree)

        scry2 = ttk.Scrollbar(midf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scry2.set)
        self.tree.pack(side="left", fill="both", expand=True, pady=8)
        scry2.pack(side="left", fill="y", padx=(0, 4), pady=8)  # smaller gap

        if hasattr(self, "_bind_edit_on_doubleclick"):
            self._bind_edit_on_doubleclick(
                self.tree,
                mac_col="mac",
                vendor_col="vendor",
                local_col="local",
            )
        if hasattr(self, "_apply_state_visibility"):
            self._apply_state_visibility()

        # Update details panel when selection changes in Active
        self.tree.bind(
            "<<TreeviewSelect>>",
            lambda e: self._update_details_from_tree(self.tree, "active"),
        )

        # =========================================================================
        # === Aggregates SECTION (bottom of left content) =========================
        # =========================================================================
        agg_outer = ttk.Frame(content)
        agg_outer.pack(fill="both", expand=False, padx=8, pady=(0, 4))

        self.agg_title = tk.StringVar(value="Per-Device Totals")
        ttk.Label(
            agg_outer,
            textvariable=self.agg_title,
            anchor="w",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="top", anchor="w", pady=(4, 0))

        aggf = ttk.Frame(agg_outer)
        aggf.pack(fill="both", expand=True)

        agg_labels = {
            "sightings": "Sightings",
            "mac":       "MAC",
            "vendor":    "Vendor/Host",
            "dest":      "Destination",
            "bytes":     "Total Bytes",
        }

        self.agg = ttk.Treeview(
            aggf,
            columns=tuple(agg_labels),
            show="headings",
            height=8,
        )
        _force_headings(self.agg, agg_labels)

        self._setup_sorting(
            self.agg,
            table_name="agg",
            default_col="sightings",
            default_reverse=True,
        )

        self.agg.column("sightings", width=COL_W_FIRST, minwidth=COL_W_FIRST, stretch=False, anchor="e")
        self.agg.column("mac",       width=COL_W_MAC,   minwidth=COL_W_MAC,   stretch=False, anchor="w")
        self.agg.column("vendor",    width=COL_W_VEND,  minwidth=COL_W_VEND,  stretch=False, anchor="w")
        self.agg.column("dest",      width=COL_W_DEST,  minwidth=COL_W_DEST,  stretch=False, anchor="w")
        self.agg.column("bytes",     width=COL_W_BYTES, minwidth=COL_W_BYTES, stretch=False, anchor="e")

        self.agg.tag_configure("unknown_vendor", background=UNKNOWN_VENDOR_BACKGROUND)
        self.agg.tag_configure("high_volume",    background=HIGH_VOLUME_BACKGROUND)
        self.agg.tag_configure("new_device",     background=NEW_DEVICE_BACKGROUND)

        self.agg.bind("<Button-3>", self._on_right_click_active)
        self._apply_saved_column_widths("agg", self.agg)

        scry3 = ttk.Scrollbar(aggf, orient="vertical", command=self.agg.yview)
        self.agg.configure(yscrollcommand=scry3.set)
        self.agg.pack(side="left", fill="both", expand=True, pady=8)
        scry3.pack(side="left", fill="y", padx=(0, 4), pady=8)  # smaller gap

        if hasattr(self, "_bind_edit_on_doubleclick"):
            self._bind_edit_on_doubleclick(
                self.agg,
                mac_col="mac",
                vendor_col="vendor",
                local_col=None,
            )

        # Update details panel when selection changes in Aggregates
        self.agg.bind(
            "<<TreeviewSelect>>",
            lambda e: self._update_details_from_tree(self.agg, "agg"),
        )

        self._post_build_column_fix()

        # schedule refresh after widgets exist
        try:
            self.after(250, self._refresh_ui)
        except Exception:
            pass

# endregion UI WIDGETS

    # =============================================================================
    # SECTION: UI CONTROLLER (events, handlers, refresh loop)
    # =============================================================================
    # region UI CONTROLLER

    # --- [HELPERS|ALIAS/VENDOR LABELS] -----------------------------------------
    
    # --- [UI|DPI] _auto_dpi_scaling ------------------------------------
    def _auto_dpi_scaling(self) -> None:
        """
        Automatically adjust Tk scaling based on the system DPI.

        On Windows, 96 DPI is "normal" (100%). We query how many pixels Tk
        thinks are in 1 inch ("1i") and scale relative to 96.
        """
        try:
            # How many pixels are in 1 inch according to Tk?
            pixels_per_inch = float(self.winfo_fpixels("1i"))
            if pixels_per_inch <= 0:
                return

            # 96 px/inch is the standard baseline (100% scaling)
            scale = pixels_per_inch / 96.0

            # Clamp to something sane so weird environments don't explode
            scale = max(0.75, min(scale, 2.5))

            # Apply to Tk's global scaling (affects fonts and some geometry)
            self.call("tk", "scaling", scale)

            # Optional debug:
            # print(f"[DPI] pixels_per_inch={pixels_per_inch:.2f}, scale={scale:.2f}")

        except Exception:
            # Never crash if DPI probing fails
            pass

    # --- [UI] _apply_state_visibility ------------------------------------
    def _apply_state_visibility(self):
        """Hide/show the 'state' column (last col in Active). Hidden unless DEBUG."""
        show = bool(globals().get("DEBUG", False))
        col = "state"
        if show:
            self.tree.heading(col, text="State")
            self.tree.column(col, width=110, minwidth=60, stretch=False, anchor="w")
        else:
            self.tree.heading(col, text="")
            self.tree.column(col, width=0, minwidth=0, stretch=False)

    # --- [UI|TREEVIEW] _bind_edit_on_doubleclick ------------------------------------
    def _bind_edit_on_doubleclick(self, tv, mac_col="mac", vendor_col="vendor", local_col=None):
        """
        Bind a double-click handler on a ttk.Treeview so that:
          - double-clicking the MAC or Vendor/Host cell edits the custom label for that MAC
          - double-clicking the local IP cell (if local_col given) edits the hostname alias for that IP

        After saving, it refreshes the vendor/host display for the current table.
        """
        # --- [UI|TREEVIEW] _select_ip_for_row ------------------------------------
        def _select_ip_for_row(row_vals: dict[str, str]) -> str:
            """Best-effort extraction of an IP address from a row dict.

            For "local" / "remote" style columns we may see "ip:port", so we
            split off the port if present.
            """
            # Prefer explicit local_col if provided
            if local_col:
                val = row_vals.get(local_col) or ""
                if val:
                    # e.g. "192.168.1.2:53596"
                    return (val.split()[0].split(":")[0]).strip()

            # Fall back to common column names if present
            for col in ("local", "remote", "src", "dst"):
                val = row_vals.get(col) or ""
                if val:
                    return (val.split()[0].split(":")[0]).strip()

            return ""

        # --- [UI|TREEVIEW] _on_dclick ------------------------------------
        def _on_dclick(event):
            region = tv.identify("region", event.x, event.y)
            if region != "cell":
                return

            row_iid = tv.identify_row(event.y)
            col_id = tv.identify_column(event.x)  # e.g. "#1", "#2", ...
            if not row_iid or not col_id:
                return

            try:
                col_index = int(col_id.strip("#")) - 1
            except Exception:
                return

            cols = list(tv["columns"])
            if col_index < 0 or col_index >= len(cols):
                return
            clicked_col = cols[col_index]

            # If user double-clicked the local IP column, open alias editor for that IP
            if local_col and clicked_col == local_col:
                row_vals = {c: tv.set(row_iid, c) for c in cols}
                ip_val = _select_ip_for_row(row_vals)
                if ip_val and hasattr(self, "_edit_alias_for_ip"):
                    try:
                        self._edit_alias_for_ip(ip_val)
                    except Exception:
                        pass

                # After alias change, refresh this table's Vendor/Host column
                if hasattr(self, "_refresh_vendor_column_for_table"):
                    try:
                        self._refresh_vendor_column_for_table(tv)
                    except Exception:
                        pass
                return

            # Otherwise: only engage on MAC or Vendor/Host column (for MAC label editing)
            if clicked_col not in {mac_col, vendor_col}:
                return

            # Build a dict of row values for easy access
            row_vals = {c: tv.set(row_iid, c) for c in cols}

            mac_val = row_vals.get(mac_col, "") or ""
            ip_val = _select_ip_for_row(row_vals)

            # Open the MAC label editor dialog
            if hasattr(self, "_open_edit_dialog"):
                try:
                    result = self._open_edit_dialog(mac_val, ip_val)
                except Exception:
                    result = None
            else:
                result = None

            # After editing the MAC label, refresh vendor/host for this table
            if hasattr(self, "_refresh_vendor_column_for_table"):
                try:
                    self._refresh_vendor_column_for_table(tv)
                except Exception:
                    pass

        # Bind double-click to this Treeview
        tv.bind("<Double-1>", _on_dclick, add="+")

    # --- [HELPER] _compose_destination ------------------------------------        
    def _compose_destination(self, ip_port: str | None, host: str | None = None) -> str:
        """Return 'IP [host]:port' if host present, else 'IP:port' or '-'."""
        if not ip_port:
            return "-"
        if host:
            try:
                ip, port = ip_port.rsplit(":", 1)
                return f"{ip} [{host}]:{port}"
            except ValueError:
                return f"{ip_port} [{host}]"
        return ip_port

    # --- [UI] _edit_alias_for_ip ------------------------------------
    def _edit_alias_for_ip(self, ip: str) -> None:
        """Quick inline editor for a single IP alias, used when double-clicking a local IP."""
        from tkinter import simpledialog as sd, messagebox as mb

        ip = (ip or "").strip()
        if not ip:
            return

        # Get current alias, if any
        try:
            current = _HOSTNAMES.name_for_ip(ip) or ""
        except Exception:
            current = ""

        name = sd.askstring(
            "Hostname Alias",
            f"IP: {ip}\nFriendly name:",
            initialvalue=current,
            parent=self,
        )
        if name is None:
            return  # user cancelled

        name = name.strip()

        try:
            # Empty -> clear alias
            _HOSTNAMES.set_alias(ip, name or None)
        except Exception:
            mb.showerror("Error", f"Failed to update alias for {ip}", parent=self)
            return

        # Refresh any views that show Vendor/Host using _display_name(...)
        try:
            self._refresh_vendor_column_for_table(self.tree)
        except Exception:
            pass
        try:
            self._refresh_vendor_column_for_table(self.agg)
        except Exception:
            pass

    # --- [UI] _ensure_mac_labels_loaded ------------------------------------
    def _ensure_mac_labels_loaded(self) -> None:
        """Lazy-load MAC labels from disk into self._mac_labels once."""
        if getattr(self, "_mac_labels_loaded", False):
            return
        try:
            self._mac_labels = load_mac_labels()
        except Exception:
            self._mac_labels = {}
        self._mac_labels_loaded = True

    # --- [UI] _fmt_dest ------------------------------------
    def _fmt_dest(remote_ip: str, remote_port: int | str) -> str:
        # Use rDNS cache if present
        try:
            with _dns_lock:
                host = _dns_cache.get(remote_ip)
        except Exception:
            host = None
        return f"{remote_ip} [{host}]:{remote_port}" if host else f"{remote_ip}:{remote_port}"

    # --- [UI] _get_current_label_for_mac ------------------------------------
    def _get_current_label_for_mac(self, mac: str) -> str:
        if not mac:
            return ""
        try:
            self._ensure_mac_labels_loaded()
        except Exception:
            pass
        d = getattr(self, "_mac_labels", None) or {}
        return d.get(mac.upper(), "")

    # --- [UI] _on_sash_drag ------------------------------------
    def _on_sash_drag(self, event=None):
        """
        Live-update the stored panel width while dragging the sash,
        so config.json gets correct values before exit.
        """
        try:
            paned = getattr(self, "main_paned", None)
            if paned is None:
                return

            total = paned.winfo_width()
            left = paned.sashpos(0)   # width of table area
            width = max(0, total - left)

            # store live value
            self.cfg["details_width"] = int(width)

            # optional: debug to console
            # print("[LIVE WIDTH]", width)

        except Exception:
            pass

    # --- [UI] _open_edit_dialog ------------------------------------
    def _open_edit_dialog(self, mac_initial: str, ip_initial: str) -> tuple[str, str] | None:
        """Modal dialog to edit a custom device label for a MAC address.

        ip_initial is only used as context (shown read-only if present).
        """
        import tkinter as tk
        from tkinter import ttk

        # Parent window
        win = tk.Toplevel(self)
        win.title("Edit Device Label")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        # Current custom label for this MAC (if any)
        cur_label = self._get_current_label_for_mac(mac_initial) if mac_initial else ""

        # --- Row 0: MAC address (read-only) ------------------------------------
        ttk.Label(win, text="MAC address:").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 2)
        )
        mac_var = tk.StringVar(value=mac_initial or "")
        mac_entry = ttk.Entry(win, textvariable=mac_var, width=28, state="readonly")
        mac_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=(8, 2))

        # --- Row 1: Custom device label ----------------------------------------
        ttk.Label(win, text="Custom device label:").grid(
            row=1, column=0, sticky="w", padx=8, pady=2
        )
        label_var = tk.StringVar(value=cur_label)
        ttk.Entry(win, textvariable=label_var, width=28).grid(
            row=1, column=1, sticky="ew", padx=8, pady=2
        )

        # Optional context: show which IP this row came from
        next_row = 2
        if ip_initial:
            ttk.Label(
                win,
                text=f"Seen at IP: {ip_initial}",
            ).grid(row=next_row, column=0, columnspan=2,
                   sticky="w", padx=8, pady=(4, 2))
            next_row += 1

        # Buttons
        btnf = ttk.Frame(win)
        btnf.grid(row=next_row, column=0, columnspan=2,
                  sticky="e", padx=8, pady=8)

        result: list[tuple[str, str] | None] = [None]

        def _ok():
            mac = (mac_var.get() or "").strip()
            lbl = (label_var.get() or "").strip()

            if mac:
                self._set_label_for_mac(mac, lbl)

            # We keep the return type compatible: (mac, ip_initial)
            result[0] = (mac, ip_initial or "")
            win.destroy()

        def _cancel():
            result[0] = None
            win.destroy()

        ttk.Button(btnf, text="Cancel", command=_cancel).pack(side="right", padx=(8, 0))
        ttk.Button(btnf, text="OK", command=_ok).pack(side="right")

        # Center over parent
        win.update_idletasks()
        try:
            parent_x = self.winfo_rootx()
            parent_y = self.winfo_rooty()
            parent_w = self.winfo_width()
            parent_h = self.winfo_height()
            w = win.winfo_width()
            h = win.winfo_height()
            x = parent_x + (parent_w - w) // 2
            y = parent_y + (parent_h - h) // 2
            win.geometry(f"+{x}+{y}")
        except Exception:
            pass

        win.wait_window()
        return result[0]

    # --- [UI|HELPER] _parse_ip_from_hostport ------------------------------------
    def _parse_ip_from_hostport(hp: str) -> str:
        # "a.b.c.d:pppp" -> "a.b.c.d"
        try:
            return hp.rsplit(":", 1)[0]
        except Exception:
            return ""

    # --- [UI|DRAG DIVIDOR EVENT] _on_sash_drag ----------------------------------------------
    def _on_sash_drag(self, event=None):
        """
        Live-update the stored details panel width while dragging the sash.
        This only updates self.cfg in memory; config.json is still written
        on close via _on_close → save_config.
        """
        try:
            paned = getattr(self, "main_paned", None)
            if paned is None:
                return

            total = paned.winfo_width()
            left = paned.sashpos(0)          # width of the left (tables) pane
            details_width = max(0, total - left)

            self.cfg["details_width"] = int(details_width)

            # Optional: live debug while tuning
            # print("[LIVE details_width]", self.cfg["details_width"])

        except Exception:
            pass

    # --- [UI] _set_label_for_mac ------------------------------------
    def _set_label_for_mac(self, mac: str, label: str) -> None:
        """Set or clear a custom label for a MAC and persist to disk."""
        mac = (mac or "").strip().upper()
        if not mac:
            return

        # Make sure in-memory dict is loaded from disk first
        try:
            self._ensure_mac_labels_loaded()
        except Exception:
            if not hasattr(self, "_mac_labels"):
                self._mac_labels = {}

        if not hasattr(self, "_mac_labels"):
            self._mac_labels = {}

        # Empty/whitespace label = remove mapping
        lbl = (label or "").strip()
        if lbl:
            self._mac_labels[mac] = lbl
        else:
            self._mac_labels.pop(mac, None)

        # Persist updated map
        try:
            save_mac_labels(self._mac_labels)
        except Exception:
            # Don't crash the UI if write fails
            pass

    # --- [UI] _set_status ------------------------------------
    def _set_status(self, msg: str):
        """Safely update a status indicator if present; otherwise fall back."""
        try:
            # Common pattern: a StringVar bound to a status bar label
            sv = getattr(self, "status_var", None)
            if sv is not None:
                sv.set(str(msg))
                try:
                    self.update_idletasks()
                except Exception:
                    pass
                return

            # Or a direct statusbar label widget
            sb = getattr(self, "statusbar", None)
            if sb is not None and hasattr(sb, "config"):
                sb.config(text=str(msg))
                try:
                    self.update_idletasks()
                except Exception:
                    pass
                return
        except Exception:
            pass

        # Last resort: reflect in the window title, or print
        try:
            self.title(f"SNMP Monitor — {msg}")
        except Exception:
            print(str(msg))

    # --- [UI|TREEVIEW] _setup_sorting ------------------------------------
    def _setup_sorting(self, tree: "ttk.Treeview", table_name: str, default_col: str | None = None, default_reverse: bool = False):
        """
        Make a treeview sortable by header click and remember the last choice.
        self._sort_prefs is a dict: {table_name: (col, reverse)}
        """
        if not hasattr(self, "_sort_prefs"):
            self._sort_prefs = {}

        numeric_cols = {
            # Alerts
            "alerts:bytes", 
            # Active
            "active:bytes", "active:over1mb",
            # Aggregates
            "agg:sightings", "agg:bytes"
        }

        def _sort_key(table: str, col: str, val: str):
            keyid = f"{table}:{col}"
            v = "" if val is None else str(val)
            if keyid in numeric_cols:
                try:
                    return int(v.replace(",", ""))
                except Exception:
                    return 0
            if table == "active" and col == "over1mb":
                return 1 if v.strip().lower() in ("yes", "true", "1") else 0
            # ISO-ish times sort as strings reasonably; leave as is
            return v.lower()

        def _do_sort(col: str):
            # Toggle if same col; else start ascending
            prev = self._sort_prefs.get(table_name, (None, False))
            reverse = (not prev[1]) if prev[0] == col else False

            rows = [(iid, tree.set(iid, col)) for iid in tree.get_children("")]
            rows.sort(key=lambda t: _sort_key(table_name, col, t[1]), reverse=reverse)
            for idx, (iid, _) in enumerate(rows):
                tree.move(iid, "", idx)

            self._sort_prefs[table_name] = (col, reverse)

        # Bind per-column header command
        for col in tree["columns"]:
            tree.heading(col, command=lambda c=col: _do_sort(c))

        # Apply default once
        if default_col:
            self._sort_prefs[table_name] = (default_col, default_reverse)
            _do_sort(default_col)

    # --- [UI|TREEVIEW] _reapply_sort_if_any ------------------------------------
    def _reapply_sort_if_any(self, table_name: str, tree: "ttk.Treeview"):
        """Reapply remembered sort after a refresh."""
        """
        Reapply the last chosen sort for a table, if one exists.

        Used at the end of each UI refresh after rows have been reinserted.

        Parameters
        ----------
        table_name : str
            Key into ``self._sort_prefs`` ('alerts', 'active', 'agg').
        tree : ttk.Treeview
            The Treeview whose rows should be resorted.
        """
        pref = getattr(self, "_sort_prefs", {}).get(table_name)
        if not pref:
            return
        col, reverse_hint = pref
        # Calling _setup_sorting once already installed the header commands;
        # we just trigger a sort by faking a header click (same logic):
        rows = [(iid, tree.set(iid, col)) for iid in tree.get_children("")]
        def _sort_key(val: str):
            # piggyback the same mapper as _setup_sorting (duplicated tiny version):
            v = "" if val is None else str(val)
            if f"{table_name}:{col}" in {"alerts:bytes","active:bytes","active:over1mb","agg:sightings","agg:bytes"}:
                try: return int(v.replace(",", ""))
                except Exception: return 0
            if table_name == "active" and col == "over1mb":
                return 1 if v.strip().lower() in ("yes","true","1") else 0
            return v.lower()
        rows.sort(key=lambda t: _sort_key(t[1]), reverse=reverse_hint)
        for idx, (iid, _) in enumerate(rows):
            tree.move(iid, "", idx)

    # --- [DNS|HELPER] queue rDNS for an IP (no-dup, safe) ------------------------
    # Optionally queue rDNS for aggregate destinations as well (keeps display consistent)
    def _queue_rdns(self, ip: str) -> None:
        if not RESOLVE_RDNS or ip in ("0.0.0.0", "127.0.0.1"):
            return
        with _dns_lock:
            cached = _dns_cache.get(ip)
            if cached is not None or ip in _dns_pending:
                return
            _dns_pending.add(ip)
        try:
            self._dns_q.put_nowait(ip)
        except queue.Full:
            pass

    # --- [DNS|HELPER] format remote connection "ip[:port]" with cached rDNS in [brackets] ----------
    def _fmt_remote(self, ip: str, port: int | str | None = None) -> str:
        name = None
        with _dns_lock:
            name = _dns_cache.get(ip)
        base = f"{ip} [{name}]" if name else ip
        return f"{base}:{port}" if port is not None else base

    # --- [HOSTNAME|UI] _display_local --------------------------------------
    def _display_local(self, local_hostport: str) -> str:
        ip = _HOSTNAMES._ip_from_hostport(local_hostport)
        name = _HOSTNAMES.name_for_ip(ip)
        # Style C: "name (ip):port" or "ip:port" if no name yet
        if not ip:
            return local_hostport or ""
        try:
            ip_only, port = local_hostport.rsplit(":", 1)
        except ValueError:
            ip_only, port = ip, ""
        return f"{name} ({ip}):{port}" if name else f"{ip}:{port}"

    # --- Menu handlers ---
    # --- [UI] _on_about --------------------------------------
    def _on_about(self):
        import tkinter.messagebox as mbox
        import platform
        
        lines = [
            f"{APP_NAME}",
            f"Version: {VERSION}  ({VERSION_DATE})",
            f"Python:  {platform.python_version()}",
            f"SNMP backend: {get_snmp_backend_name()}",
            "",
            "Files:",
            f"  ssh_secrets: {SSH_SECRETS_FILE}",
            f"  config:      {CONFIG_FILE}",
        ]
        
        mbox.showinfo("About","\n".join(lines)
          #  "SNMP Monitor\nVendor resolution via offline DB + local overrides.\n© You."
        )

    # --- [UI] _on_copy_unknown_vendors --------------------------------------
    def _on_copy_unknown_vendors(self, text: str) -> None:
        """Receives the CSV text of unknown OUIs and puts it on the clipboard."""

        self._copy_to_clipboard(text or "","Copied unknown OUI vendors to clipboard")

    # --- [UI] _on_copy_unknown_vendors_menu --------------------------------------
    def _on_copy_unknown_vendors_menu(self):
        def _norm(mac: str) -> str:
            if not mac: return ""
            s = str(mac).strip().upper().replace("-", ":")
            if ":" not in s and len(s) == 12:
                s = ":".join(s[i:i+2] for i in range(0, 12, 2))
            return s

        def _oui(mac: str) -> str:
            parts = (_norm(mac) or "").split(":")
            return ":".join(parts[:3]) if len(parts) >= 3 else ""

        def _is_laa(mac: str) -> bool:
            s = _norm(mac)
            if len(s) < 2: return False
            try:
                return (int(s[:2], 16) & 0x02) != 0
            except Exception:
                return False

        counts = {}
        macs = set(getattr(self.core, "ip2mac", {}).values())
        if not macs:
            for rec in getattr(self.core, "conn_map", {}).values():
                m = rec.get("local_mac")
                if m: macs.add(m)

        # Count OUIs where vendor resolution is Unknown (skip randomized/LAA)
        for mac in macs:
            m = _norm(mac)
            if not m or _is_laa(m):
                continue
            # use your existing resolver import(s)
            if vendor_for_mac(m) == "Unknown":
                o = _oui(m)
                if o:
                    counts[o] = counts.get(o, 0) + 1

        lines = ["# OUI,count"] + [f"{k},{v}" for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]
        self._copy_to_clipboard("\n".join(lines), "Unknown vendor OUIs copied.")

    # --- [CONFIG] load_config ------------------------------------
    def load_config(self) -> dict:
        """
        Load config.json into memory. Falls back to defaults if missing
        or malformed. Never raises.
        """
        try:
            if CONFIG_FILE.exists():
                with CONFIG_FILE.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {**_DEFAULT_CFG, **data}
        except Exception:
            pass
        return dict(_DEFAULT_CFG)

    # --- [CONFIG] save_config ------------------------------------
    def save_config(self, cfg: dict | None = None) -> None:
        """
        Persist runtime config to disk including window geometry,
        state, and panel width values stored in self.cfg.

        If cfg is provided, that dict is written; otherwise self.cfg is used.
        This keeps it compatible with older call sites that did
        save_config(self.cfg).
        """
        try:
            # Use caller-provided cfg or fallback to self.cfg
            if cfg is None:
                cfg = getattr(self, "cfg", None)
            if not isinstance(cfg, dict):
                return

            # 1) Update window props before saving
            try:
                cfg["window_geometry"] = self.geometry()
            except Exception:
                pass

            try:
                cfg["window_state"] = "zoomed" if self.state() == "zoomed" else "normal"
            except Exception:
                cfg["window_state"] = "normal"

            # 2) (Optional) update details width from the actual panel if you want
            try:
                if hasattr(self, "details_panel"):
                    cfg["details_width"] = int(self.details_panel.winfo_width())
            except Exception:
                pass

            # 3) Actually write config to disk
            with CONFIG_FILE.open("w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, sort_keys=True)

        except Exception:
            # don't crash UI if disk write fails
            pass


    # --- [UI|LIFECYCLE] _on_close ----------------------------------
    def _on_close(self):
        """Persist window + column layout (including details panel width), then close the app."""
        try:
            # 1) Snapshot geometry + state
            try:
                self.cfg["window_geometry"] = self.winfo_geometry()
            except Exception:
                pass

            try:
                st = self.state()
                self.cfg["window_state"] = "zoomed" if st == "zoomed" else "normal"
            except Exception:
                self.cfg["window_state"] = "normal"

            # 2) Snapshot column widths for each table
            col_cfg = self.cfg.setdefault("column_widths", {})

            def _capture(table_name: str, tv: ttk.Treeview | None):
                if tv is None:
                    return
                try:
                    widths: dict[str, int] = {}
                    for cid in tv["columns"]:
                        try:
                            widths[cid] = int(tv.column(cid, "width"))
                        except Exception:
                            continue
                    col_cfg[table_name] = widths
                except Exception:
                    pass

            _capture("active", getattr(self, "tree", None))
            _capture("agg", getattr(self, "agg", None))
            _capture("alerts", getattr(self, "alerts", None))

            # 3) Snapshot details panel width from the horizontal paned window
            try:
                paned = getattr(self, "main_paned", None)  # the outer PanedWindow with tables + details
                if paned is not None:
                    total = paned.winfo_width()
                    # sashpos(0) gives width of the LEFT pane (tables)
                    left_w = paned.sashpos(0)
                    details_width = max(0, total - left_w)
                    if details_width > 0:
                        self.cfg["details_width"] = int(details_width)
                        print("DEBUG details_width:", self.cfg["details_width"])
            except Exception:
                # don't let a layout issue break closing
                pass

            # 4) Save config to disk
            self.save_config(self.cfg)

        except Exception:
            # Never crash on close
            pass

        try:
            self.destroy()
        except Exception:
            import sys
            sys.exit(0)

    # --- [UI] _on_exit --------------------------------------
    def _on_exit(self):
        """Menu handler: delegate to _on_close()."""
        self._on_close()

    # --- [UI] Right-click context menu on tables -------------------------------
    def _on_right_click_active(self, event):
        """
        Context menu for the Active, Aggregates and Alerts tables.

        - For Active / Aggregates: allows editing hostname alias (IP) and MAC label.
        - For all tables: allows copying the row to clipboard.
        """
        widget = event.widget

        # Only handle treeviews
        if not isinstance(widget, ttk.Treeview):
            return

        # Identify row under mouse
        row_id = widget.identify_row(event.y)
        if not row_id:
            return

        # Select the row under the cursor so keyboard shortcuts etc. match
        try:
            widget.selection_set(row_id)
        except Exception:
            pass

        cols = list(widget["columns"])
        values = widget.item(row_id, "values") or ()
        row = {
            col: (values[idx] if idx < len(values) else "")
            for idx, col in enumerate(cols)
        }

        # Try to pull out something that looks like a local IP and MAC
        local_val = row.get("local") or row.get("local_ip") or ""
        mac_val = row.get("mac") or row.get("client_mac") or ""

        # Strip port / hostname decorations from local (e.g. "192.168.1.10:1234")
        ip_candidate = ""
        if isinstance(local_val, str) and local_val:
            # "ip[:port]" or "ip [host]:port"
            base = local_val.split()[0]          # drop hostname in brackets if present
            ip_candidate = base.split(":", 1)[0] # drop port

        menu = tk.Menu(self, tearoff=0)

        # Edit hostname alias for local IP (where it makes sense)
        if ip_candidate:
            menu.add_command(
                label=f"Edit hostname alias for {ip_candidate}",
                command=lambda ip=ip_candidate: self._edit_alias_for_ip(ip),
            )

        # Edit MAC label / device name
        if mac_val:
            menu.add_command(
                label=f"Edit device label for {mac_val}",
                command=lambda m=mac_val, ip=ip_candidate: self._edit_label_for_mac_from_row(m, ip),
            )

        # Copy entire row text
        if values:
            if menu.index("end") is not None:
                menu.add_separator()
            menu.add_command(
                label="Copy row",
                command=lambda txt="\t".join(str(v) for v in values): self._copy_to_clipboard(
                    txt,
                    "Row copied to clipboard",
                ),
            )

        if menu.index("end") is None:
            # Nothing useful to show
            return

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # --- [UI] _edit_label_for_mac_from_row -------------------------------
    def _edit_label_for_mac_from_row(self, mac: str, ip: str | None = None) -> None:
        """
        Helper for the context menu: open the MAC-label dialog and persist changes.
        """
        mac = (mac or "").strip()
        if not mac:
            return

        # Normalize once
        mac_norm = _normalize_mac(mac) or mac.upper()
        ip = (ip or "").strip()

        # Reuse the existing edit dialog
        result = self._open_edit_dialog(mac_norm, ip)
        if not result:
            return

        new_mac, label = result
        new_mac = _normalize_mac(new_mac) or mac_norm

        # Persist via existing helper
        self._set_label_for_mac(new_mac, label)

        # Small delayed refresh so the vendor/label column updates
        self.after(10, self._refresh_ui)

    # --- [UI] _on_toggle_show_idle --------------------------------------
    def _on_toggle_show_idle(self) -> None:
        """Persist the 'Show idle devices' toggle to config.json."""
        self.cfg["show_idle_devices"] = bool(self.show_idle_var.get())
        self.save_config()
        # Force a quick repaint so the table reflects the new filter
        self.after(10, self._refresh_ui)

    # --- [UI] _on_test_ssh --------------------------------------
    def _on_test_ssh(self):
        secrets = _load_ssh_secrets(SSH_SECRETS_FILE)
        host = UDM_SSH_HOST
        port = secrets.get("port", UDM_SSH_PORT)

        # lightweight probe using the same logic as your collector
        try:
            tester = ConntrackCollectorSSH(
                host=host, port=port,
                device_creds=secrets.get("device", {}),
                console_creds=secrets.get("console", {}),
                interval=1
            )
            # try device then console without starting the thread
            ok_dev = ok_con = False
            try:
                tester._try_connect("device")
                ok_dev = True
            except Exception as e:
                dev_err = str(e)
            finally:
                try:
                    if tester._ssh: tester._ssh.close()
                except Exception:
                    pass

            try:
                tester._try_connect("console")
                ok_con = True
            except Exception as e:
                con_err = str(e)
            finally:
                try:
                    if tester._ssh: tester._ssh.close()
                except Exception:
                    pass

            msg = []
            msg.append(f"Host: {host}:{port}")
            msg.append(f"Device:  {'OK' if ok_dev else f'FAIL ({dev_err})'}")
            msg.append(f"Console: {'OK' if ok_con else f'FAIL ({con_err})'}")
            messagebox.showinfo("SSH Test", "\n".join(msg))
        except Exception as e:
            messagebox.showerror("SSH Test", f"Unexpected error: {e}")

    # --- [UI] _toggle_rdns --------------------------------------
    def _toggle_rdns(self):
        # Flip the flag in memory
        new_val = not bool(self.cfg.get("resolve_rdns", True))
        self.cfg["resolve_rdns"] = new_val
    
        # Persist to config.json
        self.save_config()
    
        # Apply to global used by DNS worker
        global RESOLVE_RDNS
        RESOLVE_RDNS = new_val
    
        # Tell the user
        self._set_status(f"rDNS {'ON' if RESOLVE_RDNS else 'OFF'}")

    # --- [UI|REFRESH] _refresh_ui ----------------------------------------------
    # Purpose: Drain alerts; render tables; update status; queue rDNS
    def _refresh_ui(self):
        import queue

        # --- [UI|NET] _fmt_dest ----------------------------------------------
        # --- formatter for IP[:port] with cached rDNS if present
        def _fmt_dest(remote_ip: str, remote_port):
            try:
                with _dns_lock:
                    host = _dns_cache.get(remote_ip)
            except Exception:
                host = None
            return f"{remote_ip} [{host}]:{remote_port}" if host else f"{remote_ip}:{remote_port}"

        # --- [UI|HELPER] _tags_for_row(vendor_text ----------------------------------------------
        # --- helper: decide which tags to apply based on vendor / bytes / "newness"
        def _tags_for_row(vendor_text: str, bytes_val: int | float, *, is_new: bool = False) -> tuple[str, ...]:
            tags: list[str] = []

            v = (vendor_text or "").strip().lower()
            if not v or v == "unknown":
                tags.append("unknown_vendor")

            try:
                if int(bytes_val) >= 1_048_576:  # 1 MB threshold
                    tags.append("high_volume")
            except Exception:
                pass

            if is_new:
                tags.append("new_device")

            return tuple(tags)
        
        with self.core.data_lock:
    
            # ==============================================================
            # === REFRESH.ALERTS -drain queue, insert rows, optional toast==
            # ==============================================================

            try:
                while True:
                    alert = self.core.alert_q.get_nowait()
    
                    # compute a vendor/label for the local endpoint’s MAC/IP
                    local_hostport = alert.get("local", "")
                    local_ip = local_hostport.rsplit(":", 1)[0] if ":" in local_hostport else ""
                    vendor_disp = self._display_name(local_ip, alert.get("mac"))
    
                    # Destination: show "ip [hostname]:port" if hostname included on alert
                    remote_txt = alert.get("remote", "")
                    if alert.get("hostname"):
                        dest_text = f'{remote_txt} [{alert["hostname"]}]'
                    else:
                        dest_text = remote_txt
    
                    bytes_val = int(alert.get("bytes", 0) or 0)
                    vendor_text = vendor_disp or ""

                    # Heuristic: "new device" if the note starts with that phrase
                    is_new = str(alert.get("note", "")).lower().startswith("new device")

                    tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)

                    self.alerts.insert("", "end",
                        values=(
                            alert.get("time", ""),   # Time
                            alert.get("mac", ""),    # MAC
                            vendor_text,             # Vendor/Host
                            dest_text,               # Destination
                            local_hostport,          # Local
                            bytes_val,               # Bytes (TX)
                            alert.get("note", ""),   # Note
                        ),
                        tags=tags,
                    )
    
                    # Trim to last 500 alerts
                    if len(self.alerts.get_children()) > 500:
                        for iid in self.alerts.get_children()[:50]:
                            self.alerts.delete(iid)
    
                    # Optional Windows toast
                    if _TOASTER:
                        try:
                            _TOASTER.show_toast(
                                "Network Alert (>= 1 MB)",
                                f'{alert.get("local","")} → {alert.get("remote","")}\n'
                                f'{alert.get("vendor","")} {alert.get("mac","")}\n'
                                f'bytes={alert.get("bytes",0)}',
                                threaded=True,
                                duration=5
                            )
                        except Exception:
                            pass
            except queue.Empty:
                pass
    
            # After alerts table rebuilt:
            try:
                if hasattr(self, "alert_filter_var") and self.alert_filter_var.get():
                    _apply = getattr(self, "_apply_alert_filter", None)
                    if callable(_apply):
                        _apply()
            except Exception:
                pass

    
            # ==============================================================
            # === REFRESH.ACTIVE (middle) - CONNECTIONS ====================
            # ==============================================================
            # rebuild whole table each tick (simple & safe)

            self.tree.delete(*self.tree.get_children())
    
            for key, rec in sorted(self.core.conn_map.items(),
                                   key=lambda kv: kv[1]["last_seen"], reverse=True):
    
                # pre-filters (LAN, valid remote, state)
                if not _is_lan_client_ip(rec["local_ip"]):
                    continue
                if rec["remote_ip"] == "0.0.0.0":
                    continue
                if str(rec.get("state", "")).lower() in {"listen", "timewait", "closing"}:
                    continue
    
                # rDNS queuing
                remote_ip = rec["remote_ip"]
                remote_port = rec["remote_port"]
                if RESOLVE_RDNS and remote_ip not in ("0.0.0.0", "127.0.0.1"):
                    with _dns_lock:
                        cached = _dns_cache.get(remote_ip)
                        pending = remote_ip in _dns_pending
                    if cached is None and not pending:
                        with _dns_lock:
                            _dns_pending.add(remote_ip)
                        try:
                            self._dns_q.put_nowait(remote_ip)
                        except queue.Full:
                            pass
    
                dest_text = _fmt_dest(remote_ip, remote_port)
                local_hp = f'{rec["local_ip"]}:{rec["local_port"]}'
                vendor_disp = self._display_name(rec.get("local_ip"), rec.get("local_mac"))
    
                bytes_val = int(rec.get("bytes_tx") or 0)
                vendor_text = vendor_disp or ""

                # "New" flow heuristic: first_seen == last_seen (i.e. just created this session)
                is_new = rec.get("first_seen") == rec.get("last_seen")

                tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)

                row_vals = [
                    rec.get("first_seen", ""),               # First Seen
                    rec.get("local_mac", ""),                # MAC
                    vendor_text,                             # Vendor/Host
                    dest_text,                               # Destination
                    local_hp,                                # Local
                    rec.get("last_seen", ""),                # Last Seen
                    bytes_val,                               # Bytes (TX)
                    "Yes" if rec.get("over_1mb") else "No",  # >1MB?
                ]
                if DEBUG:
                    row_vals.append(str(rec.get("state", "")).lower())

                self.tree.insert("", "end", values=tuple(row_vals), tags=tags)
    
            # ==============================================================
            # === REFRESH.AGGREGATES (bottom) - PER-DEVICE TOTALS ==========
            # ==============================================================

            self.agg.delete(*self.agg.get_children())
    
            # 1) MACs discovered via ARP (devices present on LAN)
            macs_from_arp = {m for m in self.core.ip2mac.values() if m and m != "00:00:00:00:00:00"}
    
            # 2) MACs that we’ve accumulated traffic for
            macs_from_aggs = set(self.core.aggregates.keys())
    
            # 3) Union = all devices we know about
            all_macs = macs_from_arp | macs_from_aggs
    
            for mac in sorted(all_macs):
                vendor = self._display_name(local_ip=None, mac=mac)
                dests = self.core.aggregates.get(mac, {})
    
                if not dests:
                    # skip empty placeholders entirely
                    continue
    
                for (rip, rport), stats in sorted(dests.items(),
                                                  key=lambda kv: (-int(kv[1].get("bytes", 0)), kv[0])):
                    # queue rDNS for aggregates as well
                    if RESOLVE_RDNS and rip not in ("0.0.0.0", "127.0.0.1"):
                        with _dns_lock:
                            cached = _dns_cache.get(rip)
                            pending = rip in _dns_pending
                        if cached is None and not pending:
                            with _dns_lock:
                                _dns_pending.add(rip)
                            try:
                                self._dns_q.put_nowait(rip)
                            except queue.Full:
                                pass
    
                    # same destination formatter: IP [host]:port if cached
                    try:
                        with _dns_lock:
                            host = _dns_cache.get(rip)
                    except Exception:
                        host = None
                    agg_dest = f"{rip} [{host}]:{rport}" if host else f"{rip}:{rport}"
    
                    sightings = int(stats.get("sightings") or 0)
                    bytes_val = int(stats.get("bytes") or 0)
                    vendor_text = vendor or ""

                    # Heuristic: a "new" device if we’ve only seen it a couple of times
                    is_new = sightings <= 2

                    tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)

                    self.agg.insert("", "end",
                        values=(
                            sightings,     # Sightings
                            mac,           # MAC
                            vendor_text,   # Vendor/Host
                            agg_dest,      # Destination
                            bytes_val,     # Total Bytes
                        ),
                        tags=tags,
                    )
              
                    # Re-apply any remembered sort on all tables
        try:
            self._reapply_sort_if_any("alerts", self.alerts)
            self._reapply_sort_if_any("active", self.tree)
            self._reapply_sort_if_any("agg", self.agg)
        except Exception:
            pass
        
            # ---------------- status line (top-right) + ssh status echo -------------
            nf_status = "OFF"
            if self.nf:
                if isinstance(self.nf, ConntrackCollectorSSH):
                    nf_status = f"Conntrack over SSH: {self.nf.status_msg or '…'}"
                else:
                    bind_err = getattr(self.nf, "bind_error", None)
                    nf_status = (f"NetFlow v5 {NETFLOW_LISTEN_IP}:{NETFLOW_LISTEN_PORT}"
                                 if not bind_err else f"NetFlow ERROR: {bind_err}")
    
            if isinstance(self.nf, ConntrackCollectorSSH):
                ssh_status = self.nf.status_msg or "…"
                if ssh_status != getattr(self, "_last_ssh_status", None):
                    print(f"[SSH] {ssh_status}")
                    self._last_ssh_status = ssh_status
    
            snmp_label = get_snmp_backend_name()
            counts = getattr(self.core, "last_counts", {"arp": 0, "tcp": 0, "flows": 0})

        # --- Status bar metrics -----------------------------------
        try:
            # 1) Active connections + unique MACs
            active_rows = getattr(self.core, "get_active_rows_prepared", None)
            if callable(active_rows):
                rows = active_rows(limit=COPY_LIMIT_ROWS)
            else:
                rows = list(getattr(self.core, "conn_map", {}).values())

            active_count = len(rows)
            macs = {normalize_mac(r.get("local_mac") or r.get("mac") or "") for r in rows}
            macs.discard("")  # remove empties
            unique_macs = len(macs)

            if hasattr(self, "status_conn"):
                self.status_conn.set(f"Active: {active_count} | MACs: {unique_macs}")

            # 2) Flow collector state
            flow_label = "Flow: off"
            core = getattr(self, "core", None)
            if core is not None:
                try:
                    last_counts = getattr(core, "last_counts", {}) or {}
                    flows = int(last_counts.get("flows", 0))
                    if getattr(core, "nf", None) is not None and ENABLE_NETFLOW_V5_COLLECTOR:
                        flow_label = f"Flow: on ({flows} flows)"
                except Exception:
                    pass

            if hasattr(self, "status_flow"):
                self.status_flow.set(flow_label)

            # 3) SSH collector state
            ssh_label = "SSH: off"
            try:
                if ENABLE_CONNTRACK_SSH:
                    # if you have a conntrack object with a status, use it here
                    ssh_label = "SSH: on"
            except Exception:
                pass

            if hasattr(self, "status_ssh"):
                self.status_ssh.set(ssh_label)

            # 4) Clock / timestamp warning (simple initial version)
            clock_label = "Clock: ok"
            try:
                # rough heuristic: last alert/last_seen older than N seconds?
                # you can refine this later with real router vs local time diff.
                now = time.time()
                # If you have rows with 'last_seen' as epoch seconds:
                lag = None
                for r in rows:
                    ts = r.get("last_seen") or r.get("first_seen")
                    if isinstance(ts, (int, float)):
                        dt = now - ts
                        if dt >= 0:
                            lag = dt if lag is None else min(lag, dt)
                if lag is not None and lag > 120:
                    clock_label = f"Clock: {int(lag)}s behind?"
            except Exception:
                pass

            if hasattr(self, "status_clock"):
                self.status_clock.set(clock_label)

        except Exception:
            # don't let status bar updates kill the UI
            pass

        # finally, reschedule next refresh
        if getattr(self, "_ui_ready", False):
            try:
                self.after(1000, self._refresh_ui)
            except Exception:
                pass

    # --- [UI|DETAILS] _restore_details_width -----------------------------------
    def _restore_details_width(self) -> None:
        """
        Restore the horizontal sash position so the right-hand details panel
        uses the width from config (self.cfg['details_width']).

        Called after the UI is built and geometry is known.
        """
        try:
            paned = getattr(self, "main_paned", None)
            if paned is None:
                return

            # If the paned hasn't been laid out yet, try again shortly.
            total = paned.winfo_width()
            if total <= 1:
                self.after(50, self._restore_details_width)
                return

            cfg = getattr(self, "cfg", {}) or {}
            try:
                details_width = int(cfg.get("details_width", 380))
            except Exception:
                details_width = 380

            # Clamp details width so it can't consume everything or vanish
            min_details = 260
            max_details = max(min_details, total - 400)
            details_width = max(min_details, min(details_width, max_details))

            # sash position (index 0) is the width of the left pane
            sashpos = total - details_width
            if sashpos < 300:
                sashpos = 300  # leave enough room for the tables

            try:
                paned.sashpos(0, sashpos)
            except Exception:
                pass
        except Exception:
            # Never let UI restoration crash
            pass

    # --- [UI|CONFIG] _toggle_conntrack_ssh ------------------------------------
    def _toggle_conntrack_ssh(self) -> None:
        """Toggle the 'enable_conntrack_ssh' setting and persist to config."""
        global ENABLE_CONNTRACK_SSH

        current = bool(self.cfg.get("enable_conntrack_ssh", ENABLE_CONNTRACK_SSH))
        new_val = not current
        self.cfg["enable_conntrack_ssh"] = new_val
        self.save_config()

        ENABLE_CONNTRACK_SSH = new_val

        self._set_status(
            f"Conntrack SSH collector {'ENABLED' if new_val else 'DISABLED'} "
            "(may require restart to fully take effect)"
        )

    # --- [UI|CONFIG] _toggle_netflow_v5 ------------------------------------
    def _toggle_netflow_v5(self) -> None:
        """Toggle the 'enable_netflow_v5_collector' setting and persist to config."""
        global ENABLE_NETFLOW_V5_COLLECTOR

        current = bool(self.cfg.get("enable_netflow_v5_collector", ENABLE_NETFLOW_V5_COLLECTOR))
        new_val = not current
        self.cfg["enable_netflow_v5_collector"] = new_val
        self.save_config()

        ENABLE_NETFLOW_V5_COLLECTOR = new_val

        self._set_status(
            f"NetFlow v5 collector {'ENABLED' if new_val else 'DISABLED'} "
            "(may require restart to fully take effect)"
        )

# endregion UI CONTROLLER  

    # --- [UI|HOST] _friendly_host_for_local ---------------------------------
    # Purpose: Return a friendly hostname (alias or rdns) for a "A.B.C.D:port"
    @staticmethod
    def _friendly_host_for_local(local_hostport: str) -> str:
        ip = _HOSTNAMES._ip_from_hostport(local_hostport)
        return _HOSTNAMES.name_for_ip(ip) if ip else ""

    # --- [UI|ALIASES] _on_set_hostname_alias --------------------------------
    # Purpose: Prompt for a friendly name for the selected Active row's local IP
    # --- [UI|ALIASES] _on_set_hostname_alias ------------------------------
    # Purpose: Prompt for a friendly name for the selected Active row's local IP
    
    # --- [UI|COPY] _copy_alerts ------------------------------------
    def _copy_alerts(self):
        rows = []
        header = ["Time","Local","MAC","Vendor","Remote","Hostname","Bytes","Note"]
        rows.append("\t".join(header))
        items = list(self.alerts.get_children())[:COPY_LIMIT_ROWS]
        for iid in items:
            vals = self.alerts.item(iid)["values"]
            rows.append("\t".join(str(v) for v in vals))
        blob = "=== Alerts (top {}) ===\n".format(COPY_LIMIT_ROWS) + "\n".join(rows)
        self._copy_to_clipboard(blob, f"Copied {len(items)} alert rows to clipboard")

    # --- [UI|EXPORT] _export_snapshot ------------------------------------
    def _export_snapshot(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"snapshot_{ts}.csv"
        try:
            with open(fname, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["local","mac","vendor","remote","state","first","last","bytes_tx","over_1mb"])
                for iid in self.tree.get_children():
                    w.writerow(self.tree.item(iid)["values"])
            self.status.set(f"Snapshot exported → {fname}")
        except Exception as e:
            self.status.set(f"Export failed: {e}")
 
    # --- [UI|CLIP] _copy_to_clipboard ------------------------------------
    def _copy_to_clipboard(self, text: str, ok_msg: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()  # ensures clipboard gets the data
            self.status.set(ok_msg)
        except Exception as e:
            self.status.set(f"Copy failed: {e}")

    # --- [UI|COPY] Copy visible Active table -------------------------------------
    def _copy_active(self):
        # Pull visible items from the Treeview if present; else from core
        header = ["Local", "MAC", "Vendor", "Remote", "State", "First Seen", "Last Seen", "Bytes (TX)", ">1MB?"]
        rows = ["\t".join(header)]

        def _fmt_local(rec):
            lip = rec.get("local_ip") or rec.get("src_ip") or ""
            lpt = rec.get("local_port") or rec.get("src_port")
            return f"{lip}:{lpt}" if lip and lpt is not None else str(lip)

        def _fmt_remote(rec):
            rip = rec.get("remote_ip") or rec.get("dst_ip") or ""
            rpt = rec.get("remote_port") or rec.get("dst_port")
            host = rec.get("remote_host") or rec.get("rdns") or rec.get("hostname")
            host_part = f" [{host}]" if host else ""
            base = f"{rip}{host_part}"
            return f"{base}:{rpt}" if rip and rpt is not None else base

        def _fmt_bytes(n):
            try:
                return str(int(n))
            except Exception:
                return str(n or 0)

        items = []
        try:
            # Preferred: copy what the user sees (Tree rows)
            items = list(self.tree.get_children())[:COPY_LIMIT_ROWS]
            for iid in items:
                vals = self.tree.item(iid)["values"]
                rows.append("\t".join(str(v) for v in vals))
        except Exception:
            # Fallback: pull from core directly
            recs = self.core.get_active_rows_prepared(limit=COPY_LIMIT_ROWS)
            for rec in recs:
                local = _fmt_local(rec)
                mac = rec.get("local_mac") or ""
                vendor = rec.get("vendor") or "Unknown"
                remote = _fmt_remote(rec)
                state = rec.get("state") or rec.get("tcp_state") or ""
                first_seen = rec.get("first_seen") or ""
                last_seen = rec.get("last_seen") or ""
                raw_bytes = rec.get("bytes") or rec.get("bytes_tx") or 0
                btx = _fmt_bytes(raw_bytes)
                over = "Yes" if isinstance(raw_bytes, (int, float)) and raw_bytes >= 1_048_576 else "No"
                rows.append("\t".join([local, mac, vendor, remote, state, str(first_seen), str(last_seen), btx, over]))

        blob = "=== Active Connections (top {}) ===\n".format(COPY_LIMIT_ROWS) + "\n".join(rows)
        self._copy_to_clipboard(blob, f"Copied {len(items) if items else min(len(rows)-1, COPY_LIMIT_ROWS)} active rows to clipboard")

    # --- [UI|COPY] _copy_aggregates ------------------------------------
    def _copy_aggregates(self):
        # Copy the visible Aggregates table (first COPY_LIMIT_ROWS rows)
        rows = []
        header = ["MAC", "Vendor", "Dest (IP:Port)", "Sightings", "Bytes"]
        rows.append("\t".join(header))
        items = list(self.agg.get_children())[:COPY_LIMIT_ROWS]
        for iid in items:
            vals = self.agg.item(iid)["values"]
            rows.append("\t".join(str(v) for v in vals))
        blob = "=== Aggregates (top {}) ===\n".format(COPY_LIMIT_ROWS) + "\n".join(rows)
        self._copy_to_clipboard(blob, f"Copied {len(items)} aggregate rows to clipboard")

    # --- [UI|COPY|DEBUG] _copy_debug_bundle ------------------------------------
    def _copy_debug_bundle(self):
        # Build a single text payload with:
        # - Active (top N)
        # - Aggregates (top N)
        # - env info (versions & config)
        # - Top NetFlow flows (if collector is running)
        # - Tail of traffic_log.csv

        parts = []

        # 1) Env block
        try:
            import platform, sys as _sys
            try:
                from importlib import metadata as _md
            except Exception:
                _md = None
            puresnmp_ver = "unknown"
            if _md:
                try:
                    puresnmp_ver = _md.version("puresnmp")
                except Exception:
                    pass
            env = [
                "=== Environment ===",
                f"Python: {platform.python_version()} ({platform.system()} {platform.release()})",
                f"puresnmp: {puresnmp_ver}",
                f"SNMP backend: {get_snmp_backend_name()}",
                f"Router IP: {ROUTER_IP}",
                f"Community: {SNMP_COMMUNITY}",
                f"Poll Interval (s): {POLL_INTERVAL_SECONDS}",
                f"NetFlow v5 collector: {'ON' if getattr(self, 'nf', None) else 'OFF'} on {NETFLOW_LISTEN_IP}:{NETFLOW_LISTEN_PORT}",
                "",
            ]
            parts.append("\n".join(env))
        except Exception:
            pass

        # 2) Active table via core (normalized)
        header = ["Local", "MAC", "Vendor", "Remote", "State", "First Seen", "Last Seen", "Bytes (TX)", ">1MB?"]
        rows = ["\t".join(header)]

        def _fmt_local(rec):
            lip = rec.get("local_ip") or rec.get("src_ip") or ""
            lpt = rec.get("local_port") or rec.get("src_port")
            return f"{lip}:{lpt}" if lip and lpt is not None else str(lip)

        def _fmt_remote(rec):
            rip = rec.get("remote_ip") or rec.get("dst_ip") or ""
            rpt = rec.get("remote_port") or rec.get("dst_port")
            host = rec.get("remote_host") or rec.get("rdns") or rec.get("hostname")
            host_part = f" [{host}]" if host else ""
            base = f"{rip}{host_part}"
            return f"{base}:{rpt}" if rip and rpt is not None else base

        def _fmt_bytes(n):
            try:
                return str(int(n))
            except Exception:
                return str(n or 0)

        recs = self.core.get_active_rows_prepared(limit=COPY_LIMIT_ROWS)
        for rec in recs:
            local = _fmt_local(rec)
            mac = rec.get("local_mac") or ""
            vendor = rec.get("vendor") or "Unknown"
            remote = _fmt_remote(rec)
            state = rec.get("state") or rec.get("tcp_state") or ""
            first_seen = rec.get("first_seen") or ""
            last_seen = rec.get("last_seen") or ""
            raw_bytes = rec.get("bytes") or rec.get("bytes_tx") or 0
            btx = _fmt_bytes(raw_bytes)
            over = "Yes" if isinstance(raw_bytes, (int, float)) and raw_bytes >= 1_048_576 else "No"
            rows.append("\t".join([local, mac, vendor, remote, state, str(first_seen), str(last_seen), btx, over]))

        parts.append("=== Active Connections (top {}) ===\n".format(COPY_LIMIT_ROWS) + "\n".join(rows) + "\n")

        # (Optional) add more parts here (aggregates, tail of logs, etc.)

        self._copy_to_clipboard("\n".join(parts), "Debug bundle copied")

    # --- [UI|DEVICE NAME] _display_name ------------------------------------
    def _display_name(self, local_ip: str | None, mac: str | None) -> str:
        """Human-friendly name for a device, used in Vendor/Host columns.
    
        Priority:
          1) Hostname alias for the IP (host_aliases.json)
          2) Custom device label for the MAC
          3) Vendor name for the MAC
          4) "Unknown"
        """
        # 1) IP alias (from host_aliases.json via _HOSTNAMES)
        try:
            # prefer alias/rDNS for the LAN device (local_ip)
            if local_ip:
                host = _HOSTNAMES.name_for_ip(local_ip)
                if host:
                    return host
        except Exception:
            pass
    
        # 2) Custom MAC label
        try:
            if mac and hasattr(self, "_get_current_label_for_mac"):
                lbl = self._get_current_label_for_mac(mac)
                if lbl:
                    return lbl
        except Exception:
            pass
    
        # 3) Fallback: vendor
        try:
            return vendor_for_mac(mac) if mac else "Unknown"
        except Exception:
            return "Unknown"

    # --- [UI|DEBUG] _dump_neighbors_csv ------------------------------------
    def _dump_neighbors_csv(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"neighbors_{ts}.csv"
        try:
            rows = []
            # SNMP view
            rows.append(["SOURCE","IP","MAC"])
            for ip, mac in sorted(self.core.ip2mac.items()):
                rows.append(["SNMP", ip, mac])
            # SSH view (live snapshot)
            if isinstance(self.nf, ConntrackCollectorSSH):
                for ip, mac in self.nf.get_ip_neigh_snapshot():
                    rows.append(["SSH", ip, mac])
            with open(fname, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            self.status.set(f"Neighbors dumped → {fname}")
        except Exception as e:
            self.status.set(f"Dump failed: {e}")

    def _on_set_hostname_alias(self):
        # Find a selected row in the Active Connections table (LAN device lives in 'local')
        item = self.tree.selection()
        if not item:
            self.status.set("Select a row in Active Connections first.")
            return

        vals = self.tree.item(item[0], "values") or ()
        if not vals:
            self.status.set("Row has no data.")
            return
    
        # Column 0 is the Local display: "name (ip):port" or "ip:port"
        local_disp = vals[0]
        ip = _HOSTNAMES._ip_from_hostport(local_disp)
        if not ip:
            self.status.set("Could not parse IP from selected row.")
            return

        current = _HOSTNAMES.name_for_ip(ip)

        import tkinter.simpledialog as sd
        # Keep dialog above, and correctly parent it
        new_name = sd.askstring(
            "Set Hostname Alias",
            f"IP: {ip}\n\nEnter a friendly name (leave blank to clear):",
            initialvalue=current or "",
            parent=self
        )
        if new_name is None:
            return  # user cancelled

        _HOSTNAMES.set_alias(ip, new_name)
        self.status.set(f"Hostname alias {'updated' if (new_name or '').strip() else 'cleared'} for {ip}.")
        # Light refresh so the Local column reflects the new alias; do not force sort
        self.after(10, self._refresh_ui)

    # --- [SSH|RESTART] _restart_ssh_collector ------------------------------
    def _restart_ssh_collector(self):
        """Stop and re-create the SSH conntrack collector with updated secrets."""
        try:
            if self.nf and hasattr(self.nf, "stop") and callable(self.nf.stop):
                try:
                    self.nf.stop.set() if hasattr(self.nf, "stop") else None
                except Exception:
                    pass
                try:
                    self.nf.join(timeout=1.5)
                except Exception:
                    pass
        except Exception:
            pass

        secrets = _load_ssh_secrets(SSH_SECRETS_FILE)
        ssh_port = secrets.get("port", 22)

        if ENABLE_CONNTRACK_SSH and paramiko is not None:
            try:
                self.nf = ConntrackCollectorSSH(
                    host=UDM_SSH_HOST,
                    port=ssh_port,
                    device_creds=secrets.get("device", {}),
                    console_creds=secrets.get("console", {}),
                    interval=CONNTRACK_POLL_SECS
                )
                self.nf.start()
                self._set_status("SSH collector restarted")
            except Exception as e:
                self._set_status(f"Failed to restart SSH collector: {e}")
        else:
            self._set_status("SSH collector disabled or Paramiko unavailable")

    # --- [SSH|UI] _on_edit_ssh_credentials ---------------------------------
    def _on_edit_ssh_credentials(self):
        import tkinter as tk
        import tkinter.ttk as ttk
        import tkinter.filedialog as fd
        import tkinter.messagebox as mb

        secrets = _load_ssh_secrets(SSH_SECRETS_FILE)
        dev = secrets.get("device", {}) or {}
        con = secrets.get("console", {}) or {}
        port = secrets.get("port", 22)

        if not (con.get("user") or "").strip():
            con["user"] = "root"

        dlg = tk.Toplevel(self)
        dlg.title("Edit SSH Credentials")
        dlg.transient(self)
        dlg.grab_set()

        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill="both", expand=True)

        # Device credentials (fully editable)
        dev_lab = ttk.Label(frm, text="Device account (SSH)")
        dev_lab.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0,4))

        ttk.Label(frm, text="Username").grid(row=1, column=0, sticky="e")
        dev_user = ttk.Entry(frm, width=28)
        dev_user.insert(0, dev.get("user",""))
        dev_user.grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="Password").grid(row=2, column=0, sticky="e")
        dev_pass = ttk.Entry(frm, width=28, show="•")
        dev_pass.insert(0, dev.get("password",""))
        dev_pass.grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Key file").grid(row=3, column=0, sticky="e")
        dev_key = ttk.Entry(frm, width=28)
        dev_key.insert(0, dev.get("keyfile",""))
        dev_key.grid(row=3, column=1, sticky="w")
        def pick_dev_key():
            p = fd.askopenfilename(title="Select private key file")
            if p: 
                dev_key.delete(0, "end"); dev_key.insert(0, p)
        ttk.Button(frm, text="Browse…", command=pick_dev_key).grid(row=3, column=2, sticky="w")

        ttk.Label(frm, text="Key passphrase").grid(row=4, column=0, sticky="e")
        dev_keypass = ttk.Entry(frm, width=28, show="•")
        dev_keypass.insert(0, dev.get("key_passphrase",""))
        dev_keypass.grid(row=4, column=1, sticky="w")

        # Console credentials
        sep = ttk.Separator(frm); sep.grid(row=5, column=0, columnspan=4, sticky="ew", pady=8)

        con_lab = ttk.Label(frm, text="Console account (root; password only)")
        con_lab.grid(row=6, column=0, columnspan=4, sticky="w", pady=(0,4))

        ttk.Label(frm, text="Username").grid(row=7, column=0, sticky="e")
        con_user = ttk.Entry(frm, width=28)
        con_user.insert(0, "root")
        con_user.config(state="disabled")
        con_user.grid(row=7, column=1, sticky="w")

        ttk.Label(frm, text="Password").grid(row=8, column=0, sticky="e")
        con_pass = ttk.Entry(frm, width=28, show="•")
        con_pass.insert(0, con.get("password",""))
        con_pass.grid(row=8, column=1, sticky="w")

        # Port
        sep2 = ttk.Separator(frm); sep2.grid(row=9, column=0, columnspan=4, sticky="ew", pady=8)

        ttk.Label(frm, text="SSH Port").grid(row=10, column=0, sticky="e")
        port_var = tk.StringVar(value=str(port or 22))
        port_entry = ttk.Entry(frm, width=10, textvariable=port_var)
        port_entry.grid(row=10, column=1, sticky="w")

        # Buttons
        btns = ttk.Frame(frm); btns.grid(row=20, column=0, columnspan=4, sticky="e", pady=(12,0))
        def on_save():
            try:
                p = int(port_var.get().strip() or "22")
            except Exception:
                mb.showerror("Invalid port", "Port must be an integer.")
                return

            new_data = {
                "device": {
                    "user": dev_user.get().strip(),
                    "password": dev_pass.get(),
                    "keyfile": dev_key.get().strip(),
                    "key_passphrase": dev_keypass.get(),
                },
                "console": {
                    "user": "root",
                    "password": con_pass.get(),
                    "keyfile": (con.get("keyfile") or ""),
                    "key_passphrase": (con.get("key_passphrase") or ""),
                },
                "port": p,
            }
            if not new_data["device"]["user"] and not new_data["console"]["password"] and not new_data["device"]["password"]:
                if not mb.askyesno("Save empty credentials?", "You left all passwords blank. Save anyway?"):
                    return

            ok = _save_ssh_secrets(SSH_SECRETS_FILE, new_data)
            if ok:
                self._restart_ssh_collector()
                dlg.destroy()
                mb.showinfo("Saved", "SSH credentials saved.")
            else:
                mb.showerror("Error", "Failed to save SSH credentials.")

        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right", padx=(4,0))
        ttk.Button(btns, text="Save", command=on_save).pack(side="right")
        dlg.wait_window(dlg)

    # --- [UI|DNS] _on_clear_hostname_cache ------------------------------------
    def _on_clear_hostname_cache(self):
        _HOSTNAMES.clear_cache()
        self.status.set("Hostname cache cleared.")

    # --- [UI|DNS] _on_refresh_rdns_selected ------------------------------------
    def _on_refresh_rdns_selected(self):
        """Force a reverse-DNS lookup for the selected row's remote IP (Active Connections)."""
        import queue as _q
        sel = self.tree.selection()
        if not sel:
            self.status.set("Select a row in Active Connections first.")
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            self.status.set("Row has no data.")
            return
        # remote is like "8.8.8.8[:port]" or "8.8.8.8 [dns.google]:443"
        remote = vals[3]
        # extract the plain IP before any ' [' or ':'
        ip = remote.split(" [", 1)[0].split(":", 1)[0].strip()
        if not ip:
            self.status.set("Could not parse remote IP.")
            return

        # if already cached, drop it to re-resolve
        with _dns_lock:
            _dns_cache.pop(ip, None)
            _dns_pending.discard(ip)
        try:
            self._dns_q.put_nowait(ip)
            self.status.set(f"Queued rDNS for {ip}")
        except _q.Full:
            self.status.set("DNS queue full; try again in a moment.")

    # --- [UI|LIFECYCLE] _quit ------------------------------------
    def _quit(self):
        if self.nf:
            self.nf.stop.set()
        self.core.stop.set()
        try:
            if self.nf:
                self.nf.join(timeout=2.0)
        except Exception:
            pass
        try:
            if hasattr(self, "thread"):
                self.thread.join(timeout=2.0)
        except Exception:
            pass
        try:
            # stop DNS worker
            self._dns_q.put_nowait(None)
            if hasattr(self, "_dns_thread"):
                self._dns_thread.join(timeout=1.0)
        except Exception:
            pass
        self.destroy()

    # --- [UI|Tkinter] _show_device_details ------------------------------------
    def _show_device_details(self, row):
        """
        Display a details window for a selected device or connection.
        """
        win = tk.Toplevel(self)
        win.title(f"Device Details – {row.get('local_ip','')}")
        win.geometry("420x400")
        win.resizable(False, False)

        # Title
        tk.Label(win, text=row.get("display_name", row["local_ip"]),
                font=("Segoe UI", 14, "bold")).pack(pady=10)

        # Key fields in a grid
        fields = [
            ("IP Address", row.get("local_ip")),
            ("MAC Address", row.get("local_mac")),
            ("Vendor", row.get("vendor")),
            ("Hostname", row.get("hostname")),
            ("Bytes TX", row.get("bytes_tx")),
            ("Destination", row.get("remote")),
            ("First Seen", row.get("first_seen")),
            ("Last Seen", row.get("last_seen")),
        ]

        frame = ttk.Frame(win)
        frame.pack(fill="x", padx=15)

        for label, val in fields:
            ttk.Label(frame, text=f"{label}:").pack(anchor="w")
            ttk.Label(frame, text=str(val)).pack(anchor="w")

        # Editable friendly name
        name_var = tk.StringVar(value=self._get_current_label_for_mac(row["local_mac"]))
        ttk.Label(win, text="Friendly Name:").pack(anchor="w", padx=15, pady=(10,0))
        entry = ttk.Entry(win, textvariable=name_var, width=40)
        entry.pack(padx=15)

        def save_name():
            self._set_label_for_mac(row["local_mac"], name_var.get())
            self._refresh_ui()

        ttk.Button(win, text="Save Name", command=save_name).pack(pady=10)

        # Actions
        actions = ttk.Frame(win)
        actions.pack(pady=10)
        ttk.Button(actions, text="Ping", command=lambda: os.system(f"ping {row['local_ip']} -n 4")).grid(row=0, column=0, padx=5)
        ttk.Button(actions, text="WHOIS", command=lambda: webbrowser.open(f"https://whois.domaintools.com/{row['remote']}")).grid(row=0, column=1, padx=5)

# endregion UI LAYER

# -------------------- Offline MAC → Vendor resolver (enhanced) --------------------

# --- [] _candidate_vendor_files --------------------------------------        
def _candidate_vendor_files() -> list[Path]:
    here = BASE_DIR
    return [
        here / "mac-vendor.txt",
        here / "data" / "mac-vendor-overrides.txt",
        Path.home() / ".cache" / "mac-vendor.txt",
    ]

# --- [OUI] _normalize_oui_text -------------------------------------- 
def _normalize_oui_text(s: str) -> str:
    s = s.strip().upper()
    hexonly = re.sub(r"[^0-9A-F]", "", s)
    if len(hexonly) < 6:
        return ""
    hexonly = hexonly[:6]
    return ":".join([hexonly[i:i+2] for i in range(0, 6, 2)])

# --- [] _parse_vendor_lines --------------------------------------
def _parse_vendor_lines(lines: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        parts = _SPLIT_RE.split(line, maxsplit=1)
        if not parts:
            continue
        oui = _normalize_oui_text(parts[0])
        vendor = (parts[1].strip() if len(parts) > 1 else "").strip()
        if not oui and len(parts) > 1:
            oui = _normalize_oui_text(parts[1])
            vendor = parts[0].strip()
        if oui and vendor:
            out.setdefault(oui, vendor)
    return out

# --- [] _is_locally_admin --------------------------------------
def _is_locally_admin(mac: str) -> bool:
    """
    True if the MAC is locally administered (randomized) — i.e., U/L bit set.
    """
    mac_norm = _normalize_mac(mac)
    if len(mac_norm) != 17:
        return False
    first_octet_hex = mac_norm[:2]
    try:
        first_octet = int(first_octet_hex, 16)
        return bool(first_octet & 0x02)
    except ValueError:
        return False

class _VendorResolver:
    
    # --- [INIT] __init__ --------------------------------------
    def __init__(self, files: Iterable[Path] = ()):
        self._map: Dict[str, str] = {}
        self._alias: Dict[str, str] = {}      # full MAC (17 chars) or OUI → vendor
        self._miss_cache: set[str] = set()
        self._unknown_ouis: Dict[str, int] = {}
        self._loaded_from: list[Path] = []
        self.reload(files)

    # --- [] reload --------------------------------------
    def reload(self, files: Iterable[Path] = ()):
        self._map.clear()
        self._alias.clear()
        self._miss_cache.clear()
        self._unknown_ouis.clear()
        self._loaded_from = []
        candidates = list(files) if files else _candidate_vendor_files()
        for p in candidates:
            try:
                if p.exists():
                    with p.open("r", encoding="utf-8", errors="replace") as f:
                        m = _parse_vendor_lines(f)
                    if m:
                        self._map.update(m)
                        self._loaded_from.append(p)
            except Exception:
                pass

    # --- [] add_vendor_alias --------------------------------------
    def add_vendor_alias(self, key: str, vendor: str):
        """
        key can be a full MAC ('AA:BB:CC:DD:EE:FF') or OUI ('AA:BB:CC').
        """
        mac_full = _normalize_mac(key)
        if len(mac_full) == 17:
            self._alias[mac_full] = vendor
            return
        oui = _normalize_oui_text(key)
        if oui:
            self._alias[oui] = vendor

    # --- [] export_unknowns --------------------------------------
    def export_unknowns(self, path: Optional[Path] = None):
        """
        Write the most frequent unknown OUIs to a file for curation.
        """
        if not path:
            path = BASE_DIR / "unknown_ouis.txt"
        try:
            lines = [f"{k},{self._unknown_ouis[k]}" for k in sorted(self._unknown_ouis)]
            path.write_text("\n".join(lines), encoding="utf-8")
        except Exception:
            pass

    # --- [] export_unknowns_text --------------------------------------
    def export_unknowns_text(self) -> str:
        if not getattr(self, "_unknown_ouis", None):
            return ""
        lines = ["# OUI,count"]
        lines += [f"{oui},{cnt}" for oui, cnt in sorted(self._unknown_ouis.items(),
                                                        key=lambda kv: kv[1], reverse=True)]
        return "\n".join(lines)

    # --- [] export_unknown_macs_text --------------------------------------
    def export_unknown_macs_text(self) -> str:
        # optional: if you also track full unknown MACs
        s = getattr(self, "_unknown_macs", None)
        if not s:
            return ""
        return "\n".join(sorted(s))

    # --- [] export_unknowns_to_clipboard --------------------------------------
    def export_unknowns_to_clipboard(self, copier=None) -> bool:
        """
        Copies the OUI,count list to clipboard.
        If `copier` is provided (e.g. your existing copy_to_clipboard(str)), it will be used.
        Falls back to Tk clipboard if not provided.
        """
        text = self.export_unknowns_text()
        if not text:
            print("[VENDOR] No unknown OUIs to export.")
            return False

        if copier:
            copier(text)
            print("[VENDOR] Unknown OUIs copied to clipboard via provided copier.")
            return True

        # Fallback: Tkinter clipboard
        try:
            import tkinter as tk
            r = tk.Tk(); r.withdraw()
            r.clipboard_clear(); r.clipboard_append(text)
            r.update(); r.destroy()
            print("[VENDOR] Unknown OUIs copied to clipboard.")
            return True
        except Exception as e:
            print(f"[VENDOR] Clipboard export failed: {e}")
            return False

    # --- [] _is_locally_admin_from_full --------------------------------------
    @staticmethod
    def _is_locally_admin_from_full(mac_full: str) -> bool:
        """Assumes 'AA:BB:CC:DD:EE:FF'. Checks the U/L (locally-admin) bit."""
        if not mac_full or len(mac_full) < 2:
            return False
        try:
            first_byte = int(mac_full.split(":")[0], 16)
            return (first_byte & 0b10) != 0
        except Exception:
            return False

    # --- [] vendor_for_mac --------------------------------------
    def vendor_for_mac(self, mac: str | None) -> str:
        """Best-effort vendor resolution with explicit handling for randomized MACs."""
        if not mac:
            return "Unknown"

        mac_full = _normalize_mac(mac)
        if not mac_full:
            return "Unknown"
    
        oui = _mac_oui(mac_full)  # e.g. 'AA:BB:CC' compute OUI from normalized full

        # 0) exact alias (full MAC) — user override wins
        if mac_full in self._alias:
            return (self._alias[mac_full] or "Unknown").strip()

        # 1) randomized MACs — label explicitly and stop (don’t pollute unknowns)
        if self._is_locally_admin_from_full(mac_full):   # <-- note self.
            return "Locally Administered (Randomized)"
    
        # 2) alias by OUI
        if oui and oui in self._alias:
            val = self._alias[oui]
            if val and val.strip() and val.strip() != "Unknown":
                return val.strip()

        # 3) main offline map by OUI
        if oui and oui in self._map:
            val = self._map[oui]
            if val and val.strip() and val.strip() != "Unknown":
                return val.strip()

        # 4) manuf fallback (package DB)
        if _MANUF and mac_full:
            try:
                v = _MANUF.get_manuf_long(mac_full) or _MANUF.get_manuf(mac_full)
                if v and v.strip() and v.strip() != "Unknown":
                    return v.strip()
            except Exception:
                pass

        # 5) track unknown OUIs (non-randomized only), with a tiny miss cache
        if oui:
            self._unknown_ouis[oui] = self._unknown_ouis.get(oui, 0) + 1
            if oui in self._miss_cache:
                return "Unknown"
            self._miss_cache.add(oui)

        return "Unknown"

_HOSTNAMES = _HostnameResolver(HOST_ALIAS_PATH)
_HOSTNAMES

# Optional helper if you want a manual fix list right here:
# _VENDOR.add_vendor_alias("B0:F7:C4", "Amazon Technologies Inc.")   # OUI alias
# _VENDOR.add_vendor_alias("B0:F7:C4:DC:90:B5", "My Server (Amazon)") # full MAC alias
# -------------------- end enhanced resolver --------------------

# =============================================================================
# SECTION: UNIFIED VENDOR RESOLUTION (override vendors_offline)
# =============================================================================

# Single shared resolver instance
_VENDORS = _VendorResolver()

# --- [] vendor_for_mac --------------------------------------
def vendor_for_mac(mac: str | None) -> str:
    """
    Unified vendor lookup used by the whole app.

    Order of precedence:
      1) Full MAC / OUI aliases from your overrides files (data/mac-vendor-overrides.txt, etc.)
      2) Base mac-vendor.txt (big OUI DB)
      3) Fallback: Unknown, with special handling for randomized MACs
    """
    return _VENDORS.vendor_for_mac(mac or "")

# =============================================================================
# SECTION: ENTRY POINT (main guard)
# =============================================================================

# region ENTRY POINT
# --- [MAIN] __main__ --------------------------------------
if __name__ == "__main__":
    try:
        import tkinter  # ensure available early
        _load_secrets()
        update_vendor_db_now()
        App().mainloop()
    except KeyboardInterrupt:
        sys.exit(0)

# endregion ENTRY POINT