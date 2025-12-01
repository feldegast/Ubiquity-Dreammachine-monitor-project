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
import sys
import threading
import webbrowser

from ui_tables import (
    COL_W_FIRST,
    COL_W_MAC,
    COL_W_VEND,
    COL_W_DEST,
    COL_W_LOCAL,
    COL_W_LAST,
    COL_W_BYTES,
    COL_W_STATUS,
    build_alerts_section,
    build_active_section,
    build_aggregates_section,
    refresh_alerts_table,
    refresh_active_table,
    refresh_aggregates_table,
    apply_default_alerts_column_widths,
    apply_default_active_column_widths,
    apply_default_aggregates_column_widths,
)

from ui_theme import (
    NEW_DEVICE_BACKGROUND,
    UNKNOWN_VENDOR_BACKGROUND,
    HIGH_VOLUME_BACKGROUND,
    STATUS_ICON_SIZE,
    COLOR_VENDOR_LABELLED,
    COLOR_VENDOR_KNOWN,
    COLOR_VENDOR_UNKNOWN,
    COLOR_VENDOR_LAA,# locally-administered / randomized (LAA
)

from datetime import datetime
from importlib import import_module
from pathlib import Path
from typing import Iterable, Dict, Optional

from collectors import NetflowV5Collector, ConntrackCollectorSSH

# =============================================================================
# SECTION: MODULE LINKING (Vendor Resolver → monitor_core)
# =============================================================================
# region MODULE LINKING

import vendor_resolver
import monitor_core

# Ensure monitor_core uses the unified vendor resolver
monitor_core.vendor_for_mac = vendor_resolver.vendor_for_mac

# endregion MODULE LINKING

# =============================================================================
# SECTION: DEVICE + HOST ALIAS MANAGER (modern resolver)
# =============================================================================
# region ALIAS_MANAGER

from helpers.alias_manager import AliasManager  # moved to helpers.alias_manager

# endregion ALIAS_MANAGER

# =============================================================================
# SECTION: CONSTANTS & SETTINGS
# =============================================================================
# region CONSTANTS & SETTINGS

#App name and version information
APP_NAME = "Ubiquiti SNMP + NetFlow Monitor (LAN → WAN)"
VERSION = "6.2.1"
VERSION_DATE = "2025.12.01"

#uaser data defaults
ENABLE_CONNTRACK_SSH = True   # ← make sure this is here and not commented out
ENABLE_NETFLOW_V5_COLLECTOR = False  # set False to disable when enabled i get no data
POLL_INTERVAL_SECONDS = 5
RESOLVE_RDNS = True
DEFAULT_SHOW_IDLE_DEVICES = False   # Show MACs with no destinations/bytes in Aggregates table?
ROUTER_IP = "192.168.1.1"
COPY_LIMIT_ROWS = 200
DEBUG_LOG_TAIL_LINES = 200
DEBUG = False
monitor_core.DEBUG = DEBUG
ConntrackCollectorSSH.DEBUG = DEBUG

# ---- Windows toast (optional) ----
ENABLE_TOASTS = False  # ← turn off the flaky win10toast path

# =============================================================================
# FILE PATH CONSTANTS (single source of truth)
# =============================================================================
# region FILE PATH CONSTANTS

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

# endregion FILE PATH CONSTANTS

# Global instance used by all UI + core display functions
_ALIASES = AliasManager(
    ip_path=HOST_ALIAS_PATH,
    mac_path=MAC_LABELS_PATH,
)
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

    # Filter defaults (persisted)
    "filter_hide_web": False,
    "filter_only_unknown_laa": False,
    "filter_high_volume_only": False,
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

# endregion CONSTANTS & SETTINGS

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

# Windows toast
try:
    from win10toast import ToastNotifier
    _TOASTER = ToastNotifier() if ENABLE_TOASTS else None
except Exception:
    _TOASTER = None
# end Windows toast

# endregion IMPORTS & GLOBALS

# =============================================================================
# SECTION: ENRICHMENT (Vendor lookup, Device naming)
# =============================================================================
# region ENRICHMENT

from vendor_resolver import vendor_for_mac

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


# ===== shared widths so first 4 columns align across tables =====
'''
COL_W_STATUS = 32
COL_W_FIRST = 20
COL_W_MAC   = 20
COL_W_VEND  = 220
COL_W_DEST  = 420
COL_W_LOCAL = 160
COL_W_LAST  = 140
COL_W_BYTES = 110
'''

# --- Enable SSH conntrack collector ---
#filename defined in centralised filename constants
UDM_SSH_HOST = ROUTER_IP
UDM_SSH_PORT = 22           # usually 22
# If your UDM lacks the "conntrack" binary, we’ll fall back to reading /proc
CONNTRACK_POLL_SECS = 3
# --- End SSH conntrack collector ---

monitor_core.SNMP_COMMUNITY = SNMP_COMMUNITY = "public"

# Which LANs count as "client devices"
# LAN_PREFIXES = ["192.168.1.0/24", "10.27.10.0/24"]

# Which LANs count as "client devices"
LAN_PREFIXES = [
    "192.168.1.0/24",
    "192.168.22.0/24",
    "192.168.152.0/24",
    "10.57.13.0/24",   # VPN subnet if you want to include it
]

try:
    _LAN_NETWORKS = [ipaddress.ip_network(p, strict=False) for p in LAN_PREFIXES]
except Exception:
    _LAN_NETWORKS = []

# Push the compiled networks into monitor_core
monitor_core._LAN_NETWORKS = _LAN_NETWORKS

# NetFlow v5 collector (UDP)
NETFLOW_LISTEN_IP = "0.0.0.0"
NETFLOW_LISTEN_PORT = 2055
RDNS_TIMEOUT = 1.0  # seconds per lookup
# ===============================

# ---------- ALERTING ----------
ALERT_THRESHOLD_BYTES = 1_048_576  # 1 MB per single connection
ALERT_COOLDOWN_SECS   = 300        # don't repeat alert for the same 5-tuple within this cooldown

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

from monitor_core import (
    MonitorCore, 
    walk_arp_table,
    _walk_ipnet_physical,
    _walk_at_mib,
    normalize_mac,

)
# endregion ENRICHMENT

# Treat these as unknown
#moved to monitor_core.py
#ZERO_MACS = monitor_core.ZERO_MACS = {"00:00:00:00:00:00", "00-00-00-00-00-00", "", None}

try:
    #from mac_vendor_lookup import MacLookup, AsyncMacLookup  # pip install mac-vendor-lookup aiofiles
    from mac_vendor_lookup import AsyncMacLookup  # pip install mac-vendor-lookup aiofiles
except Exception:
    #MacLookup = None
    AsyncMacLookup = None

# =============================================================================
# SECTION: MAC LABEL STORAGE (local labels / overrides)
# =============================================================================
# region: MAC LABEL STORAGE (local labels / overrides)

# --- [NET] load_mac_labels ------------------------------------
def load_mac_labels() -> dict:
    """
    Load local_mac_labels.json and normalise all entries to:
        { MAC : { "label": "NAME" } }
    """
    try:
        with MAC_LABELS_PATH.open("r", encoding="utf-8") as f:
            raw = json.load(f) or {}
    except Exception:
        return {}

    fixed = {}

    for mac, entry in raw.items():
        # Case 1: old format { MAC: "Label" }
        if isinstance(entry, str):
            fixed[mac.upper()] = {"label": entry.strip()}

        # Case 2: expected new format { MAC: { "label": "Label" } }
        elif isinstance(entry, dict):
            lbl = entry.get("label") or ""
            fixed[mac.upper()] = {"label": lbl.strip()}

        # Anything unexpected → safely ignore
        else:
            continue

    return fixed

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

# endregion: MAC LABEL STORAGE (local labels / overrides)

# --- [HOSTNAME|CORE] _HostnameResolver ---------------------------------
from helpers.hostname_resolver import _HostnameResolver  # moved to helpers.hostname_resolver
# =============================================================================
# SECTION: HOSTNAME ALIAS RESOLVER (GLOBAL INSTANCE)
# =============================================================================
# region HOSTNAME ALIAS RESOLVER

# This must appear BEFORE class App so Pylance sees it as defined,
# and so App._display_local and other methods can use it.

_HOSTNAMES = _HostnameResolver(HOST_ALIAS_PATH)
_HOSTNAMES

# endregion HOSTNAME ALIAS RESOLVER

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

# =============================================================================
# SECTION: Secrets / SSH config
# =============================================================================
# region: Secrets / SSH config

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

# endregion: Secrets / SSH config

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
# SECTION: NETWORK CORE
# =============================================================================
# region: NETWORK CORE

# =============================================================================
# SECTION: NETWORK CORE - SNMP backend selection & helpers
# =============================================================================
# region NETWORK CORE - SNMP backend selection & helpers

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

monitor_core.snmp_walk = snmp_walk

# endregion NETWORK CORE - SNMP backend selection & helpers

# =============================================================================
# SUBSECTION: NETWORK CORE - ARP/IP-MIB parsing & UI prep
# =============================================================================
# region NETWORK CORE - ARP/IP-MIB parsing & UI prep

# numeric OIDs (no MIB files needed)
OID_ifName                  = "1.3.6.1.2.1.31.1.1.1.1"      # IF-MIB::ifName
monitor_core.OID_ipNetToMediaPhysAddress = OID_ipNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2"        # IP-MIB::ipNetToMediaPhysAddress
monitor_core.OID_ipNetToMediaNetAddress  = OID_ipNetToMediaNetAddress  = "1.3.6.1.2.1.4.22.1.3"        # IP-MIB::ipNetToMediaNetAddress
OID_tcpConnState            = "1.3.6.1.2.1.6.13.1.1"        # TCP-MIB::tcpConnState

TCP_STATE = {
    1: 'closed', 2: 'listen', 3: 'synSent', 4: 'synReceived',
    5: 'established', 6: 'finWait1', 7: 'finWait2', 8: 'closeWait',
    9: 'lastAck', 10: 'closing', 11: 'timeWait', 12: 'deleteTCB'
}
# Additional MAC source: IP-MIB::ipNetToPhysicalPhysAddress
# OID: 1.3.6.1.2.1.4.35.1.4 .<ifIndex>.<addrType>.<addrLen>.<addrOctets...>
# For IPv4 rows: addrType=1, addrLen=4, then a.b.c.d

# ====== ARP / NEIGHBOR TABLES (robust) ======

# Additional tables & OIDs
monitor_core.OID_ipNetToPhysicalPhysAddress = OID_ipNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4"
# Legacy AT-MIB (some firmwares still populate this)
monitor_core.OID_atPhysAddress =  OID_atPhysAddress = "1.3.6.1.2.1.3.1.1.2"
monitor_core.OID_atNetAddress =  OID_atNetAddress  = "1.3.6.1.2.1.3.1.1.3"

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
monitor_core._parse_mac_from_val = _parse_mac_from_val

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
monitor_core.walk_tcp_connections = walk_tcp_connections

# --- Wire SNMP-related settings into monitor_core ---
monitor_core.ROUTER_IP = ROUTER_IP
monitor_core.SNMP_COMMUNITY = SNMP_COMMUNITY

monitor_core.POLL_INTERVAL_SECONDS = POLL_INTERVAL_SECONDS
monitor_core.ALERT_THRESHOLD_BYTES = ALERT_THRESHOLD_BYTES
monitor_core.ALERT_COOLDOWN_SECS = ALERT_COOLDOWN_SECS

monitor_core.OID_ipNetToMediaNetAddress       = OID_ipNetToMediaNetAddress
monitor_core.OID_ipNetToMediaPhysAddress      = OID_ipNetToMediaPhysAddress
monitor_core.OID_ipNetToPhysicalPhysAddress   = OID_ipNetToPhysicalPhysAddress
monitor_core.OID_atNetAddress                 = OID_atNetAddress
monitor_core.OID_atPhysAddress                = OID_atPhysAddress

monitor_core.snmp_walk = snmp_walk
monitor_core.walk_tcp_connections = walk_tcp_connections
monitor_core.DEBUG = DEBUG
# endregion NETWORK CORE - ARP/IP-MIB parsing & UI prep

# endregion: NETWORK CORE

# =============================================================================
# SECTION: UTILITIES - DNS / rDNS / utilities
# =============================================================================
# region: UTILITIES - DNS / rDNS / utilities

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

# --- [UTIL|FILEIO|TAIL] tail_file ------------------------------------
def tail_file(path: str, max_lines: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            return "".join(lines[-max_lines:])
    except Exception:
        return ""

# endregion UTILITIES - DNS / rDNS / utilities

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
import tkinter.font as tkfont

class App(tk.Tk):
    
    """
    Main Tkinter GUI for the Ubiquiti SNMP + NetFlow monitor.

    This window owns:
    - The three primary tables (Alerts, Active, Aggregates)
    - The right-hand device details panel
    - Status bar and footer controls
    - All menu and context menu handlers
    - Persistence of layout and config (window size, column widths, details width)
    """

    # --- [CONFIG] load_config ------------------------------------
    def load_config(self) -> dict:
        """
        Load config.json into memory. Falls back to defaults if missing
        or malformed. Never raises. Persist runtime config to disk including window geometry,
        state, and panel width values stored in self.cfg.
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

    # --- [UI|INIT] __init__ ------------------------------------
    def __init__(self):
        """
        Initialise the main application window.

        - Applies automatic DPI scaling.
        - Loads persisted configuration from config.json.
        - Sets window title / geometry based on config.
        - Creates the Core engine and background collectors.
        - Builds all UI widgets and starts the periodic refresh loop.
        """
        super().__init__()
        
        # Early status so we can show startup progress even before _build_ui()
        # (build_ui will see these and NOT overwrite them because of hasattr checks)
        self.note = tk.StringVar(value="Starting collectors…")
        self.status = tk.StringVar(value="Starting up…")
        self._startup_seen_data = False  # flips to True once we see first rows

        # Apply DPI scaling before we build any UI or set fonts
        self._auto_dpi_scaling()
        
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

        self._init_vendor_icons()
        
        self._build_ui()
        self._ui_ready = True 
        # Give Tk a beat to compute sizes, then place sashes
        self.after(50, self._init_layout)  # place sashes once sizes are known
        self.after(0, lambda: self._center_window(-80))  # nudge up as needed
        
        self.thread = threading.Thread(target=self.core.run, daemon=True)
        self.thread.start()

        # Track when we've actually seen live data (used to close the popup)
        self._startup_seen_data = False

        # Show a large, easy-to-read startup dialog in the centre of the window.
        # Slight delay so the main window has a sensible size and position.
        self.after(500, self._open_startup_dialog)
        
        # Ensure we save prefs on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Kick off the refresh loop AFTER widgets exist
        self._reschedule_refresh(100)
    
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

    def _init_vendor_icons(self):
        """
        Create 40x40 transparent icons with centered 28px squares representing vendor states.
        Stored as self.icon_labelled, self.icon_known, self.icon_unknown.
        """
        from PIL import Image, ImageDraw, ImageTk

        def make_icon(hex_color: str, inner: int = 28, size: int = 40):
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            margin = (size - inner) // 2
            draw.rectangle([margin, margin, margin + inner, margin + inner], fill=hex_color)
            return ImageTk.PhotoImage(img)

        self.icon_labelled = make_icon(COLOR_VENDOR_LABELLED)
        self.icon_known    = make_icon(COLOR_VENDOR_KNOWN)
        self.icon_unknown  = make_icon(COLOR_VENDOR_UNKNOWN)

    # --- [UI|SEARCH] _apply_alert_filter ------------------------------------
    def _apply_alert_filter(self, *_):
        """
        Apply the live text filter to all three tables.

        The search string is taken from self.alert_filter_var and matched
        case-insensitively against key fields (IP, hostname, vendor/host,
        MAC, destination) so that Alerts, Active, and Aggregates all show
        only rows that contain the filter text.
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

    # endregion UI WIDGETS

    # =============================================================================
    # SECTION: SHARED HELPERS FOR REFRESH FUNCTIONS
    # =============================================================================
    # region: SHARED HELPERS FOR REFRESH FUNCTIONS

    # --- [UI|LAYOUT] _reset_column_widths ----------------------
    def _reset_column_widths(self) -> None:
        """
        Reset all Treeview column widths back to their built-in defaults and
        clear any saved overrides in config.json.
        """
        # 1) Reset the Treeviews using ui_tables helpers

        # ===================================================================================
        # SECTION: Alerts table
        # ===================================================================================
        # region: Alerts table
    
        try:
            if hasattr(self, "alerts") and self.alerts is not None:
                apply_default_alerts_column_widths(self.alerts)
        except Exception:
            pass

        # endregion Alerts table

        # ===================================================================================
        # SECTION: Active Connections table
        # ===================================================================================
        # region: Active Connections table

        try:
            if hasattr(self, "tree") and self.tree is not None:
                # DEBUG is a module-global in main.py
                apply_default_active_column_widths(self.tree, DEBUG)
        except Exception:
            pass
        # endregion Active Connections table

        # ===================================================================================
        # SECTION: Aggregates table
        # ===================================================================================
        # region: Aggregates table
    
        try:
            if hasattr(self, "agg") and self.agg is not None:
                apply_default_aggregates_column_widths(self.agg)
        except Exception:
            pass

        # endregion Aggregates table

        # ===================================================================================
        # SECTION: Clear any saved column width overrides in the config
        # ===================================================================================
        # region: Clear any saved column width overrides in the config

        # 2) Clear any saved column width overrides in the config
        try:
            cfg = self.cfg or {}
            col_cfg = cfg.get("column_widths", {})
            col_cfg["alerts"] = {}
            col_cfg["active"] = {}
            col_cfg["agg"] = {}
            cfg["column_widths"] = col_cfg
            self.cfg = cfg
            self.save_config()
        except Exception:
            pass

        # endregion Clear any saved column width overrides in the config

    # --- [UI|LAYOUT] _apply_saved_column_widths ---------------------
    def _apply_saved_column_widths(self, table_name: str, tv: ttk.Treeview) -> None:
        """
        Restore per-column widths for a Treeview from the persisted config.

        Parameters
        ----------
        table_name : str
            Logical name of the table ("active", "agg", "alerts").
        tv : ttk.Treeview
            The Treeview whose columns should be sized.
        """

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

    def _clear_details_panel(self) -> None:
        """Show a neutral 'no row selected' state in the details panel."""
        self.detail_mac.set("No row selected")
        self.detail_name.set("Unknown / unrecognised vendor")
        self.detail_local.set("-")
        self.detail_remote.set("-")
        self.detail_when.set("-")
        self.detail_bytes.set("-")
        self.detail_note.set("-")
        self.detail_mac_flags.set("-")

    # --- [UI|DETAILS] _build_details_panel ------------------------------------
    def _build_details_panel(self, parent: tk.Frame) -> None:
        # ------------------------------------------------------------------
        # Right-hand "Selected Device / Connection" panel
        # ------------------------------------------------------------------
        """
        Build the right-hand device details panel.

        It shows a summary of the currently selected row from any table:
        Alerts, Active, or Aggregates.
        """

        import tkinter as tk
        from tkinter import ttk

        frame = ttk.LabelFrame(parent, text="Selected Device / Connection")
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        # StringVars stored on self so _update_details_from_tree can update them
        self.detail_mac = tk.StringVar(value="No row selected")
        self.detail_name = tk.StringVar(value="Unknown / unrecognised vendor")
        self.detail_local = tk.StringVar(value="-")
        self.detail_remote = tk.StringVar(value="-")
        self.detail_when = tk.StringVar(value="-")
        self.detail_bytes = tk.StringVar(value="-")
        self.detail_note = tk.StringVar(value="-")
        self.detail_mac_flags = tk.StringVar(value="-")

        # Small 2-column grid of labels
        rows = [
            ("MAC Address:", self.detail_mac),
            ("Device / Vendor:", self.detail_name),
            ("Local endpoint:", self.detail_local),
            ("Remote endpoint:", self.detail_remote),
            ("When:", self.detail_when),
            ("Bytes (TX):", self.detail_bytes),
            ("Notes:", self.detail_note),
            ("MAC status:", self.detail_mac_flags),
        ]

        for r, (label_text, var) in enumerate(rows):
            ttk.Label(frame, text=label_text).grid(
                row=r, column=0, sticky="w", padx=(4, 2), pady=1
            )
            ttk.Label(frame, textvariable=var).grid(
                row=r, column=1, sticky="w", padx=(2, 4), pady=1
            )

        # let column 1 expand to take remaining width
        frame.columnconfigure(1, weight=1)

        # Initialise with "no selection" state
        self._clear_details_panel()

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

    # --- [UI|DETAILS] _describe_port -------------------------------------------
    def _describe_port(self, port_str: str) -> str:
        """
        Map a numeric port to a human-friendly name for common services.
        Returns an empty string if unknown or not numeric.
        """
        try:
            p = int(str(port_str))
        except Exception:
            return ""

        common = {
            20:  "FTP-data",
            21:  "FTP",
            22:  "SSH",
            23:  "Telnet",
            25:  "SMTP",
            53:  "DNS",
            80:  "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            161: "SNMP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            587: "SMTP-submission",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-alt",
            8443: "HTTPS-alt",
        }

        return common.get(p, "")

    # --- [UI|DETAILS] _update_details_from_tree --------------------------------
    def _update_details_from_tree(self, tv: "ttk.Treeview", table_name: str) -> None:
        """
        Update the right-hand details panel based on the selected row in `tv`.

        `table_name` is one of: "alerts", "active", "agg".
        """

        from tkinter import ttk  # noqa: F401  (for type hints / completeness)
        from monitor_core import normalize_mac

        # ===================================================================================
        # SECTION: 1) Ensure only ONE table has a highlighted row at any time
        # ===================================================================================
        # region: 1) Ensure only ONE table has a highlighted row at any time

        try:
            if table_name != "alerts" and hasattr(self, "alerts"):
                self.alerts.selection_remove(*self.alerts.selection())
            if table_name != "active" and hasattr(self, "tree"):
                self.tree.selection_remove(*self.tree.selection())
            if table_name != "agg" and hasattr(self, "agg"):
                self.agg.selection_remove(*self.agg.selection())
        except Exception:
            # Don't let selection issues kill the update
            pass
        # endregion: 1) Ensure only ONE table has a highlighted row at any time
        
        # ===================================================================================
        # SECTION: 2) Find the selected item in THIS tree
        # ===================================================================================
        # region: 2) Find the selected item in THIS tree

        sel = tv.selection()
        if not sel:
            # Fallback to focused item if nothing is formally selected
            focused = tv.focus()
            if focused:
                sel = (focused,)

        # IMPORTANT: If there is still no selection, DO NOT clear the details.
        # That way, when Active/Aggregates refresh and lose selection,
        # the right-hand panel keeps showing the last-clicked row.
        if not sel:
            return

        iid = sel[0]
        values = tv.item(iid, "values") or ()
        cols = tv["columns"] or ()

        # Map column IDs -> cell values, e.g. {"mac": "...", "vendor": "..."}
        row = {col: values[idx] for idx, col in enumerate(cols) if idx < len(values)}

        # endregion: 2) Find the selected item in THIS tree

        # ===================================================================================
        # SECTION: 3) Extract common pieces according to table_name
        # ===================================================================================
        # region: 3) Extract common pieces according to table_name

        mac_raw = row.get("mac", "") or ""
        mac_norm = normalize_mac(mac_raw)

        # Local endpoint (ip:port) – present in alerts/active, not in agg
        local_display = row.get("local", "") or ""

        # Destination / remote endpoint – column name differs
        remote_display = row.get("dest", "") or row.get("remote", "") or ""

        # "When" information differs by table
        if table_name == "alerts":
            when_display = row.get("time", "") or ""
        elif table_name == "active":
            first = row.get("first", "") or ""
            last = row.get("last", "") or ""
            if first and last:
                when_display = f"{first} → {last}"
            else:
                when_display = first or last or ""
        elif table_name == "agg":
            sightings = row.get("sightings", "") or ""
            when_display = f"{sightings} sightings" if sightings else ""
        else:
            when_display = ""

        # Bytes / totals
        bytes_str = row.get("bytes", "") or row.get("total", "") or ""

        # Note (alerts only)
        note = row.get("note", "") or ""

        # endregion: 3) Extract common pieces according to table_name

        # ===================================================================================
        # SECTION: 4) Vendor / name – use our display helper (aliases, labels, etc.)
        # ===================================================================================
        # region: 4) Vendor / name – use our display helper (aliases, labels, etc.)
        
        local_ip = ""
        if ":" in local_display:
            local_ip = local_display.rsplit(":", 1)[0]

        display_name = (
            self._display_name(local_ip or None, mac_norm)
            or row.get("vendor", "")
            or ""
        )

        # Optional: augment with router DHCP hostname (via SSH) if available
        router_host = self._router_hostname_for_ip(local_ip)
        if router_host:
            # Avoid duplicating if the router hostname is already part of the string
            if router_host.lower() not in display_name.lower():
                if display_name:
                    display_name = f"{display_name} [{router_host}]"
                else:
                    display_name = router_host

        # endregion: 4) Vendor / name – use our display helper (aliases, labels, etc.)
        
        # ===================================================================================
        # SECTION: 5) MAC status flags (labelled / known / laa / unknown)
        # ===================================================================================
        # region: 5) MAC status flags (labelled / known / laa / unknown)

        status_key = self._vendor_status_for_mac(mac_norm)
        if status_key == "labelled":
            mac_flags = "Labelled host (green square)"
        elif status_key == "known":
            mac_flags = "Known vendor (blue square)"
        elif status_key == "laa":
            mac_flags = "Randomised / locally-administered MAC (orange square)"
        else:
            mac_flags = "Unknown / unrecognised vendor (red square)"

        # endregion: 5) MAC status flags (labelled / known / laa / unknown)
        
        # ===================================================================================
        # SECTION: 6) Push into the StringVars bound to the details panel labels
        # ===================================================================================
        # region: 6) Push into the StringVars bound to the details panel labels

        self.detail_mac.set(mac_norm or mac_raw or "Unknown")
        self.detail_name.set(display_name or "Unknown / unrecognised vendor")
        self.detail_local.set(local_display or "-")
        self.detail_remote.set(remote_display or "-")
        self.detail_when.set(when_display or "-")
        self.detail_bytes.set(str(bytes_str) if bytes_str != "" else "-")
        self.detail_note.set(note or "-")
        self.detail_mac_flags.set(mac_flags)

        # endregion: 6) Push into the StringVars bound to the details panel labels

    # --- [UI] notify ------------------------------------
    def notify(self, title, msg):
        """
        Show a lightweight OS-level toast notification, if supported.

        Parameters
        ----------
        title : str
            Short title for the notification.
        msg : str
            Body text to display in the toast.
        """

        if _TOASTER:
            try:
                _TOASTER.show_toast(title, msg, threaded=True)
            except Exception:
                pass

    # --- [UI|LAYOUT] _post_build_column_fix ------------------------------------    
    def _post_build_column_fix(self):
        """
        Normalize the first column width across Alerts, Active, and Aggregates.

        Called after all three Treeviews exist so their "first" column line up
        visually, using the same width constant as in _build_ui().
        """
        
        try:
            # Keep in sync with your build_ui constants
            for tv in (self.alerts, self.tree, self.agg):
                try:
                    first_col = tv["columns"][0]
                    tv.column(first_col, width=COL_W_FIRST)
                except Exception:
                    pass
        except Exception:
            pass

    # --- [UI|LAYOUT] _setup_synced_column_widths ------------------------------------    
    def _setup_synced_column_widths(self) -> None:
        """
        Keep related columns (by *meaning*, not just ID) in sync across
        Alerts, Active, and Aggregates.

        Logical groups:

        - "time_like":  Alerts.time, Active.first, Agg.sightings
        - "mac":        Alerts.mac, Active.mac, Agg.mac
        - "vendor":     Alerts.vendor, Active.vendor, Agg.vendor
        - "local":      Alerts.local, Active.local
        - "dest":       Alerts.dest, Active.dest, Agg.dest

        When you resize one of these in any table, we propagate that width
        to the corresponding columns in the other tables.
        """
        try:
            # Gather the three main tables if they exist
            tables: dict[str, object] = {
                "alerts": getattr(self, "alerts", None),
                "active": getattr(self, "tree", None),
                "agg":    getattr(self, "agg", None),
            }

            # Drop any that don't exist (e.g. during early startup)
            tables = {name: tv for name, tv in tables.items() if tv is not None}
            if not tables:
                return

            # Logical mapping of column groups -> per-table column IDs
            SYNC_GROUPS: dict[str, dict[str, str]] = {
                # Time / First Seen / Sightings share the same width
                "time_like": {
                    "alerts": "time",
                    "active": "first",
                    "agg":    "sightings",
                },
                "mac": {
                    "alerts": "mac",
                    "active": "mac",
                    "agg":    "mac",
                },
                "vendor": {
                    "alerts": "vendor",
                    "active": "vendor",
                    "agg":    "vendor",
                },
                "local": {
                    "alerts": "local",
                    "active": "local",
                },
                "dest": {
                    "alerts": "dest",
                    "active": "dest",
                    "agg":    "dest",
                },
                # If you decide later that bytes should sync too,
                # you can add a "bytes" group here.
            }

            # Filter out groups where fewer than 2 tables participate
            # (no point syncing if only one table has that column).
            pruned_groups: dict[str, dict[str, str]] = {}
            for gname, mapping in SYNC_GROUPS.items():
                # keep only entries for tables that actually exist
                present = {
                    tname: col_id
                    for tname, col_id in mapping.items()
                    if tname in tables
                }
                if len(present) >= 2:
                    pruned_groups[gname] = present

            if not pruned_groups:
                return

            def _on_column_resize(event):
                """
                Called on ButtonRelease-1 on any Treeview.

                For each logical group this Treeview participates in,
                read its new width and propagate to the matching columns
                in the other tables of that group.
                """
                tv = event.widget
                # Work out which logical table name this tv corresponds to
                tv_name = None
                for name, obj in tables.items():
                    if obj is tv:
                        tv_name = name
                        break
                if tv_name is None:
                    return  # not one of our three main tables

                # For each group, if this table participates, propagate width
                for gname, mapping in pruned_groups.items():
                    if tv_name not in mapping:
                        continue

                    src_col = mapping[tv_name]
                    # If the column doesn't exist on this tv, skip
                    try:
                        col_info = tv.column(src_col)
                        width = col_info.get("width")
                    except Exception:
                        continue

                    if width is None:
                        continue

                    # Apply same width to other tables in this group
                    for other_name, other_col in mapping.items():
                        if other_name == tv_name:
                            continue
                        other_tv = tables.get(other_name)
                        if other_tv is None:
                            continue
                        try:
                            other_tv.column(other_col, width=width)
                        except Exception:
                            # don't let a bad column kill the whole sync
                            continue

            # Bind once per table
            for tv in tables.values():
                try:
                    tv.bind("<ButtonRelease-1>", _on_column_resize, add="+")
                except Exception:
                    pass

        except Exception:
            if DEBUG:
                import traceback
                print("[UI] _setup_synced_column_widths failed:")
                traceback.print_exc()

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

    # =============================================================================
    # SECTION: Startup dialogue
    # =============================================================================
    # region: Startup dialogue
    
    # --- [UI|STARTUP] update dialog from MonitorCore --------------------
    def _update_startup_dialog(self):
        """
        Refresh the 6-step startup dialog from MonitorCore.startup_*.

        This method ONLY updates the text/markers. The dialog is actually
        closed from _refresh_ui once live data appears.
        """
        dlg = getattr(self, "_startup_dialog", None)
        if dlg is None:
            return
        try:
            if not dlg.winfo_exists():
                return
        except Exception:
            return

        core = getattr(self, "core", None)
        if core is None:
            self.after(250, self._update_startup_dialog)
            return

        total = getattr(core, "startup_total_steps", 6) or 6
        idx = getattr(core, "startup_step_index", 0)
        label = getattr(core, "startup_step_label", "")
        done_core = getattr(core, "startup_done", False)

        steps = getattr(self, "_startup_steps", [])
        labels = getattr(self, "_startup_step_labels", [])

        # Update each line: ✓ for completed, → for current, plain for pending.
        for i, (step_text, lbl) in enumerate(zip(steps, labels), start=1):
            # Prefer dynamic label for the current step, if provided by core
            text_for_line = label if (i == idx and label) else step_text

            if i < idx:
                prefix = "✓ "
            elif i == idx and not done_core:
                prefix = "→ "
            elif i == idx and done_core:
                prefix = "✓ "
            else:
                prefix = "  "

            lbl.configure(text=f"{prefix}{i}/{total} {text_for_line}")

        # Keep polling until someone (refresh_ui) closes the dialog
        self.after(250, self._update_startup_dialog)

    # --- [UI|STARTUP] _center_startup_dialog -----------------------------
    def _center_startup_dialog(self):
        """Center the startup dialog after it has been mapped."""
        dlg = getattr(self, "_startup_dialog", None)
        if dlg is None:
            if DEBUG:
                print("[DEBUG] _center_startup_dialog: no dialog object")
            return
        try:
            if not dlg.winfo_exists():
                if DEBUG:
                    print("[DEBUG] _center_startup_dialog: dialog no longer exists")
                return
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] _center_startup_dialog: winfo_exists exception: {e}")
            return

        # Ensure geometry is up-to-date
        self.update_idletasks()
        dlg.update_idletasks()

        dlg_w = dlg.winfo_width()
        dlg_h = dlg.winfo_height()

        app_w = self.winfo_width()
        app_h = self.winfo_height()
        app_x = self.winfo_rootx()
        app_y = self.winfo_rooty()

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()

        # Prefer centring over the app window; fall back to screen centre
        if app_w > 1 and app_h > 1:
            target_x = app_x + (app_w - dlg_w) // 2
            target_y = app_y + (app_h - dlg_h) // 2 - 40  # nudge up a bit
            method = "APP-CENTER"
        else:
            target_x = (sw - dlg_w) // 2
            target_y = (sh - dlg_h) // 2
            method = "SCREEN-CENTER"

        dlg.geometry(f"+{target_x}+{target_y}")
        dlg.update_idletasks()

        if DEBUG:
            dlg_x = dlg.winfo_rootx()
            dlg_y = dlg.winfo_rooty()
            print(
                f"[DEBUG] _center_startup_dialog: method={method}, "
                f"target=({target_x}, {target_y}), actual=({dlg_x}, {dlg_y})"
            )

    # --- [UI|STARTUP] 6-step startup dialog -----------------------------
    def _open_startup_dialog(self):
        """
        Show a centred dialog with the 6 backend-startup steps.

        Progress data is read from:
            core.startup_step_index
            core.startup_step_label
            core.startup_total_steps

        The dialog is auto-closed by _refresh_ui once live data appears.
        """
        # Only create once
        if getattr(self, "_startup_dialog", None) is not None:
            try:
                if self._startup_dialog.winfo_exists():
                    return
            except Exception:
                self._startup_dialog = None

        core = getattr(self, "core", None)
        if core is None:
            # Core not ready yet; try again shortly
            self.after(300, self._open_startup_dialog)
            return

        dlg = tk.Toplevel(self)
        self._startup_dialog = dlg
        dlg.title("Initialising backend")
        dlg.transient(self)
        dlg.resizable(False, False)

        # Make it appear above the main window (without being hard-modal)
        dlg.lift()
        try:
            dlg.attributes("-topmost", True)
            dlg.after(10, lambda: dlg.attributes("-topmost", False))
        except Exception:
            pass

        # Slightly larger font for readability
        base_font = tkfont.nametofont("TkDefaultFont")
        big_font = base_font.copy()
        big_font.configure(size=max(base_font.cget("size") + 2, 12))
        self._startup_font = big_font

        container = ttk.Frame(dlg, padding=12)
        container.pack(fill="both", expand=True)

        header = ttk.Label(
            container,
            text="Initialising backend data collection…",
            font=(big_font.cget("family"), big_font.cget("size") + 1, "bold"),
        )
        header.pack(anchor="w", pady=(0, 8))

        steps_frame = ttk.Frame(container)
        steps_frame.pack(fill="both", expand=True)

        # The 6 conceptual steps we want to show
        self._startup_steps = [
            "Starting backend data collection",
            "Initialise the data backend",
            "Initial ARP/IP-MIB/neighbor walk",
            "Read conntrack / netstat / NetFlow",
            "Enrich rows with MAC/vendor/labels",
            "Waiting for data…",
        ]

        self._startup_step_labels = []
        total = getattr(core, "startup_total_steps", 6) or 6

        for idx, text in enumerate(self._startup_steps, start=1):
            lbl = ttk.Label(
                steps_frame,
                text=f"{idx}/{total} {text}",
                anchor="w",
                font=big_font,
            )
            lbl.pack(anchor="w")
            self._startup_step_labels.append(lbl)

        # Let Tk compute natural size now, then centre after the dialog is mapped
        self.update_idletasks()
        dlg.update_idletasks()

        # Start polling core for progress
        self._update_startup_dialog()

        # Centre the dialog once the WM has actually mapped it
        dlg.after(0, self._center_startup_dialog)

    def _poll_startup_progress(self):
        """Update the 6-step dialog from MonitorCore.startup_* and auto-close when done."""
        win = getattr(self, "_startup_win", None)
        if not win or not win.winfo_exists():
            return

        core = getattr(self, "core", None)
        if core is None:
            self.after(250, self._poll_startup_progress)
            return

        total = getattr(core, "startup_total_steps", 6) or 6
        idx = getattr(core, "startup_step_index", 0)
        label = getattr(core, "startup_step_label", "")
        done = getattr(core, "startup_done", False)
        seen = getattr(self, "_startup_seen_data", False)

        texts = getattr(self, "_startup_step_texts", [])
        labels = getattr(self, "_startup_step_labels", [])

        for i, lbl in enumerate(labels, start=1):
            base = texts[i - 1] if i - 1 < len(texts) else ""
            # For current step, prefer the dynamic label coming from core
            current_text = label if (i == idx and label) else base
            lbl.configure(
                text=f"{i}/{total} {current_text}",
                style="StartupCurrent.TLabel" if i == idx else "StartupNormal.TLabel",
            )

        # Close once backend finished AND the UI has seen first rows (from your existing logic)
        if done and seen:
            try:
                win.destroy()
            except Exception:
                pass
            self._startup_win = None
            return

        # Keep polling until we’re done
        self.after(250, self._poll_startup_progress)
    # endregion: Startup dialogue

    # --- [HOSTNAME|UI] _on_manage_hostname_aliases -------------------------
    # Purpose: Manage hostname aliases (add/edit/delete/clear-cache)
    def _on_manage_hostname_aliases(self):
        """
        Export a CSV snapshot of the current monitor state to disk.

        Writes a file containing at least the Active and/or Aggregates views,
        using the same formatted values as shown in the UI, so you can inspect
        historical data in Excel or other tools.
        """
        
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

    # --- [UI|MENU] _update_vendor_menu_state ------------------------------------
    def _update_vendor_menu_state(self) -> None:
        """
        Enable/disable Vendor Enrichment menu items based on current state:

        - Export… is disabled if there are no overrides in the resolver
        - Import… is disabled if the JSON file doesn't exist
        """
        
        ''' disables after refactoring
        vm = getattr(self, "vendor_menu", None)
        if vm is None:
            return

        # 1) Export: only enabled if we have any aliases in the resolver
        try:
            has_overrides = bool(getattr(_VENDORS, "_alias", {}))
        except Exception:
            has_overrides = False

        vm.entryconfig(
            "Export Vendor Overrides…",
            state="normal" if has_overrides else "disabled",
        )

        # 2) Import: only enabled if the JSON file exists
        try:
            exists = VENDOR_OVERRIDES_JSON.exists()
        except Exception:
            exists = False

        vm.entryconfig(
            "Import Vendor Overrides…",
            state="normal" if exists else "disabled",
        )'''
        
    # --- [UI|MENU] _menu_export_vendor_overrides ------------------------------------
    def _menu_export_vendor_overrides(self):
        from tkinter import filedialog, messagebox
        path = filedialog.asksaveasfilename(
            title="Export Vendor Overrides to JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            count = export_vendor_enrichment(path)
            messagebox.showinfo("Export complete", f"Exported {count} entries to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    # --- [UI|MENU] _menu_import_vendor_overrides ------------------------------------
    def _menu_import_vendor_overrides(self):
        from tkinter import filedialog, messagebox
        path = filedialog.askopenfilename(
            title="Import Vendor Overrides from JSON",
            filetypes=[("JSON files", "*.json"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            count = import_vendor_enrichment(path, prefer_existing=True)
            messagebox.showinfo("Import complete", f"Merged {count} entries from:\n{path}")
        except Exception as e:
            messagebox.showerror("Import failed", str(e))
            
    # --- [UI|MENU] _build_menu ------------------------------------
    def _build_menu(self):
        """
        Build the menubar for the main window.

        Attaches File / Tools / Help (or equivalent) menus and binds them
        to the appropriate handler methods on this App instance.
        """

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

        view_menu.add_separator()
        view_menu.add_command(
            label="Reset column widths",
            command=self._reset_column_widths,
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

        # rDNS toggle (default ON unless config says otherwise)
        self._rdns_var = tk.BooleanVar(value=bool(self.cfg.get("resolve_rdns", RESOLVE_RDNS)))
        tools_menu.add_checkbutton(label="Resolve rDNS",variable=self._rdns_var,onvalue=True,offvalue=False,command=self._toggle_rdns,)
        
        conntrack_var = tk.BooleanVar(value=self.cfg.get("enable_conntrack_ssh", ENABLE_CONNTRACK_SSH))
        tools_menu.add_checkbutton(label="Use conntrack SSH collector", variable=conntrack_var, command=self._toggle_conntrack_ssh,)

        netflow_var = tk.BooleanVar(value=self.cfg.get("enable_netflow_v5_collector", ENABLE_NETFLOW_V5_COLLECTOR))
        tools_menu.add_checkbutton(label="Use NetFlow v5 collector", variable=netflow_var, command=self._toggle_netflow_v5,)

        tools_menu.add_separator()
        tools_menu.add_command(label="Settings…", command=self._open_settings_dialog)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # -------- Vendor Enrichment Menu --------
        self.vendor_menu = tk.Menu(menubar, tearoff=False)
        self.vendor_menu.add_command(label="Export Vendor Overrides…", accelerator="Ctrl+E", command=self._menu_export_vendor_overrides,)
        self.bind("<Control-e>", lambda *_: self._menu_export_vendor_overrides())
        self.vendor_menu.add_command(label="Import Vendor Overrides…", command=self._menu_import_vendor_overrides,)
        menubar.add_cascade(label="Vendor Enrichment", menu=self.vendor_menu)

        # Initialise enabled/disabled state
        self._update_vendor_menu_state()

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
    def _build_ui(self):
        """
        Construct all top-level UI widgets for the main window.

        Layout:
        - Footer with copy/export buttons.
        - Status bar with note + live metrics (active, MACs, flow/SSH, clock).
        - Left side: vertical stack of Alerts, Active, and Aggregates tables.
        - Right side: device details panel in a fixed-width sidebar.
        - Binds selection, context menu, and search/filter behaviours.
        - Schedules the first call to _refresh_ui() when done.
        """
        
        # Purpose: MENUBAR + CONTENT (Alerts + Active + Aggregates + Details)
        #          + STATUS (bottom) + FOOTER (above status)
        
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
        
        # Ensure status icon images exist
        self._init_vendor_status_icons()
        
        # ----- menubar (optional) -----
        if hasattr(self, "_build_menu"):
            try:
                self._build_menu()
            except Exception:
                pass

        # --- [UI|TABLES] _force_headings --------------------------------------------------
        def _force_headings(tv: ttk.Treeview, labels: dict[str, str]):
            """Apply column IDs + headings WITHOUT overriding tv['show'].

            Some tables use 'tree headings' now for a #0 status icon column, so
            this helper must not force 'headings' only.
            """
            cols = tuple(labels.keys())
            tv["columns"] = cols
            tv["displaycolumns"] = cols
            # Do NOT touch tv['show'] here; caller decides.
            for cid, txt in labels.items():
                tv.heading(cid, text=txt)

            def _reassert():
                for cid, txt in labels.items():
                    tv.heading(cid, text=txt)

            tv.after_idle(_reassert)

        # =============================================================================
        # SECTION: FOOTER (buttons above statusbar)
        # =============================================================================
        # region FOOTER (buttons above statusbar)

        foot = ttk.Frame(self)
        foot.pack(side="bottom", fill="x", padx=8, pady=(0, 6))
        self.foot = foot

        # right cluster
        ttk.Button(foot, text="Copy Alerts",                         command=self._copy_alerts,).pack(side="right", padx=(8, 0))
        ttk.Button(foot, text="Copy Active",                         command=self._copy_active,).pack(side="right", padx=(8, 0))
        ttk.Button(foot, text="Copy Aggregates",                     command=self._copy_aggregates,).pack(side="right", padx=(8, 0))
        ttk.Button(foot, text="Export Snapshot (CSV)",               command=self._export_snapshot,).pack(side="right", padx=(8, 0))
        ttk.Button(foot, text="Manage Hostname Aliases",             command=self._on_manage_hostname_aliases,).pack(side="right", padx=(8, 0))
        ttk.Button(foot, text="Set Hostname Alias (from selection)", command=self._on_set_hostname_alias,).pack(side="right", padx=(8, 12))

        # left cluster (always visible)
        ttk.Button(foot, text="Export unknown MAC addresses",        command=self._on_copy_unknown_vendors_menu,).pack(side="left")
        ttk.Button(foot, text="Copy Debug Bundle",                   command=self._copy_debug_bundle,).pack(side="left", padx=(8, 12))

        # endregion FOOTER (buttons above statusbar)


        # =============================================================================
        # SECTION: Statusbar (very bottom)
        # =============================================================================
        # region Statusbar (very bottom)
        
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

        ttk.Label(statusf, textvariable=self.status_conn, anchor="e").pack(
            side="right", padx=(8, 0)
        )
        ttk.Label(statusf, textvariable=self.status_flow, anchor="e").pack(
            side="right", padx=(8, 0)
        )
        ttk.Label(statusf, textvariable=self.status_ssh, anchor="e").pack(
            side="right", padx=(8, 0)
        )


        # endregion Statusbar (very bottom)
        
        # =============================================================================
        # SECTION: UI.CONTENT (everything that scrolls/expands)
        # =============================================================================
        # region UI.CONTENT (everything that scrolls/expands)
        
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

        # =============================================================================
        # SECTION: Alerts SECTION (top of left content)
        # =============================================================================
        # region Alerts SECTION (top of left content)
    
        alert_outer = ttk.Frame(paned)
        paned.add(alert_outer, weight=1)
        build_alerts_section(self, alert_outer)

        # endregion Alerts SECTION (top of left content)
        
        # =============================================================================
        # SECTION: Active Connections (middle of left content)
        # =============================================================================
        # region Active Connections (middle of left content)

        active_outer = ttk.Frame(paned)
        paned.add(active_outer, weight=2)
        build_active_section(self, active_outer)

        # endregion Active Connections (middle of left content)

        # =============================================================================
        # SECTION: Aggregates (bottom of left content)
        # =============================================================================
        # region Aggregates (bottom of left content)

        agg_outer = ttk.Frame(content)
        agg_outer.pack(fill="both", expand=False, padx=8, pady=(0, 4))
        build_aggregates_section(self, agg_outer)
        
        self._post_build_column_fix()

        # All three main tables now exist; keep shared columns in sync
        try:
            self._setup_synced_column_widths()
        except Exception:
            if DEBUG:
                import traceback
                print("[UI] _setup_synced_column_widths failed in _build_ui:")
                traceback.print_exc()

        # schedule refresh after widgets exist
        try:
            self._reschedule_refresh(250)
        except Exception:
            pass
        # endregion AAggregates (bottom of left content)
        
        # endregion UI.CONTENT (everything that scrolls/expands)

    # =============================================================================
    # SECTION: UI CONTROLLER (events, handlers, refresh loop)
    # =============================================================================
    # region UI CONTROLLER
    
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

            if DEBUG:
                print(f"[DPI] pixels_per_inch={pixels_per_inch:.2f}, scale={scale:.2f}")

        except Exception:
            # Never crash if DPI probing fails
            pass

    # --- [UI] _apply_state_visibility ------------------------------------
    def _apply_state_visibility(self):
        """
        Hide/show the 'state' column (DEBUG-only in Active table).

        - If DEBUG is False or the column doesn't exist, do nothing.
        - If DEBUG is True and the 'state' column exists, make it visible.
        """
        tree = getattr(self, "tree", None)
        if tree is None:
            return

        col = "state"

        # If the Treeview doesn't have a 'state' column, bail out cleanly.
        cols = tree["columns"]
        if isinstance(cols, (list, tuple)):
            has_state = col in cols
        else:
            # Tk can return a space-separated string
            has_state = col in str(cols).split()

        if not has_state:
            # In non-DEBUG builds, we never added the column; nothing to do.
            return

        show = bool(globals().get("DEBUG", False))

        if show:
            tree.heading(col, text="State")
            tree.column(col, width=110, minwidth=60, stretch=False, anchor="w")
        else:
            tree.heading(col, text="")
            tree.column(col, width=0, minwidth=0, stretch=False)

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

    # =============================================================================
    # SECTION:Local MAC labels: get / set helpers
    # =============================================================================
    # region Local MAC labels: get / set helpers

    # --- [UI] _get_current_label_for_mac ------------------------------------
    def _get_current_label_for_mac(self, mac: str) -> str:
        return _ALIASES.label_for_mac(mac) or ""
    
    # --- [UI] _set_label_for_mac ------------------------------------
    def _set_label_for_mac(self, mac: str, label: str):
        _ALIASES.set_label_for_mac(mac, label)

    # endregion Local MAC labels: get / set helpers

    # --- [UI|VENDOR STATUS ICONS] ---------------------------------------
    def _init_vendor_status_icons(self) -> None:
        """
        Build small in-memory square icons for vendor status:

        - 'labelled' : custom device label (green)
        - 'known'    : known vendor (blue)
        - 'laa'      : locally-administered / randomized MAC (purple)
        - 'unknown'  : everything else (red)
        """
        import tkinter as tk
        from ui_theme import (
            STATUS_ICON_SIZE,
            COLOR_VENDOR_LABELLED,
            COLOR_VENDOR_KNOWN,
            COLOR_VENDOR_LAA,
            COLOR_VENDOR_UNKNOWN,
        )

        if getattr(self, "_status_icons", None):
            return  # already created

        size = STATUS_ICON_SIZE

        def _square(color: str) -> tk.PhotoImage:
            img = tk.PhotoImage(width=size, height=size)
            img.put(color, to=(0, 0, size, size))
            return img

        self._status_icons: dict[str, tk.PhotoImage] = {
            "labelled": _square(COLOR_VENDOR_LABELLED),
            "known":    _square(COLOR_VENDOR_KNOWN),
            "laa":      _square(COLOR_VENDOR_LAA),
            "unknown":  _square(COLOR_VENDOR_UNKNOWN),
        }

    # --- [UI|VENDOR STATUS CLASSIFIER] _vendor_status_for_mac -----------
    def _vendor_status_for_mac(self, mac: str | None) -> str:
        """
        Return one of: 'labelled', 'known', 'laa', 'unknown'.

        'labelled' means:
          - there is a MAC label in local_mac_labels.json, OR
          - any IP that has a Hostname Alias currently maps to this MAC.

        'known' / 'laa' / 'unknown' come from vendor_resolver.
        """
        # Local imports to avoid circular deps and keep this helper self-contained
        from vendor_resolver import vendor_for_mac, _is_locally_administered
        from monitor_core import normalize_mac

        # Normalise MAC using the canonical normaliser
        mac_norm = normalize_mac(mac or "")
        if not mac_norm or mac_norm == "00:00:00:00:00:00":
            return "unknown"

        # =============================================================================
        # SECTION: 1) MAC labels (local_mac_labels.json) → 'labelled' (green)
        # =============================================================================
        # region 1) MAC labels (local_mac_labels.json) → 'labelled' (green)

        try:
            # Small cache so we don't re-read file every time
            label_map = getattr(self, "_mac_labels_cache", None)
            if label_map is None:
                label_map = load_mac_labels()   # local function in this file
                self._mac_labels_cache = label_map

            entry = label_map.get(mac_norm)
            label_str: str = ""
            if isinstance(entry, dict):
                # New format: { "AA:BB:...": {"label": "My Laptop"} }
                label_str = (entry.get("label") or "").strip()
            elif entry is not None:
                # Backwards-compatible: { "AA:BB:...": "My Laptop" }
                label_str = str(entry).strip()

            if label_str:
                return "labelled"
        except Exception:
            # Never let label logic break the app
            pass


        # endregion 1) MAC labels (local_mac_labels.json) → 'labelled' (green)

        # =============================================================================
        # SECTION: 2) Hostname aliases (local_ip_labels.json) → 'labelled'
        # =============================================================================
        # region 2) Hostname aliases (local_ip_labels.json) → 'labelled'
        
        try:
            core = getattr(self, "core", None)
            if core is not None:
                ip2mac = getattr(core, "ip2mac", {}) or {}
                aliases = _HOSTNAMES.aliases()  # { ip: alias_name }
                if isinstance(aliases, dict):
                    for ip, alias_name in aliases.items():
                        if not alias_name:
                            continue  # skip blank aliases
                        mac_for_ip = ip2mac.get(ip)
                        if mac_for_ip and normalize_mac(mac_for_ip) == mac_norm:
                            return "labelled"
        except Exception:
            # Never let alias logic break the app
            pass
        # endregion 2) Hostname aliases (local_ip_labels.json) → 'labelled'
        
        # =============================================================================
        # SECTION: 3) Fallback: vendor-based classification
        # =============================================================================
        try:
            vendor_name = vendor_for_mac(mac_norm) or ""
        except Exception:
            vendor_name = ""

        # Locally-administered bit set → probably randomised / LAA
        if _is_locally_administered(mac_norm):
            return "laa"

        # Vendor name present → known
        if vendor_name.strip():
            return "known"

        # Nothing else matched → unknown
        return "unknown"

    # --- [UI|HOSTNAMES] _router_hostname_for_ip ------------------------------
    def _router_hostname_for_ip(self, ip: str | None) -> str:
        """
        Look up the DHCP hostname for a given local IP by asking the SSH
        collector (ConntrackCollectorSSH) to parse /run/dnsmasq/leases.

        Returns "" if:
          - no IP is given,
          - there is no SSH collector,
          - the router doesn't have a lease/hostname for that IP,
          - or anything goes wrong.
        """
        if not ip:
            return ""

        try:
            # Local import to avoid any circular import tangles
            from collectors import ConntrackCollectorSSH

            core = getattr(self, "core", None)
            if core is None:
                return ""

            nf = getattr(core, "nf", None)
            if not isinstance(nf, ConntrackCollectorSSH):
                # No SSH conntrack collector → nothing to ask
                return ""

            # Ask the collector for the current DHCP lease map
            leases = nf.fetch_dhcp_leases()
            entry = leases.get(ip)
            if not entry:
                return ""

            host = (entry.get("hostname") or "").strip().strip("*")
            if not host:
                return ""
            return host

        except Exception:
            # Never let hostname lookup kill the UI
            return ""

    # --- [UI|HOSTNAMES] _router_hostname_for_ip ------------------------------
    def _router_hostname_for_ip(self, ip: str | None) -> str:
        """
        Look up the DHCP hostname for a given local IP by asking the SSH
        collector (ConntrackCollectorSSH) to parse /run/dnsmasq/leases.

        Returns "" if:
          - no IP is given,
          - there is no SSH collector,
          - the router doesn't have a lease/hostname for that IP,
          - or anything goes wrong.
        """
        if not ip:
            return ""

        try:
            # Local import to avoid any circular import tangles
            from collectors import ConntrackCollectorSSH

            core = getattr(self, "core", None)
            if core is None:
                return ""

            nf = getattr(core, "nf", None)
            if not isinstance(nf, ConntrackCollectorSSH):
                # No SSH conntrack collector → nothing to ask
                return ""

            # Ask the collector for the current DHCP lease map
            leases = nf.fetch_dhcp_leases()
            entry = leases.get(ip)
            if not entry:
                return ""

            host = (entry.get("hostname") or "").strip().strip("*")
            if not host:
                return ""
            return host

        except Exception:
            # Never let hostname lookup kill the UI
            return ""

    # --- [UI|VENDOR STATUS ICON LOOKUP] _status_icon_for_mac ---------------
    def _status_icon_for_mac(self, mac: str | None) -> tk.PhotoImage | None:
        """
        Return the tk.PhotoImage for the given MAC's vendor status.

        Safe to call even before _init_vendor_status_icons (returns None).
        """
        icons = getattr(self, "_status_icons", None)
        if not icons:
            return None

        key = self._vendor_status_for_mac(mac)
        return icons.get(key)

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

            if DEBUG:
            # Optional: live debug while tuning
                print("[LIVE details_width]", self.cfg["details_width"])

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
            
    def _status_msg(self, msg: str):
        """
        Show a user-facing status message in the status bar.
        Also print to console when DEBUG=True.

        Use this instead of print() for important errors or warnings
        that the user should see.
        """
        text = str(msg)
        try:
            self._set_status(text)
        except Exception:
            pass

        if DEBUG:
            print(text)

    # --- [UI|STATUS] _update_status_line ------------------------------------
    def _update_status_line(self):
        """
        Build the status text for the bottom status bar, using the refactored
        MonitorCore + collectors.

        Shows something like:
          SNMP: puresnmp | Active: 12 TCP: 10 ARP: 34 Flows: 8 | Flow: NetFlow v5 OK | SSH: OK
        """

        core = getattr(self, "core", None)
        if core is None:
            self._set_status("Core not running")
            return

        try:
            # Basic counters from core
            active      = len(getattr(core, "conn_map", {}) or {})
            last_counts = getattr(core,     "last_counts", {}) or {}
            arp         = last_counts.get(  "arp", 0)
            tcp         = last_counts.get(  "tcp", 0)
            flows       = last_counts.get(  "flows", 0)

            bits = []

            # SNMP backend name (you already have get_snmp_backend_name())
            bits.append(f"SNMP: {get_snmp_backend_name()}")

            # Core counters
            bits.append(f"Active: {active}  TCP: {tcp}  ARP: {arp}  Flows: {flows}")

            # Flow backend: NetFlow or SSH conntrack
            nf = getattr(core, "nf", None)

            from collectors import NetflowV5Collector, ConntrackCollectorSSH  # safe local import

            if isinstance(nf, NetflowV5Collector):
                err = getattr(nf, "bind_error", None)
                if err:
                    bits.append("Flow: NetFlow ERROR")
                else:
                    bits.append("Flow: NetFlow v5 OK")
            elif isinstance(nf, ConntrackCollectorSSH):
                msg = nf.status_msg or "idle"
                bits.append(f"Flow: conntrack ({msg})")
            elif nf is None:
                bits.append("Flow: off")

            # SSH indicator – use the SSH collector if you keep a reference on App
            ssh = getattr(self, "ssh_collector", None)
            if ssh is not None:
                ssh_msg = ssh.status_msg or "idle"
                bits.append(f"SSH: {ssh_msg}")

            # Finally push to the existing status mechanism (note_lbl / status_var)
            self._set_status(" | ".join(bits))

        except Exception as e:
            # Don't let status failures kill the UI; just log in DEBUG mode.
            if DEBUG:
                print("[UI|STATUS] error building status line:", e)

    # --- [UI|TREEVIEW] _setup_sorting ------------------------------------
    def _setup_sorting(self, tree: "ttk.Treeview", table_name: str, default_col: str | None = None, default_reverse: bool = False):
        """
        Enable click-to-sort behaviour for a Treeview.

        Parameters
        ----------
        tv : ttk.Treeview
            The Treeview to configure.
        table_name : str
            Logical name of the table ("active", "agg", "alerts"), used as a key
            to remember per-table sort state.
        default_col : str
            Column id to sort by when the table is first built.
        default_reverse : bool
            Whether the initial sort order should be descending.
        """

        if not hasattr(self, "_sort_prefs"):
            self._sort_prefs = {}

        numeric_cols = {
            # Alerts
            "alerts:bytes",
            # Active
            "active:bytes",
            # Aggregates
            "agg:sightings", "agg:bytes",
        }

        time_cols = {
            "alerts:time",
            "active:first",
            "active:last",
        }

        def _sort_key(table: str, col: str, val: str):
            from datetime import datetime

            keyid = f"{table}:{col}"
            v = "" if val is None else str(val)

            # Numeric columns
            if keyid in numeric_cols:
                try:
                    return int(v.replace(",", ""))
                except Exception:
                    return 0

            # Boolean-ish column (>1MB? Yes/No)
            if table == "active" and col == "over1mb":
                return 1 if v.strip().lower() in ("yes", "true", "1") else 0

            # Time-like columns – parse ISO timestamps
            if keyid in time_cols:
                try:
                    return datetime.fromisoformat(v)
                except Exception:
                    # push invalid/blank to the top
                    return datetime.min

            # Fallback: case-insensitive string
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

        numeric_cols = {
            "alerts:bytes",
            "active:bytes",
            "agg:sightings", "agg:bytes",
        }

        time_cols = {
            "alerts:time",
            "active:first",
            "active:last",
        }

        def _sort_key(val: str):
            from datetime import datetime

            v = "" if val is None else str(val)
            keyid = f"{table_name}:{col}"

            if keyid in numeric_cols:
                try:
                    return int(v.replace(",", ""))
                except Exception:
                    return 0

            if table_name == "active" and col == "over1mb":
                return 1 if v.strip().lower() in ("yes", "true", "1") else 0

            if keyid in time_cols:
                try:
                    return datetime.fromisoformat(v)
                except Exception:
                    return datetime.min

            return v.lower()
        
        rows.sort(key=lambda t: _sort_key(t[1]), reverse=reverse_hint)
        for idx, (iid, _) in enumerate(rows):
            tree.move(iid, "", idx)

    # --- [DNS|HELPER] queue rDNS for an IP (no-dup, safe) ------------------------
    def _queue_rdns(self, ip: str) -> None:
        # Optionally queue rDNS for aggregate destinations as well (keeps display consistent)
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
        """
        Returns a human-friendly label for a local ip:port.
        """
        ip = AliasManager.ip_from_hostport(local_hostport)
        if not ip:
            return local_hostport

        # 1) Prefer user-defined IP labels
        name = _ALIASES.name_for_ip(ip)
        if name:
            return f"{name}  ({local_hostport})"

        # 2) No label defined → just show IP normally
        return local_hostport

    # --- Menu handlers ---
    # --- [UI] _on_about --------------------------------------
    def _on_about(self):
        """
        Show an “About” dialog with version and environment information.

        Displays app name/version, Python version, SNMP backend, and paths
        to key files such as the SSH secrets and config file.
        """
        
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
                        if DEBUG:
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
        mac_norm = normalize_mac(mac) or mac.upper()
        ip = (ip or "").strip()

        # Reuse the existing edit dialog
        result = self._open_edit_dialog(mac_norm, ip)
        if not result:
            return

        new_mac, label = result
        new_mac = normalize_mac(new_mac) or mac_norm

        # Persist via existing helper
        self._set_label_for_mac(new_mac, label)

        # Small delayed refresh so the vendor/label column updates
        self._reschedule_refresh(10)

    # --- [UI] _on_toggle_show_idle --------------------------------------
    def _on_toggle_show_idle(self) -> None:
        """Persist the 'Show idle devices' toggle to config.json."""
        self.cfg["show_idle_devices"] = bool(self.show_idle_var.get())
        self.save_config()
        # Force a quick repaint so the table reflects the new filter
        self._reschedule_refresh(10)

    # --- [UI] _on_test_ssh --------------------------------------
    def _on_test_ssh(self):
        """
        Perform a quick SSH connectivity test to the UDM.

        Uses the same credentials and host/port as the SSH collector, but runs
        a short probe (device and console) without starting the background thread.
        Shows a message box summarising which endpoints succeed or fail.
        """
        
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
        """
        Toggle reverse-DNS resolution based on the Tools → Resolve rDNS checkbutton.

        The BooleanVar on the menu (self._rdns_var) is the source of truth:
        - update self.cfg["resolve_rdns"]
        - push into global RESOLVE_RDNS (used by the worker + refresh_* calls)
        - persist to config.json
        """
        # Read the state from the menu's BooleanVar; default to True if missing.
        try:
            new_val = bool(self._rdns_var.get())
        except Exception:
            new_val = True

        # Update config + globals
        self.cfg["resolve_rdns"] = new_val
        self.save_config()

        global RESOLVE_RDNS
        RESOLVE_RDNS = new_val

        # Status line feedback
        self._set_status(f"rDNS {'ON' if RESOLVE_RDNS else 'OFF'}")

    def _reschedule_refresh(self, delay_ms: int = 1000):
        try:
            self.after(delay_ms, self._refresh_ui)
        except Exception:
            pass

    # --- [UI|REFRESH] _refresh_ui ----------------------------------------------
    def _refresh_ui(self):
        """
        Periodically refresh the table contents and status bar from the Core state.
    
        - Rebuilds the Alerts, Active, and Aggregates Treeviews from core.conn_map
          and other cached structures.
        - Reapplies row colour tags (unknown vendor, high volume, new device).
        - Updates the status bar metrics (active count, MAC count, flow/SSH state,
          clock skew warning).
        - Reschedules itself using after() while the app is running.
        """

        if DEBUG:
            print("[DEBUG] UI sees conn_map size:", len(self.core.conn_map))

        with self.core.data_lock:
            

        # =============================================================================
        # SECTION: REFRESH.ALERTS (top) - drain queue, insert rows, toast
        # =============================================================================
        # region REFRESH.ALERTS (top) - drain queue, insert rows, toast

            refresh_alerts_table(self, toaster=_TOASTER)


        # endregion REFRESH.ALERTS (top) - drain queue, insert rows, toast
        
        # =============================================================================
        # SECTION: REFRESH.ACTIVE (middle) - CONNECTIONS
        # =============================================================================
        # region REFRESH.ACTIVE (middle) - CONNECTIONS

            # Active Connections table
            refresh_active_table(
                self,
                dns_lock=_dns_lock,
                dns_cache=_dns_cache,
                dns_pending=_dns_pending,
                resolve_rdns=RESOLVE_RDNS,
            )
            
        # endregion REFRESH.ACTIVE (middle) - CONNECTIONS
        
        # =============================================================================
        # SECTION: REFRESH.AGGREGATES (bottom) - PER-DEVICE TOTALS
        # =============================================================================
        # region REFRESH.AGGREGATES (bottom) - PER-DEVICE TOTALS

            # Aggregates table
            refresh_aggregates_table(
                self,
                dns_lock=_dns_lock,
                dns_cache=_dns_cache,
                dns_pending=_dns_pending,
                resolve_rdns=RESOLVE_RDNS,
            )

        # endregion REFRESH.AGGREGATES (bottom) - PER-DEVICE TOTALS
        
        # ===============================================================
        # REAPPLY SORT
        # ===============================================================
        try:
            self._reapply_sort_if_any("alerts", self.alerts)
            self._reapply_sort_if_any("active", self.tree)
            self._reapply_sort_if_any("agg", self.agg)
        except Exception:
            pass

        # =============================================================================
        # SECTION: STATUS LINE - SSH STATUS ECHO
        # =============================================================================
        # region STATUS LINE - SSH STATUS ECHO
        
        # --- Status bar metrics: Active + MACs ----------------------------
        try:
            core = self.core
            active_rows = getattr(core, "get_active_rows_prepared", None)
            if callable(active_rows):
                rows = active_rows(limit=COPY_LIMIT_ROWS)
            else:
                rows = list(core.conn_map.values())

            active_count = len(rows)

            macs = {
                normalize_mac(
                    r.get("local_mac") or r.get("mac") or ""
                )
                for r in rows
            }
            macs.discard("")
            unique_macs = len(macs)

            if hasattr(self, "status_conn"):
                self.status_conn.set(f"Active: {active_count} | MACs: {unique_macs}")

            # Simple startup indicator:
            # - While we have no data yet, show an "initialising" message.
            # - Once we see any rows/MACs, flip to "Ready", clear note, and
            #   close the startup dialog if it's still open.
            if not getattr(self, "_startup_seen_data", False):
                if active_count > 0 or unique_macs > 0:
                    # First data has arrived
                    self._startup_seen_data = True

                    # Update status bar
                    if hasattr(self, "status"):
                        self.status.set("Ready")
                    if hasattr(self, "note") and self.note.get().startswith("Starting"):
                        # Clear the note once we are live
                        self.note.set("")

                    # Close the startup dialog once we know we have live data
                    dlg = getattr(self, "_startup_dialog", None)
                    if dlg is not None:
                        try:
                            dlg.destroy()
                        except Exception:
                            pass
                        self._startup_dialog = None

                    if DEBUG:
                        print(
                            f"[DEBUG] _refresh_ui: first data seen - "
                            f"Active={active_count}, MACs={unique_macs}"
                        )
                else:
                    # Still waiting for the first successful core cycle
                    if hasattr(self, "status"):
                        self.status.set(
                            "Initialising… waiting for router/conntrack data"
                        )
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] _refresh_ui status block error: {e}")
            # Don't let status failures kill the UI
            pass

        # --- Router IP on the left status text ----------------------------
        try:
            # Prefer an instance attribute if it ever exists, otherwise fall back
            router_ip = getattr(self, "router_ip", None) or self.cfg.get("router_ip", ROUTER_IP)
            self.status.set(f"Connected to: {router_ip}")
        except Exception:
            pass

        # --- Flow + SSH backend status ------------------------------------
        try:
            from collectors import ConntrackCollectorSSH, NetflowV5Collector

            core = self.core
            nf = getattr(core, "nf", None)

            # SSH label
            ssh_label = "SSH: off"

            if isinstance(nf, ConntrackCollectorSSH):
                msg = nf.status_msg or "OK"
                who = getattr(nf, "_who", None) or "console"
                ssh_label = f"SSH: {msg} ({who})"

                # Only print when changing (and in DEBUG)
                if msg != getattr(self, "_last_ssh_status", None):
                    if DEBUG:
                        print(f"[SSH] {msg}")
                    self._last_ssh_status = msg

            elif ENABLE_CONNTRACK_SSH:
                ssh_label = "SSH: enabled (idle)"

            if hasattr(self, "status_ssh"):
                self.status_ssh.set(ssh_label)

            # Flow label
            flow_label = "Flow: off"
            try:
                flows = int(core.last_counts.get("flows", 0))
            except Exception:
                flows = 0

            if isinstance(nf, ConntrackCollectorSSH):
                # SSH conntrack as flow source
                if not flows:
                    flows = active_count
                flow_label = f"Flow: SSH conntrack ({flows} flows)"

            elif isinstance(nf, NetflowV5Collector):
                err = getattr(nf, "bind_error", None)
                if err:
                    flow_label = "Flow: NetFlow ERROR"
                else:
                    flow_label = f"Flow: NetFlow v5 ({flows} flows)"

            else:
                # SNMP-only fallback: show active connections
                flow_label = f"Flow: SNMP ({active_count} connections)"

            if hasattr(self, "status_flow"):
                self.status_flow.set(flow_label)

        except Exception:
            # Again, never let status bar kill UI
            pass
        
        # endregion STATUS LINE - SSH STATUS ECHO
        
        # ===============================================================
        # SCHEDULE NEXT REFRESH
        # ===============================================================
        # region SCHEDULE NEXT REFRESH
        
        if getattr(self, "_ui_ready", False):
            try:
                self._reschedule_refresh()
            except Exception:
                pass

        # endregion SCHEDULE NEXT REFRESH

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

    # --- [UI|COPY] _copy_alerts ------------------------------------
    def _copy_alerts(self):
        """
        Copy the current Alerts table to the clipboard.

        Uses the same formatting helper as _copy_active() so the output is
        easy to inspect or share.
        """

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
        """
        Export a CSV snapshot of the current monitor state to disk.

        Writes a file containing at least the Active and/or Aggregates views,
        using the same formatted values as shown in the UI, so you can inspect
        historical data in Excel or other tools.
        """
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
        """
        Copy a text blob to the system clipboard and optionally show a toast.

        Parameters
        ----------
        text : str
            Text to place on the clipboard.
        toast : str | None
            Optional short message to display via the Windows toast notifier
            (if available).
        """

        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()  # ensures clipboard gets the data
            self.status.set(ok_msg)
        except Exception as e:
            self.status.set(f"Copy failed: {e}")

    # --- [UI|COPY] Copy visible Active table -------------------------------------
    def _copy_active(self):
        """
        Copy the current Active Connections table to the clipboard.

        Formats the rows as a simple tab-separated or CSV-style text so it can
        be pasted into a text editor or spreadsheet for further analysis.
        """

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
        """
        Copy the Per-Device Totals (Aggregates) table to the clipboard.

        Useful for quickly exporting top talkers or device totals to another
        tool without writing a file to disk.
        """

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
        """
        Copy a multi-section debug bundle to the clipboard.

        Sections:
          1) Environment / config
          2) Active connections (top N)
          3) Connected devices summary (via App._display_name)
          4) Tail of the debug log
        """
        
        parts: list[str] = []

        # =============================================================================
        # 1) Environment / config
        # =============================================================================
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
                f"App: {APP_NAME}",
                f"Version: {VERSION}  ({VERSION_DATE})",
                f"Python: {platform.python_version()} ({platform.system()} {platform.release()})",
                f"Executable: {getattr(_sys, 'executable', '')}",
                f"SNMP backend: {get_snmp_backend_name()}",
                f"puresnmp: {puresnmp_ver}",
                f"Router IP: {ROUTER_IP}",
                f"Community: {SNMP_COMMUNITY}",
                f"Poll Interval (s): {POLL_INTERVAL_SECONDS}",
                f"NetFlow v5 collector: "
                f"{'ON' if getattr(self, 'nf', None) else 'OFF'} on {NETFLOW_LISTEN_IP}:{NETFLOW_LISTEN_PORT}",
                "",
            ]
            parts.append("\n".join(env))
        except Exception:
            # Environment info is nice-to-have only – ignore failures.
            pass

        core = getattr(self, "core", None)

        # Small helpers shared by sections 2 & 3
        def _safe_rows_from_core(limit: int) -> list[dict]:
            if core is None:
                return []
            getter = getattr(core, "get_active_rows_prepared", None)
            try:
                if callable(getter):
                    return getter(limit=limit)
                # Fallback: raw conn_map
                return list(core.conn_map.values())[:limit]
            except Exception:
                return []

        # =============================================================================
        # 2) Active connections snapshot (top N)
        # =============================================================================
        try:
            header = [
                "Local",
                "MAC",
                "Vendor/Host (via _display_name)",
                "Remote",
                "State",
                "First Seen",
                "Last Seen",
                "Bytes (TX)",
                ">1MB?",
            ]
            rows = ["\t".join(header)]

            def _fmt_local(rec: dict) -> str:
                lip = rec.get("local_ip") or rec.get("src_ip") or ""
                lpt = rec.get("local_port") or rec.get("src_port")
                return f"{lip}:{lpt}" if lip and lpt is not None else str(lip)

            def _fmt_remote(rec: dict) -> str:
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

            # Preferred: what the user actually sees in the Active table
            items = []
            try:
                items = list(self.tree.get_children())[:COPY_LIMIT_ROWS]
                for iid in items:
                    vals = self.tree.item(iid)["values"]
                    rows.append("\t".join(str(v) for v in vals))
            except Exception:
                # Fallback: pull from core directly
                recs = _safe_rows_from_core(COPY_LIMIT_ROWS)
                for rec in recs:
                    local = _fmt_local(rec)
                    mac = rec.get("local_mac") or rec.get("mac") or ""
                    # old-style vendor field (still useful)
                    vendor = rec.get("vendor") or "Unknown"
                    remote = _fmt_remote(rec)
                    state = rec.get("state") or rec.get("tcp_state") or ""
                    first_seen = rec.get("first_seen") or ""
                    last_seen = rec.get("last_seen") or ""
                    raw_bytes = rec.get("bytes") or rec.get("bytes_tx") or 0
                    btx = _fmt_bytes(raw_bytes)
                    over = (
                        "Yes"
                        if isinstance(raw_bytes, (int, float)) and raw_bytes >= 1_048_576
                        else "No"
                    )
                    rows.append(
                        "\t".join(
                            [
                                local,
                                mac,
                                vendor,
                                remote,
                                state,
                                str(first_seen),
                                str(last_seen),
                                btx,
                                over,
                            ]
                        )
                    )

            parts.append(
                "=== Active Connections (top {}) ===\n".format(COPY_LIMIT_ROWS)
                + "\n".join(rows)
            )
        except Exception:
            # Don’t let debug-copy kill the app
            pass

        # =============================================================================
        # 3) Connected devices summary (one line per MAC, via _display_name)
        # =============================================================================
        try:
            core = getattr(self, "core", None)
            if core is not None:
                from vendor_resolver import _normalize_mac as normalize_mac

                # mac_norm -> set of IPs
                mac_to_ips: dict[str, set[str]] = {}

                # 3a) Devices from ARP / ip2mac
                for ip, mac in getattr(core, "ip2mac", {}).items():
                    mac_norm = normalize_mac(mac or "")
                    if not mac_norm:
                        continue
                    mac_to_ips.setdefault(mac_norm, set()).add(ip)

                # 3b) Devices from aggregates (even if no current connection)
                for mac in getattr(core, "aggregates", {}).keys():
                    mac_norm = normalize_mac(mac or "")
                    if not mac_norm:
                        continue
                    mac_to_ips.setdefault(mac_norm, set())

                # 3c) Devices seen in the active rows we just used
                try:
                    recs = core.get_active_rows_prepared(limit=COPY_LIMIT_ROWS)
                except Exception:
                    recs = []

                for rec in recs:
                    mac_norm = normalize_mac(rec.get("local_mac") or rec.get("mac") or "")
                    if not mac_norm:
                        continue
                    ip = rec.get("local_ip") or rec.get("src_ip") or ""
                    if ip:
                        mac_to_ips.setdefault(mac_norm, set()).add(ip)

                if mac_to_ips:
                    dev_header = ["MAC", "IP(s)", "DisplayName (App._display_name)", "Status"]
                    dev_rows = ["\t".join(dev_header)]

                    for mac_norm in sorted(mac_to_ips.keys()):
                        ips = sorted(mac_to_ips.get(mac_norm) or [])
                        primary_ip = ips[0] if ips else None

                        # Use the same display logic as the UI (includes aliases / DHCP / DNS)
                        try:
                            name = self._display_name(primary_ip, mac_norm, None)
                        except Exception as e:
                            name = f"(error from _display_name: {e})"

                        # Optional: vendor status (labelled / known / laa / unknown)
                        status = ""
                        try:
                            if hasattr(self, "_vendor_status_for_mac"):
                                status = self._vendor_status_for_mac(mac_norm)
                        except Exception:
                            status = ""

                        dev_rows.append(
                            "\t".join(
                                [
                                    mac_norm,
                                    ", ".join(ips) if ips else "-",
                                    name or "",
                                    status or "",
                                ]
                            )
                        )

                    parts.append(
                        "=== Connected Devices (via _display_name) ===\n"
                        + "\n".join(dev_rows)
                        + "\n"
                    )
        except Exception:
            # Safe to ignore; bundle is still useful without this section
            pass

        # =============================================================================
        # 4) Tail of debug log
        # =============================================================================
        try:
            log_tail = tail_file(LOG_FILENAME, DEBUG_LOG_TAIL_LINES)
            if log_tail:
                parts.append("=== Debug log tail ===\n" + log_tail)
        except Exception:
            pass

        # =============================================================================
        # Final: join and copy to clipboard
        # =============================================================================
        blob = "\n\n".join(p for p in parts if p)

        try:
            self.clipboard_clear()
            self.clipboard_append(blob)
            if hasattr(self, "status"):
                self.status.set("Debug bundle copied to clipboard")
        except Exception:
            # As a last resort, show an error dialog
            try:
                messagebox.showerror(
                    "Copy failed",
                    "Could not copy the debug bundle to the clipboard.",
                )
            except Exception:
                pass

    # --- [UI|TEXT] _display_name ----------------------------------------------
    def _display_name(self, local_ip: str | None, mac: str | None, vendor: str | None = None) -> str:
        """
        Return a nice 'Vendor / Host' string for tables.
    
        Priority:
          1) MAC label (from local_mac_labels.json)
          2) Host alias for the *local* IP (local_ip_labels.json)
          3) Router DHCP hostname (via SSH, if available)
          4) Vendor name (from OUI DB / overrides)
          5) 'Unknown'
    
        Also handles randomized / locally-administered MACs by annotating with "(Random)".
        """

        from vendor_resolver import _is_locally_administered, vendor_for_mac
        from vendor_resolver import _normalize_mac as normalize_mac
        try:
            # optional – only present when SSH conntrack is used
            from collectors import ConntrackCollectorSSH  # type: ignore
        except Exception:
            ConntrackCollectorSSH = None  # type: ignore

        mac_norm = normalize_mac(mac or "")
        vendor = (vendor or "").strip()

        # =============================================================================
        # 1) Current MAC label (from mac_labels, via existing helper)
        # =============================================================================
        label = ""
        try:
            if hasattr(self, "_get_current_label_for_mac"):
                label = (self._get_current_label_for_mac(mac_norm) or "").strip()
        except Exception:
            label = ""

        # =============================================================================
        # 2) Local hostname alias (from local_ip_labels.json)
        # =============================================================================
        alias_name = ""
        if local_ip:
            try:
                # _HOSTNAMES is the global _HostnameResolver(HOST_ALIAS_PATH)
                alias_map = _HOSTNAMES.aliases()
            except Exception:
                alias_map = {}

            if isinstance(alias_map, dict):
                alias_name = (alias_map.get(local_ip) or "").strip()

        # =============================================================================
        # 2b) Router DHCP hostname (via SSH -> dnsmasq leases), if no alias
        # =============================================================================
        dhcp_name = ""
        if local_ip and not alias_name:
            try:
                core = getattr(self, "core", None)
                nf = getattr(core, "nf", None) if core is not None else None

                if ConntrackCollectorSSH is not None and isinstance(nf, ConntrackCollectorSSH):
                    # lightweight call – only when user opens row details
                    leases = nf.fetch_dhcp_leases()
                    if isinstance(leases, dict):
                        entry = leases.get(local_ip)
                        if isinstance(entry, dict):
                            dhcp_name = (entry.get("hostname") or "").strip()
            except Exception:
                dhcp_name = ""

        # If we got a DHCP hostname and no explicit alias, treat it like an alias
        if not alias_name and dhcp_name:
            alias_name = dhcp_name

        # =============================================================================
        # 3) Vendor lookup (if not supplied)
        # =============================================================================
        if not vendor:
            try:
                vendor = vendor_for_mac(mac_norm) or ""
            except Exception:
                vendor = ""
        vendor = vendor.strip()
        vendor_lower = vendor.lower()

        # =============================================================================
        # 4) Randomized / locally-administered MACs
        # =============================================================================
        is_random = False
        try:
            is_random = _is_locally_administered(mac_norm)
        except Exception:
            # Fallback: look for keywords in vendor string
            if "locally administered" in vendor_lower or "randomized" in vendor_lower:
                is_random = True

        if is_random:
            # Prefer label or alias, but annotate that it's random.
            if label:
                return f"{label} (Random)"
            if alias_name:
                return f"{alias_name} (Random)"
            # Fallback to whatever vendor text we have, or generic
            return vendor or "Random"

        # =============================================================================
        # 5) Normal (non-random) MACs
        # =============================================================================
        # 5a) If we have a label, show label, with extra info in brackets if useful.
        if label:
            # If vendor is something meaningful (not Unknown), show it.
            if vendor and vendor != "Unknown":
                return f"{label} ({vendor})"
            # Otherwise, use alias as context if present.
            if alias_name:
                return f"{label} ({alias_name})"
            return label

        # 5b) No label, but we have an alias/DHCP hostname
        if alias_name:
            if vendor and vendor != "Unknown":
                return f"{alias_name} ({vendor})"
            return alias_name

        # 5c) No label, no alias → fall back to vendor or Unknown.
        return vendor or "Unknown"

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

    # --- [UI|ALIASES] _on_set_hostname_alias --------------------------------
    # Purpose: Prompt for a friendly name for the selected Active row's local IP
    def _on_set_hostname_alias(self):
        """
        Create or update a hostname alias based on the current row selection.

        Typically uses the selected IP address and an alias name entered by
        the user, then persists the mapping so future refreshes display the
        alias instead of only the raw IP.
        """
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
        #self.after(10, self._refresh_ui)
        self._reschedule_refresh()

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
            self._reschedule_refresh(0)

        ttk.Button(win, text="Save Name", command=save_name).pack(pady=10)

        # Actions
        actions = ttk.Frame(win)
        actions.pack(pady=10)
        ttk.Button(actions, text="Ping", command=lambda: os.system(f"ping {row['local_ip']} -n 4")).grid(row=0, column=0, padx=5)
        ttk.Button(actions, text="WHOIS", command=lambda: webbrowser.open(f"https://whois.domaintools.com/{row['remote']}")).grid(row=0, column=1, padx=5)

# endregion UI LAYER

# --- [OUI] _normalize_oui_text -------------------------------------- 
def _normalize_oui_text(s: str) -> str:
    s = s.strip().upper()
    hexonly = re.sub(r"[^0-9A-F]", "", s)
    if len(hexonly) < 6:
        return ""
    hexonly = hexonly[:6]
    return ":".join([hexonly[i:i+2] for i in range(0, 6, 2)])

# =============================================================================
# SECTION: VENDOR RESOLVER (shared core + UI)
# =============================================================================
# region VENDOR RESOLVER (shared core + UI)

from pathlib import Path
from typing import Optional

# We centralise all MAC → vendor logic in vendor_resolver.py.
# That module already knows about:
#   * mac-vendor-lookup’s offline database
#   * data/mac-vendor.txt
#   * data/mac-vendor-overrides.txt
#   * LOCAL_OUI_OVERRIDES inside vendor_resolver.py
#
# Here we just expose thin wrappers so the rest of the app
# (core + UI) always goes through the same resolver.

def vendor_for_mac(mac: Optional[str]) -> str:
    """
    Unified vendor lookup used by the whole app.

    Delegates to vendor_resolver.vendor_for_mac(), which returns a plain
    vendor name (no special tagging of locally administered addresses).
    """
    return vendor_resolver.vendor_for_mac(mac)

def vendor_for_display(mac: Optional[str]) -> str:
    """
    UI-friendly vendor label for a MAC address.

    Delegates to vendor_resolver.vendor_for_display(), which applies
    UI tweaks such as showing locally administered addresses as
    'Randomized (LAA)' (or similar label from vendor_resolver).
    """
    return vendor_resolver.vendor_for_display(mac)

# Make the monitoring core use the exact same resolver.
# monitor_core imports vendor_for_mac as a callable at module scope.
import monitor_core

monitor_core.vendor_for_mac = vendor_for_mac

# --- JSON export / import stubs (legacy menu items) --------------------------
#
# The old implementation stored "enrichment" in an in-memory map and let you
# export/import JSON files. We’ve moved to text-based overrides under data/
# (mac-vendor.txt and mac-vendor-overrides.txt), so there isn’t really a
# separate JSON enrichment layer any more.
#
# To avoid breaking the existing menu items, we keep compatible function
# names and signatures, but make them harmless no-ops that just return 0.
# If you decide you don’t want those menu items at all, you can later
# remove the handlers that call these and delete this stub section.

def export_vendor_enrichment(path: str | Path | None = None) -> int:
    """
    Legacy stub: there is nothing to export now that vendor overrides live
    in text files under data/. We return 0 so the caller can still show
    'Exported 0 entries' without crashing.
    """
    return 0

def import_vendor_enrichment(
    path: str | Path | None = None,
    *,
    prefer_existing: bool = True,
) -> int:
    """
    Legacy stub: there is nothing to import here; overrides are loaded
    from the text files in data/. Returning 0 keeps the menu handler happy.
    """
    return 0

# endregion VENDOR RESOLVER (shared core + UI)

# =============================================================================
# SECTION: ENTRY POINT (main guard)
# =============================================================================

# region ENTRY POINT
# --- [MAIN] __main__ --------------------------------------
if __name__ == "__main__":
    try:
        import tkinter  # ensure available early
        _load_secrets()
        App().mainloop()
    except KeyboardInterrupt:
        sys.exit(0)

# endregion ENTRY POINT