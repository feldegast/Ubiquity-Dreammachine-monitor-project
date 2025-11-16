# vendors_offline.py
from __future__ import annotations
import os
import threading
from typing import Dict, Optional

_DEFAULT_DB_BASENAMES = (
    "mac-vendor.txt",       # next to the executable / script
    "mac-vendors.txt",
)

class OfflineVendors:
    """
    Offline OUI vendor resolver backed by a plain text database.
    Expected format per line (tab-separated):
        <OUI_HEX_NO_COLONS><TAB><VENDOR NAME>[<TAB or spaces><comment...>]

    Example line:
        0000C0\tWestern Digital now SMC (Std. Microsystems Corp.)
    """

    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.RLock()
        self._db_path = db_path or self._auto_find_db()
        self._map: Dict[str, str] = {}
        self._loaded = False
        self._ensure_loaded()

    def _auto_find_db(self) -> str:
        # 1) Explicit environment override if set
        env_path = os.environ.get("MAC_VENDOR_DB", "").strip()
        if env_path and os.path.isfile(env_path):
            return env_path

        # 2) Try next to the running script / executable
        here = os.path.abspath(os.path.dirname(__file__))
        for name in _DEFAULT_DB_BASENAMES:
            p = os.path.join(here, name)
            if os.path.isfile(p):
                return p

        # 3) Try CWD as a fallback
        for name in _DEFAULT_DB_BASENAMES:
            p = os.path.join(os.getcwd(), name)
            if os.path.isfile(p):
                return p

        # Final: we'll still return a default path; load will handle errors gracefully.
        return os.path.join(here, "mac-vendor.txt")

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._loaded:
                return
            self._map.clear()

            if not os.path.isfile(self._db_path):
                # No DB found; lookups will return "Unknown"
                self._loaded = True
                return

            # Read the DB
            with open(self._db_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("//"):
                        continue
                    # Prefer tab-split; fall back to first whitespace
                    parts = line.split("\t", 1)
                    if len(parts) == 1:
                        # allow space separated as a fallback
                        parts = line.split(None, 1)
                        if len(parts) == 1:
                            continue
                    raw_oui, vendor = parts[0].strip(), parts[1].strip()
                    # sanitize OUI like '0000C0' (6 bytes hex = 12 chars),
                    # but your file uses 6 bytes without colons.
                    oui = self._normalize_oui(raw_oui)
                    if not oui:
                        continue
                    # Keep vendor as-is (but strip trailing comments if they look like extra columns)
                    # If more columns exist, keep only the first vendor column
                    vendor = vendor.split("\t")[0].strip()
                    if not vendor:
                        continue
                    # Store uppercase hex (12 chars)
                    self._map[oui] = vendor

            self._loaded = True

    def reload(self, db_path: Optional[str] = None) -> None:
        with self._lock:
            if db_path:
                self._db_path = db_path
            self._loaded = False
            self._ensure_loaded()

    @staticmethod
    def _normalize_oui(s: str) -> Optional[str]:
        # Keep only hex chars, uppercase, then use first 6 bytes (12 hex chars)
        hex_only = "".join(ch for ch in s if ch.isalnum()).upper()
        # Accept 6 bytes (12 hex) or 3 bytes (6 hex) (some lists store 3 bytes)
        if len(hex_only) >= 12:
            return hex_only[:12]
        if len(hex_only) == 6:
            # Expand 3 bytes to 6 bytes boundary usage: treat as 3-byte OUI (still fine)
            return hex_only + "000000"[:6]  # Map 3-byte to 6-byte namespace (safe fallback)
        return None

    @staticmethod
    def _mac_to_oui(mac: str) -> Optional[str]:
        # Normalize MAC like "AA:BB:CC:DD:EE:FF" -> "AABBCC" (first 3 bytes) -> 12 hex chars
        hex_only = "".join(ch for ch in mac if ch.isalnum()).upper()
        if len(hex_only) < 6:
            return None
        # Take first 6 hex (3 bytes) and pad to 12 so we can use a single dict namespace
        base6 = hex_only[:6]
        return base6 + "000000"

    def vendor_for_mac(self, mac: str) -> str:
        if not mac:
            return "Unknown"
        oui = self._mac_to_oui(mac)
        if not oui:
            return "Unknown"
        with self._lock:
            # direct hit
            v = self._map.get(oui)
            if v:
                return v
        return "Unknown"


# Module-level singleton for super-simple usage
_VENDORS = OfflineVendors()

def vendor_for_mac(mac: str) -> str:
    """Simple function you can import in your app."""
    return _VENDORS.vendor_for_mac(mac)

def reload_db(db_path: Optional[str] = None) -> None:
    """Call this if you replace the DB file at runtime."""
    _VENDORS.reload(db_path)
