# vendor_resolver.py
from __future__ import annotations
from pathlib import Path
from typing import Optional

# Optional deps: install with
#   pip install mac-vendor-lookup manuf aiofiles
#
# This module:
# - Normalizes MACs
# - Uses local overrides first
# - Optionally labels LAA ("Randomized (LAA)")
# - Falls back: mac-vendor-lookup -> manuf -> "Unknown"
# - Safe update of mac-vendor-lookup cache on Windows (creates ~/.cache)

try:
    from mac_vendor_lookup import MacLookup
except Exception:  # pragma: no cover
    MacLookup = None  # type: ignore

try:
    from manuf import manuf as manuf_mod
except Exception:  # pragma: no cover
    manuf_mod = None  # type: ignore

# --- Configuration ----------------------------------------------------------

# Local vendor overrides by OUI (first 3 octets, uppercase with colons)
LOCAL_OUI_OVERRIDES = {
    "6C:1F:F7": "Ugreen Group Limited",
    "B0:F7:C4": "Amazon Technologies Inc.",
    # If you want Samsung to show even though it's LAA:
    # "52:6D:8F": "Samsung Electronics",
}

# Prefer to label LAA addresses as randomized rather than vendor name
PREFER_LAA_LABEL = True

# What to display when no vendor is known
UNKNOWN_LABEL = "Unknown"


# --- Utilities --------------------------------------------------------------

def _normalize_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    mac = mac.strip().upper().replace("-", ":")
    # pad single-octet forms etc.; ensure colon-separated hex pairs
    if ":" not in mac and len(mac) in (12, 16):  # 12 = 6 bytes, 16 = 8 bytes
        mac = ":".join(mac[i:i+2] for i in range(0, len(mac), 2))
    return mac


def _oui(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def _is_locally_administered(mac: str) -> bool:
    mac = _normalize_mac(mac)
    if len(mac) < 2 or ":" not in mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return (first_octet & 0x02) != 0  # LAA bit set
    except Exception:
        return False


# --- Resolver ---------------------------------------------------------------

class _VendorResolver:
    def __init__(self) -> None:
        self._ml = None
        if MacLookup is not None:
            try:
                self._ml = MacLookup()
            except Exception:
                self._ml = None

        self._manuf = None
        if manuf_mod is not None:
            try:
                self._manuf = manuf_mod.MacParser()
            except Exception:
                self._manuf = None

    def update_now(self, silent: bool = True) -> bool:
        """
        Refresh mac-vendor-lookup local DB; returns True on success.
        Creates ~/.cache on Windows if missing to avoid FileNotFoundError.
        """
        if self._ml is None:
            if not silent:
                print("[vendor] mac-vendor-lookup not available")
            return False
        try:
            # Ensure cache dir exists (mac-vendor-lookup uses ~/.cache/mac-vendors.txt)
            cache_dir = Path.home() / ".cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            # Do the update
            self._ml.update_vendors()
            if not silent:
                print("[vendor] vendor DB updated")
            return True
        except Exception as e:
            if not silent:
                print(f"[vendor] update failed: {e}")
            return False

    def for_mac(self, mac: Optional[str]) -> str:
        """
        Return best-guess vendor for a MAC (no LAA labeling).
        """
        mac_n = _normalize_mac(mac)
        if not mac_n:
            return UNKNOWN_LABEL

        # 1) Local overrides
        oui = _oui(mac_n)
        if oui in LOCAL_OUI_OVERRIDES:
            return LOCAL_OUI_OVERRIDES[oui]

        # 2) mac-vendor-lookup
        if self._ml is not None:
            try:
                name = self._ml.lookup(mac_n)  # raises if not found
                if name:
                    return str(name)
            except Exception:
                pass

        # 3) manuf fallback
        if self._manuf is not None:
            try:
                name = self._manuf.get_manuf(mac_n)
                if name:
                    return str(name)
            except Exception:
                pass

        return UNKNOWN_LABEL

    def for_display(self, mac: Optional[str]) -> str:
        """
        Preferred label for UI: LAA gets 'Randomized (LAA)' if enabled, else vendor.
        """
        mac_n = _normalize_mac(mac)
        if not mac_n:
            return UNKNOWN_LABEL

        if PREFER_LAA_LABEL and _is_locally_administered(mac_n):
            return "Randomized (LAA)"

        return self.for_mac(mac_n)

    # --- Backwards-compat shims ------------------------------------
    def vendor_for_mac(self, mac: str | None) -> str:
        """Compat: old code expects a .vendor_for_mac() method."""
        return self.for_mac(mac)

    def vendor_for_display(self, mac: str | None) -> str:
        """Compat: old code expects a .vendor_for_display() method."""
        return self.for_display(mac)
    
# Singleton
_RESOLVER = _VendorResolver()


# --- Public API -------------------------------------------------------------

def update_vendor_db_now(silent: bool = True) -> bool:
    """Call once at startup if you want to refresh the local DB."""
    return _RESOLVER.update_now(silent=silent)


def vendor_for_mac(mac: Optional[str]) -> str:
    """Return vendor name (no LAA labeling)."""
    return _RESOLVER.for_mac(mac)


def vendor_for_display(mac: Optional[str]) -> str:
    """Return UI-preferred label (LAA shown as 'Randomized (LAA)')."""
    return _RESOLVER.for_display(mac)


# Back-compat: some code calls lookup_vendor(...)
lookup_vendor = vendor_for_display
