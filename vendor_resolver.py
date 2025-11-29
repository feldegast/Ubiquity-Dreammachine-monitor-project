from __future__ import annotations

import re
from typing import Dict, Optional

from app_paths import BASE_OUI_FILE, OVERRIDE_OUI_FILE

# =============================================================================
# SECTION: VENDOR RESOLVER (MAC → Vendor/OUI lookup)
# =============================================================================
# region VENDOR RESOLVER

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

# Match two consecutive hex characters (one byte)
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}")


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Best-effort normalisation of a MAC string.

    * Extracts hex pairs from any separator style (':', '-', '.', spaces, etc)
    * Upper-cases everything
    * Returns the first 6 bytes as 'AA:BB:CC:DD:EE:FF'
    """
    if not mac:
        return None

    hex_pairs = _MAC_RE.findall(mac)
    if len(hex_pairs) < 3:  # need at least an OUI (3 bytes)
        return None

    # At most 6 bytes (standard MAC length)
    hex_pairs = hex_pairs[:6]
    return ":".join(p.upper() for p in hex_pairs)


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Public wrapper so other modules can import a single normaliser."""
    return _normalize_mac(mac)


def _normalize_oui(raw: str) -> Optional[str]:
    """Normalise an OUI string to 'AA:BB:CC'.

    Accepts formats like:
      - 'D8:5E:D3'
      - 'D8-5E-D3'
      - 'D85ED3'
      - 'd8:5e:d3'
    """
    if not raw:
        return None

    # Extract hex digits only
    hex_digits = re.findall(r"[0-9A-Fa-f]", raw)
    if len(hex_digits) < 6:
        return None

    # First 3 bytes (6 hex chars)
    first_six = hex_digits[:6]
    pairs = [
        "".join(first_six[i : i + 2]).upper()
        for i in range(0, 6, 2)
    ]
    return ":".join(pairs)


def _oui_from_normalized_mac(mac_norm: str) -> str:
    """Given a normalised MAC 'AA:BB:CC:DD:EE:FF', return its OUI 'AA:BB:CC'."""
    parts = mac_norm.split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else mac_norm


# Locally administered bit: second least-significant bit of the first octet.
# If that bit is 1, the MAC is "locally administered" (not a globally unique OUI).
def _is_locally_administered(mac: Optional[str]) -> bool:
    """Return True if the MAC is locally administered (U/L bit set)."""
    mac_norm = _normalize_mac(mac)
    if not mac_norm:
        return False

    first_octet = mac_norm.split(":", 1)[0]
    try:
        value = int(first_octet, 16)
    except ValueError:
        return False

    # U/L bit is bit 1 of the first octet (0x02)
    return bool(value & 0x02)


# ---------------------------------------------------------------------------
# OUI file loaders
# ---------------------------------------------------------------------------

def _load_oui_file(path) -> Dict[str, str]:
    """Load an OUI → Vendor mapping from a text file.

    Expected format per line (TAB *or* spaces between OUI and vendor):

        <OUI><whitespace><Vendor name>

    Examples:

        000000    Xerox Corp
        D85ED3\tGIGA-BYTE TECHNOLOGY CO., LTD.
        AABBCC    Some Company

    * Lines starting with '#' are ignored.
    * OUI can be 'D8:5E:D3', 'D8-5E-D3', 'D85ED3', etc.
    * Multiple spaces or tabs between OUI and name are fine.
    """
    mapping: Dict[str, str] = {}

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Split on first run of whitespace (tabs or spaces)
                parts = re.split(r"\s+", line, maxsplit=1)
                if len(parts) < 2:
                    continue

                raw_oui = parts[0].strip()
                vendor = parts[1].strip()
                if not raw_oui or not vendor:
                    continue

                oui = _normalize_oui(raw_oui)
                if not oui:
                    continue

                mapping[oui] = vendor
    except FileNotFoundError:
        # Missing file is OK – you'll just get 'Unknown' for those OUIs.
        pass

    return mapping


def _build_vendor_map() -> Dict[str, str]:
    """Build the final OUI → Vendor mapping.

    1. Load the base OUI database (mac-vendor.txt)
    2. Apply overrides from mac-vendor-overrides.txt (overrides win)
    """
    base = _load_oui_file(BASE_OUI_FILE)
    overrides = _load_oui_file(OVERRIDE_OUI_FILE)

    # Apply overrides last so they take precedence
    base.update(overrides)
    return base


# Single in-memory map used by all lookups
_VENDOR_BY_OUI: Dict[str, str] = _build_vendor_map()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def vendor_for_mac(mac: Optional[str]) -> str:
    """Return the best-guess vendor name for a MAC address.

    * Normalises the MAC (AA:BB:CC:DD:EE:FF)
    * Derives its OUI (AA:BB:CC)
    * Looks up in:
        - mac-vendor.txt
        - mac-vendor-overrides.txt
    * Returns 'Unknown' if nothing matches
    """
    mac_norm = _normalize_mac(mac)
    if not mac_norm:
        return "Unknown"

    oui = _oui_from_normalized_mac(mac_norm)
    return _VENDOR_BY_OUI.get(oui, "Unknown")


# endregion VENDOR RESOLVER
