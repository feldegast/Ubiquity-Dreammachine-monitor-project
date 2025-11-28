from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional

# =============================================================================
# SECTION: VENDOR RESOLVER (MAC → Vendor/OUI lookup)
# =============================================================================
# region VENDOR RESOLVER

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Downloaded OUI database (TAB-separated)
BASE_OUI_FILE = DATA_DIR / "mac-vendor.txt"

# Local overrides (CSV: OUI,Vendor Name...) – only first comma is significant
OVERRIDE_OUI_FILE = DATA_DIR / "mac-vendor-overrides.txt"

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

# Match two consecutive hex characters (one byte)
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}")


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Best-effort normalisation of a MAC string.

    * Extracts hex pairs from any separator style (':', '-', '.', spaces)
    * Upper-cases everything
    * Returns the first 6 bytes as 'AA:BB:CC:DD:EE:FF'
    """
    if not mac:
        return None

    # Grab raw hex pairs
    hex_pairs = _MAC_RE.findall(mac)
    if len(hex_pairs) < 3:  # need at least an OUI (3 bytes)
        return None

    # We keep up to 6 bytes – extra pairs (in weird formats) are ignored
    pairs = [p.upper() for p in hex_pairs[:6]]
    return ":".join(pairs)


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
    """Return the OUI part ('AA:BB:CC') from a normalised MAC."""
    parts = mac_norm.split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else mac_norm


def _is_locally_administered(mac_norm: Optional[str]) -> bool:
    """Return True if the MAC is locally administered (LAA).

    We look at the second least significant bit of the first byte.
    (See IEEE 802 MAC address format).
    """
    if not mac_norm:
        return False

    first_octet = mac_norm.split(":", 1)[0]
    try:
        b0 = int(first_octet, 16)
    except ValueError:
        return False

    return bool(b0 & 0x02)


# ---------------------------------------------------------------------------
# Loading OUI → Vendor mappings
# ---------------------------------------------------------------------------

def _load_base_ouis(path: Path) -> Dict[str, str]:
    """Load the downloaded TAB-delimited OUI database.

    Expected format per line:
        <OUI>\t<Vendor name>

    * Lines starting with '#' are ignored
    * OUI can be either 'D8:5E:D3', 'D8-5E-D3', 'D85ED3', etc.
    """
    mapping: Dict[str, str] = {}

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("\t")
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
        # It's fine – you'll just see 'Unknown' everywhere until the file exists
        pass

    return mapping


def _load_override_ouis(path: Path) -> Dict[str, str]:
    """Load local CSV overrides: 'OUI,Vendor Name...'.

    Only the FIRST comma is treated as a separator so that vendor names
    can contain commas, e.g.:

        D8:5E:D3,GIGA-BYTE TECHNOLOGY CO., LTD.
    """
    mapping: Dict[str, str] = {}

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                # Only first comma is significant
                if "," not in line:
                    continue

                prefix, vendor_raw = line.split(",", 1)
                raw_oui = prefix.strip()
                vendor = vendor_raw.strip()

                if not raw_oui or not vendor:
                    continue

                oui = _normalize_oui(raw_oui)
                if not oui:
                    continue

                mapping[oui] = vendor
    except FileNotFoundError:
        # Optional file – ignore if missing
        pass

    return mapping


def _build_vendor_map() -> Dict[str, str]:
    """Build the final OUI → Vendor mapping.

    1. Load the base TAB-delimited database (mac-vendor.txt)
    2. Apply CSV overrides from mac-vendor-overrides.txt (overrides win)
    """
    base = _load_base_ouis(BASE_OUI_FILE)
    overrides = _load_override_ouis(OVERRIDE_OUI_FILE)

    # Apply overrides last so they take precedence
    base.update(overrides)
    return base


# Single in-memory map used by all lookups
_VENDOR_BY_OUI: Dict[str, str] = _build_vendor_map()


def vendor_for_mac(mac: Optional[str]) -> str:
    """Return the best-guess vendor name for a MAC address.

    * Normalises the MAC
    * Extracts its OUI ('AA:BB:CC')
    * Looks up in:
        - data/mac-vendor.txt               (TAB-delimited)
        - data/mac-vendor-overrides.txt     (CSV, OUI,Vendor Name...)
    * Returns 'Unknown' if nothing matches
    """
    mac_norm = _normalize_mac(mac)
    if not mac_norm:
        return "Unknown"

    oui = _oui_from_normalized_mac(mac_norm)
    return _VENDOR_BY_OUI.get(oui, "Unknown")


# endregion VENDOR RESOLVER
