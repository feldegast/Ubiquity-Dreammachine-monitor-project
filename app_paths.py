# app_paths.py
from pathlib import Path

# =============================================================================
# FILE PATH CONSTANTS (single source of truth)
# =============================================================================

# Base dirs
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Config & SSH secrets
CONFIG_FILE      = BASE_DIR / "config.json"           # same folder as main.py
SSH_SECRETS_FILE = DATA_DIR / "ssh_secrets.json"      # runtime secret, under data/

# Logs
LOG_FILENAME       = DATA_DIR / "traffic_log.csv"
ALERT_LOG_FILENAME = DATA_DIR / "alerts_log.csv"

# Vendor resolver

# Downloaded OUI database (TAB-separated) — read-only, shipped with the app
# Lives next to main.py / vendor_resolver.py.
BASE_OUI_FILE = BASE_DIR / "mac-vendor.txt"

# Vendor enrichment overrides (OUI / full-MAC → vendor), CSV-based
OVERRIDE_OUI_FILE = DATA_DIR / "mac-vendor-overrides.txt"

# Labelled hosts → green square
HOST_ALIAS_PATH = DATA_DIR / "local_ip_labels.json"
MAC_LABELS_PATH = DATA_DIR / "local_mac_labels.json"
