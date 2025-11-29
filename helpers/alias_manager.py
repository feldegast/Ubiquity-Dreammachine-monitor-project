from pathlib import Path
import json


class AliasManager:
    """
    Centralised resolver for:
      • custom IP → device label
      • custom MAC → device label
      • JSON-backed persistence
    """

    def __init__(self, ip_path: Path, mac_path: Path):
        self.ip_path = ip_path
        self.mac_path = mac_path
        self.ip_labels = self._load_json(ip_path)
        self.mac_labels = self._load_json(mac_path)

    # ---- JSON helpers -----------------------------------------------------
    
    # =============================================================================
    # SECTION: JSON helpers
    # =============================================================================
    # region JSON helpers

    def _load_json(self, path: Path) -> dict[str, str]:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf8"))
        except Exception:
            pass
        return {}

    def _save_json(self, path: Path, data: dict[str, str]) -> None:
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf8")
        except Exception:
            pass
    # endregion JSON helpers

    # =============================================================================
    # SECTION: IP label handling
    # =============================================================================
    # region IP label handling

    def name_for_ip(self, ip: str) -> str | None:
        """Return custom label for an IP, or None."""
        return self.ip_labels.get(ip)

    def set_name_for_ip(self, ip: str, name: str | None):
        if name:
            self.ip_labels[ip] = name
        else:
            self.ip_labels.pop(ip, None)
        self._save_json(self.ip_path, self.ip_labels)

    # endregion IP label handling
    
    # =============================================================================
    # SECTION: MAC label handling
    # =============================================================================
    # region MAC label handling

    def label_for_mac(self, mac: str) -> str | None:
        return self.mac_labels.get(mac.upper())

    def set_label_for_mac(self, mac: str, name: str | None):
        mac = mac.upper()
        if name:
            self.mac_labels[mac] = name
        else:
            self.mac_labels.pop(mac, None)
        self._save_json(self.mac_path, self.mac_labels)

    # endregion MAC label handling

    # =============================================================================
    # SECTION: Convenience
    # =============================================================================
    # region Convenience

    @staticmethod
    def ip_from_hostport(hostport: str) -> str:
        """Extract '192.168.1.50' from '192.168.1.50:443'."""
        if not hostport:
            return ""
        return hostport.split(":", 1)[0]
    
    # endregion Convenience

# endregion ALIAS_MANAGER