from pathlib import Path


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