"""
core/whitelist.py — Thread-safe whitelist manager.

Loads whitelisted IPs from a plain-text file (one IP per line; '#' comments).
The Scheduler calls reload() every N seconds for hot-reloading without restart.

Usage:
    from core.whitelist import WhitelistManager
    wl = WhitelistManager("runtime/whitelist.txt")
    wl.is_whitelisted("192.168.10.1")   # → True/False
    wl.add("192.168.10.99")
    wl.reload()                          # called by Scheduler
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class WhitelistManager:
    """
    Thread-safe whitelist backed by a plain-text file.

    File format:
        192.168.10.1    # Linux Firewall
        192.168.10.12   # Monitor (this host)
        # comments and blank lines are ignored
    """

    def __init__(self, whitelist_file: str) -> None:
        self._path = Path(whitelist_file)
        self._lock = threading.RLock()
        self._ips: set[str] = set()
        self.reload()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def all(self) -> list[str]:
        with self._lock:
            return sorted(self._ips)

    # ------------------------------------------------------------------
    # Mutations (persist immediately)
    # ------------------------------------------------------------------

    def add(self, ip: str) -> None:
        with self._lock:
            self._ips.add(ip)
            self._save()
        logger.info(f"[WHITELIST] Added {ip}")

    def remove(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._ips:
                return False
            self._ips.discard(ip)
            self._save()
        logger.info(f"[WHITELIST] Removed {ip}")
        return True

    def clear(self) -> None:
        with self._lock:
            self._ips.clear()
            self._save()
        logger.info("[WHITELIST] Cleared all entries")

    # ------------------------------------------------------------------
    # Hot-reload (called by Scheduler)
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Re-read the whitelist file. Thread-safe; safe to call from any thread."""
        new_ips: set[str] = set()
        if self._path.exists():
            with open(self._path, "r", errors="ignore") as fh:
                for line in fh:
                    # Strip inline comments
                    ip = line.split("#")[0].strip()
                    if ip:
                        new_ips.add(ip)
        with self._lock:
            self._ips = new_ips
        logger.debug(f"[WHITELIST] Reloaded — {len(new_ips)} entries")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as fh:
            for ip in sorted(self._ips):
                fh.write(ip + "\n")
