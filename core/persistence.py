"""
core/persistence.py — BlockStore: persists blocked IPs to runtime/blocked.json.

The interface (is_blocked, add, remove, all, clear) is designed so that a SQLite
backend can be swapped in later by reimplementing only this file — callers are
completely unaffected.

blocked.json schema:
    [
      {
        "ip":         "192.168.10.15",
        "attack":     "SYN_FLOOD",
        "severity":   "CRITICAL",
        "confidence": 0.95,
        "reason":     "SYN_FLOOD | attacker=... victim=...",
        "timestamp":  "2025-10-14T10:53:42+00:00"
      },
      ...
    ]
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from core.events import DetectionEvent

logger = logging.getLogger(__name__)


class BlockStore:
    """
    JSON-backed store for blocked IPs.
    Thread-safe; persists immediately on every write.
    SQLite-ready: replace _load/_flush without changing any callers.
    """

    def __init__(self, blocked_file: str) -> None:
        self._path = Path(blocked_file)
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}  # ip → record
        self._load()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._records

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return sorted(
                self._records.values(),
                key=lambda r: r.get("timestamp", ""),
                reverse=True,
            )

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def add(self, event: DetectionEvent) -> None:
        """Persist a DetectionEvent. No-op if the IP is already recorded."""
        with self._lock:
            if event.attacker in self._records:
                return
            self._records[event.attacker] = {
                "ip":         event.attacker,
                "attack":     event.attack,
                "severity":   event.severity.value,
                "confidence": round(event.confidence, 4),
                "reason":     event.to_log_line(),
                "timestamp":  event.timestamp.isoformat(),
            }
            self._flush()
        logger.info(
            f"[BLOCKSTORE] Persisted {event.attacker} ({event.attack})"
        )

    def remove(self, ip: str) -> bool:
        """Remove a block record. Returns False if not found."""
        with self._lock:
            if ip not in self._records:
                return False
            del self._records[ip]
            self._flush()
        logger.info(f"[BLOCKSTORE] Removed record for {ip}")
        return True

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._flush()
        logger.info("[BLOCKSTORE] Cleared all records")

    # ------------------------------------------------------------------
    # Internal — swap these two methods for a SQLite backend
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            logger.debug(f"[BLOCKSTORE] No existing file at {self._path} — starting fresh")
            return
        try:
            with open(self._path, "r", errors="ignore") as fh:
                data: list[dict] = json.load(fh)
            for rec in data:
                self._records[rec["ip"]] = rec
            logger.info(
                f"[BLOCKSTORE] Loaded {len(self._records)} records from {self._path}"
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning(
                f"[BLOCKSTORE] Could not parse {self._path}: {exc} — starting fresh"
            )

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as fh:
            json.dump(list(self._records.values()), fh, indent=2, ensure_ascii=False)
