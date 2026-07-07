"""
core/scheduler.py — APScheduler wrapper for periodic maintenance tasks.

Runs as a background thread alongside PacketCapture.
Jobs are configurable via config.yaml (scheduler section).

Jobs:
  health_check       — GET /api/v1/health on Firewall API; logs if unreachable
  reload_whitelist   — hot-reload runtime/whitelist.txt
  reload_thresholds  — hot-reload runtime/thresholds.json (written by IDS API PATCH)
  aggregate_stats    — count events by type/severity → runtime/stats.json
  cleanup_blocks     — placeholder for future TTL-based block expiry
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
from apscheduler.schedulers.background import BackgroundScheduler

from core.persistence import BlockStore
from core.whitelist import WhitelistManager
from plugins.base import DetectionContext

logger = logging.getLogger(__name__)


class IDRSScheduler:
    """
    Background scheduler for Mini-IDRS maintenance tasks.

    All jobs run on a dedicated APScheduler thread. The main thread is
    occupied by PacketCapture (Scapy sniff loop), which is single-threaded
    by design. Thread safety for shared objects (WhitelistManager,
    BlockStore) is handled internally by those classes.
    """

    def __init__(
        self,
        *,
        firewall_api_url:          str,
        firewall_api_key:          str,
        whitelist_mgr:             WhitelistManager,
        block_store:               BlockStore,
        detection_context:         DetectionContext,
        thresholds_file:           str,
        stats_file:                str,
        health_check_interval:     int = 60,
        whitelist_reload_interval: int = 30,
        thresholds_reload_interval:int = 30,
        stats_interval:            int = 300,
        block_cleanup_hours:       int = 1,
    ) -> None:
        self._fw_url           = firewall_api_url
        self._fw_headers       = {"X-API-Key": firewall_api_key}
        self._whitelist        = whitelist_mgr
        self._block_store      = block_store
        self._ctx              = detection_context
        self._thresholds_file  = Path(thresholds_file)
        self._stats_file       = Path(stats_file)

        self._sched = BackgroundScheduler(timezone="UTC")

        self._sched.add_job(
            self._health_check,
            "interval",
            seconds=health_check_interval,
            id="health_check",
        )
        self._sched.add_job(
            self._reload_whitelist,
            "interval",
            seconds=whitelist_reload_interval,
            id="reload_whitelist",
        )
        self._sched.add_job(
            self._reload_thresholds,
            "interval",
            seconds=thresholds_reload_interval,
            id="reload_thresholds",
        )
        self._sched.add_job(
            self._aggregate_stats,
            "interval",
            seconds=stats_interval,
            id="aggregate_stats",
        )
        self._sched.add_job(
            self._cleanup_blocks,
            "interval",
            hours=block_cleanup_hours,
            id="cleanup_blocks",
        )

    def start(self) -> None:
        self._sched.start()
        logger.info(
            "[SCHEDULER] Started — jobs: health_check, reload_whitelist, "
            "reload_thresholds, aggregate_stats, cleanup_blocks"
        )

    def shutdown(self) -> None:
        self._sched.shutdown(wait=False)
        logger.info("[SCHEDULER] Stopped")

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    def _health_check(self) -> None:
        try:
            resp = requests.get(
                f"{self._fw_url}/api/v1/health",
                headers=self._fw_headers,
                timeout=5,
            )
            if resp.status_code == 200:
                logger.debug("[HEALTH] Firewall API reachable")
            else:
                logger.warning(
                    f"[HEALTH] Firewall API returned {resp.status_code}"
                )
        except Exception as exc:
            logger.error(f"[HEALTH] Firewall API unreachable: {exc}")

    def _reload_whitelist(self) -> None:
        self._whitelist.reload()
        # Keep the DetectionContext whitelist set in sync
        self._ctx.whitelist = set(self._whitelist.all())

    def _reload_thresholds(self) -> None:
        """
        Read runtime/thresholds.json (written by IDS API PATCH /api/v1/config/thresholds)
        and update the live DetectionContext thresholds dict in place.
        """
        if not self._thresholds_file.exists():
            return
        try:
            with open(self._thresholds_file) as fh:
                new_thresholds: dict = json.load(fh)
            self._ctx.thresholds.update(new_thresholds)
            logger.debug(f"[SCHEDULER] Thresholds reloaded: {new_thresholds}")
        except Exception as exc:
            logger.warning(f"[SCHEDULER] Could not reload thresholds: {exc}")

    def _aggregate_stats(self) -> None:
        records       = self._block_store.all()
        attack_counts = Counter(r.get("attack", "UNKNOWN") for r in records)
        sev_counts    = Counter(r.get("severity", "UNKNOWN") for r in records)
        stats = {
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "total_blocked":  len(records),
            "by_attack_type": dict(attack_counts),
            "by_severity":    dict(sev_counts),
        }
        self._stats_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._stats_file, "w") as fh:
            json.dump(stats, fh, indent=2)
        logger.debug(f"[STATS] Aggregated and written to {self._stats_file}")

    def _cleanup_blocks(self) -> None:
        # Reserved for future TTL-based block expiry.
        # When blocks gain a TTL field, this job will iterate records
        # and call block_store.remove() + firewall_mgr.unblock() for expired ones.
        logger.debug("[CLEANUP] Block cleanup job ran — no TTL configured yet")
