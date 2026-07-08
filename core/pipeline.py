"""
core/pipeline.py — EventPipeline

The single wiring point for all downstream consumers of a DetectionEvent.
Both live packet capture (PacketCapture) and the PCAP replay tool (tools/replay.py)
call pipeline.process() — ensuring identical behaviour in both modes.

Processing order for each DetectionEvent:
  1. Whitelist check — skip if IP is whitelisted
  2. Duplicate check — skip if IP is already in BlockStore
  3. Logger          — write to ids.log at the matching severity level
  4. BlockStore      — persist to runtime/blocked.json
  5. FirewallManager — POST /api/v1/rules to Firewall API → nftables FORWARD DROP
  6. VictimBlocker   — SSH to Victim VM → iptables INPUT DROP
  7. on_event cb     — optional callback for callers needing live notification
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from core.events import DetectionEvent
from core.firewall import FirewallManager
from core.logger import log_event
from core.persistence import BlockStore
from core.victim import VictimBlocker
from core.whitelist import WhitelistManager

logger = logging.getLogger(__name__)


class EventPipeline:
    """
    Routes a DetectionEvent through all downstream consumers.

    Args:
        on_event: Optional callback invoked after all other consumers.
                  Use it to push live events to an in-memory cache
                  (e.g. the IDS API's recent-events deque) when the
                  monitor and API run in the same process.
    """

    def __init__(
        self,
        whitelist_mgr:  WhitelistManager,
        block_store:    BlockStore,
        firewall_mgr:   FirewallManager,
        victim_blocker: VictimBlocker,
        on_event:       Optional[Callable[[DetectionEvent], None]] = None,
    ) -> None:
        self._whitelist = whitelist_mgr
        self._blocks    = block_store
        self._firewall  = firewall_mgr
        self._victim    = victim_blocker
        self._on_event  = on_event

    def process(self, event: DetectionEvent) -> bool:
        """
        Process one DetectionEvent through the full pipeline.
        Returns True if the event was acted upon, False if skipped.
        """
        attacker = event.attacker

        # 1 — Whitelist check
        if self._whitelist.is_whitelisted(attacker):
            logger.debug(f"[PIPELINE] Skip {attacker} — whitelisted")
            return False

        # 2 — Duplicate check
        if self._blocks.is_blocked(attacker):
            logger.debug(f"[PIPELINE] Skip {attacker} — already blocked")
            return False

        # 3 — Log
        log_event(event)

        # 4 — Linux Firewall: FORWARD DROP via Firewall REST API → nftables
        fw_ok = self._firewall.block(attacker)
        logger.info(
            f"[PIPELINE] Firewall block({attacker}) → {'ok' if fw_ok else 'FAILED'}"
        )

        # 6 — Victim VM: INPUT DROP via SSH → iptables
        victim_ok = self._victim.block(attacker)
        logger.info(
            f"[PIPELINE] Victim block({attacker}) → {'ok' if victim_ok else 'FAILED'}"
        )

        logger.info(
            f"[PIPELINE] {event.attack} | {attacker} → "
            f"firewall={'ok' if fw_ok else 'FAIL'} "
            f"victim={'ok' if victim_ok else 'FAIL'}"
        )

        # 6b — Persist only if at least one enforcement layer succeeded
        if not (fw_ok or victim_ok):
            logger.error(
                f"[PIPELINE] Skipping persistence for {attacker} — all blockers failed"
            )
            return False
        self._blocks.add(event, firewall_blocked=fw_ok, victim_blocked=victim_ok)

        # 7 — Optional callback
        if self._on_event:
            try:
                self._on_event(event)
            except Exception as exc:
                logger.warning(f"[PIPELINE] on_event callback error: {exc}")

        # 8 — Notify IDS API of the new event (non-blocking thread)
        self._notify_api(event)

        return True

    def _notify_api(self, event: DetectionEvent) -> None:
        import threading
        from core.config import cfg
        import requests

        def run():
            # Use localhost to hit the local IDS API instance
            url = f"http://127.0.0.1:{cfg.ids_api.port}/api/v1/events"
            headers = {
                "X-API-Key": cfg.ids_api.api_key,
                "Content-Type": "application/json"
            }
            try:
                # low timeout to prevent hanging
                requests.post(url, json=event.to_dict(), headers=headers, timeout=2)
            except Exception as exc:
                logger.debug(f"[PIPELINE] Failed to notify IDS API: {exc}")

        threading.Thread(target=run, daemon=True).start()

