"""
core/packet_capture.py — Packet capture and plugin dispatcher.

Wraps scapy.sniff() in a class, dispatches each packet to every registered
plugin, and passes any DetectionEvent returned to the EventPipeline.

Runs in the foreground (blocks until KeyboardInterrupt or interface error).
The Scheduler runs concurrently in a background thread.
"""
from __future__ import annotations

import logging
import sys

from scapy.all import get_if_list, sniff
from scapy.packet import Packet

from core.pipeline import EventPipeline
from plugins.base import BaseDetector, DetectionContext

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Manages raw packet sniffing and routes each packet through all plugins.

    Each plugin independently inspects the packet and returns either a
    DetectionEvent or None. Events are forwarded to the EventPipeline.
    Plugin exceptions are caught and logged without stopping capture.
    """

    def __init__(
        self,
        plugins:  list[BaseDetector],
        context:  DetectionContext,
        pipeline: EventPipeline,
    ) -> None:
        self._plugins  = plugins
        self._context  = context
        self._pipeline = pipeline

    def start(self, iface: str) -> None:
        """
        Begin sniffing on the given interface. Blocks until interrupted.
        Requires root/sudo privileges (raw socket access).
        """
        logger.info(f"[CAPTURE] Starting on interface '{iface}'")
        logger.info(
            f"[CAPTURE] Active plugins: {[p.name for p in self._plugins]}"
        )
        logger.info(
            f"[CAPTURE] Monitoring victim={self._context.victim_ip} "
            f"monitor={self._context.monitor_ip}"
        )
        try:
            sniff(iface=iface, prn=self._dispatch, store=False)
        except OSError as exc:
            logger.error(f"[CAPTURE] Cannot open interface '{iface}': {exc}")
            logger.error(f"[CAPTURE] Available interfaces: {get_if_list()}")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("[CAPTURE] Stopped (KeyboardInterrupt)")
            sys.exit(0)

    # ------------------------------------------------------------------
    # Internal — Scapy callback
    # ------------------------------------------------------------------

    def _dispatch(self, pkt: Packet) -> None:
        """Dispatch one raw packet to every registered plugin."""
        for plugin in self._plugins:
            try:
                event = plugin.handle_packet(pkt, self._context)
                if event is not None:
                    self._pipeline.process(event)
            except Exception as exc:
                logger.exception(
                    f"[CAPTURE] Unhandled exception in plugin {plugin.name}: {exc}"
                )
