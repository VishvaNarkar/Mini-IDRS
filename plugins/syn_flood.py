"""
plugins/syn_flood.py — SYN Flood Detector

Uses a per-IP sliding-window deque to count bare SYN packets (SYN set, ACK
not set) destined for the victim VM. When the count reaches the configured
threshold within the window, a CRITICAL DetectionEvent is emitted and the
window is cleared to avoid repeated triggers for the same burst.

Thresholds are read from DetectionContext.thresholds on every call, so live
updates via PATCH /api/v1/config/thresholds take effect without restart.

Severity: CRITICAL — active denial-of-service; disrupts the victim service.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from core.events import DetectionEvent, Severity
from plugins.base import BaseDetector, DetectionContext


class SynFloodDetector(BaseDetector):
    """Detects TCP SYN flood attacks using a sliding time window."""

    name     = "SYN_FLOOD"
    severity = Severity.CRITICAL

    def __init__(self) -> None:
        # src_ip → deque of monotonic timestamps (one per bare SYN packet)
        self._windows: dict[str, deque] = defaultdict(deque)

    def handle_packet(
        self, pkt: Packet, ctx: DetectionContext
    ) -> Optional[DetectionEvent]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None

        ip_layer  = pkt[IP]
        tcp_layer = pkt[TCP]
        src       = ip_layer.src
        dst       = ip_layer.dst
        flags     = int(tcp_layer.flags)

        if src in ctx.whitelist or src == ctx.monitor_ip:
            return None

        # Only bare SYNs (SYN set, ACK not set) destined for the Victim VM
        is_bare_syn = (flags & 0x02) and not (flags & 0x10)
        if not is_bare_syn or dst != ctx.victim_ip:
            return None

        cfg_thresholds = ctx.thresholds.get("syn_flood", {})
        threshold      = cfg_thresholds.get("threshold", 25)
        window_secs    = cfg_thresholds.get("window_seconds", 5)
        now            = time.monotonic()

        dq = self._windows[src]
        dq.append(now)
        # Evict timestamps outside the sliding window
        while dq and dq[0] < now - window_secs:
            dq.popleft()

        count = len(dq)
        if count >= threshold:
            dq.clear()   # Reset to prevent repeated triggers on the same burst
            return DetectionEvent(
                attack     = self.name,
                attacker   = src,
                victim     = dst,
                severity   = self.severity,
                confidence = min(1.0, count / threshold),
                details    = {
                    "packet_count":   count,
                    "window_seconds": window_secs,
                    "threshold":      threshold,
                },
            )

        return None

    def reset(self, ip: str | None = None) -> None:
        if ip is None:
            self._windows.clear()
        else:
            self._windows.pop(ip, None)
