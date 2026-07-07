"""
plugins/xmas_scan.py — XMAS Scan Detector

Detects TCP packets with FIN + URG + PSH flags set simultaneously.
This is the classic nmap -sX fingerprint and is unambiguous when all
three flags appear together on a single packet.

Severity: LOW — reconnaissance only; no direct service disruption.
Confidence: 1.0 — the flag combination is unambiguous.
"""
from __future__ import annotations

from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from core.events import DetectionEvent, Severity
from plugins.base import BaseDetector, DetectionContext

# FIN (0x01) | PSH (0x08) | URG (0x20) = 0x29
_XMAS_FLAGS = 0x29


class XmasScanDetector(BaseDetector):
    """Detects TCP XMAS (FIN+PSH+URG) scan packets."""

    name     = "XMAS_SCAN"
    severity = Severity.LOW

    def handle_packet(
        self, pkt: Packet, ctx: DetectionContext
    ) -> Optional[DetectionEvent]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None

        ip_layer  = pkt[IP]
        tcp_layer = pkt[TCP]
        src       = ip_layer.src

        # Skip whitelisted sources and the monitor itself
        if src in ctx.whitelist or src == ctx.monitor_ip:
            return None

        if int(tcp_layer.flags) == _XMAS_FLAGS:
            return DetectionEvent(
                attack     = self.name,
                attacker   = src,
                victim     = ip_layer.dst,
                severity   = self.severity,
                confidence = 1.0,
                details    = {"flags": hex(_XMAS_FLAGS)},
            )

        return None

    # Stateless — no reset() needed
