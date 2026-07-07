"""
plugins/ssh_brute_force.py — SSH Brute-Force Detector

Tracks completed TCP 3-way handshakes on port 22 per source IP using a
sliding-window deque. A completed handshake (SYN → SYN-ACK → ACK) counts
as one connection attempt. When the count reaches the configured threshold
within the window, a HIGH DetectionEvent is emitted.

Bug fix vs original idrs_monitor.py:
    The original had a dead code path where the second `if flags & 0x02`
    check (line 182) was unreachable because the SYN-flood handler returned
    early for ALL bare SYNs destined to VICTIM_IP (line 178), preventing
    any SSH handshake tracking for victim-destined traffic.

    Fix: this plugin runs completely independently of SynFloodDetector.
    Both plugins receive every packet from PacketCapture. This plugin
    tracks SYNs to port 22 regardless of whether SynFloodDetector also
    saw the same packet.

Severity: HIGH — active credential attack against the victim SSH service.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from core.events import DetectionEvent, Severity
from plugins.base import BaseDetector, DetectionContext

_SSH_PORT = 22


class SshBruteForceDetector(BaseDetector):
    """Detects SSH brute-force by tracking completed TCP handshakes on port 22."""

    name     = "SSH_BRUTE_FORCE"
    severity = Severity.HIGH

    def __init__(self) -> None:
        # (src_ip, dst_ip, dst_port) → deque of SYN timestamps (pending half-opens)
        self._syn_pending: dict[tuple, deque] = defaultdict(deque)
        # src_ip → deque of completed-handshake timestamps
        self._handshake_windows: dict[str, deque] = defaultdict(deque)

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
        dport     = tcp_layer.dport
        sport     = tcp_layer.sport
        now       = time.monotonic()

        if src in ctx.whitelist or src == ctx.monitor_ip:
            return None

        # Step 1 — SYN seen (no ACK): record a pending entry for port-22 connections
        if (flags & 0x02) and not (flags & 0x10):
            if dport == _SSH_PORT:
                self._syn_pending[(src, dst, dport)].append(now)
            return None

        # Step 2 — SYN-ACK seen: server responded, confirm the half-open entry
        if (flags & 0x12) == 0x12:
            key = (dst, src, sport)   # reversed direction: original client → server key
            if key in self._syn_pending:
                self._syn_pending[key].append(now)
            return None

        # Step 3 — Final ACK on port 22: count as a completed handshake
        if (flags & 0x10) and not (flags & 0x02):
            key = (src, dst, dport)
            if dport == _SSH_PORT and key in self._syn_pending:
                # Pop one pending SYN to represent one completed handshake
                if self._syn_pending[key]:
                    self._syn_pending[key].popleft()
                    if not self._syn_pending[key]:
                        self._syn_pending.pop(key, None)

                cfg_thresholds = ctx.thresholds.get("ssh_brute_force", {})
                threshold      = cfg_thresholds.get("threshold", 8)
                window_secs    = cfg_thresholds.get("window_seconds", 60)

                dq = self._handshake_windows[src]
                dq.append(now)
                while dq and dq[0] < now - window_secs:
                    dq.popleft()

                count = len(dq)
                if count >= threshold:
                    dq.clear()
                    return DetectionEvent(
                        attack     = self.name,
                        attacker   = src,
                        victim     = dst,
                        severity   = self.severity,
                        confidence = min(1.0, count / threshold),
                        details    = {
                            "handshake_count": count,
                            "window_seconds":  window_secs,
                            "threshold":       threshold,
                        },
                    )

        return None

    def reset(self, ip: str | None = None) -> None:
        if ip is None:
            self._syn_pending.clear()
            self._handshake_windows.clear()
        else:
            # Remove all pending entries originating from this IP
            to_del = [k for k in self._syn_pending if k[0] == ip]
            for k in to_del:
                del self._syn_pending[k]
            self._handshake_windows.pop(ip, None)
