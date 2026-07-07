"""
plugins/base.py — BaseDetector ABC and DetectionContext.

All detection plugins must subclass BaseDetector and implement handle_packet().
DetectionContext carries shared state (victim IP, whitelist, live thresholds)
without coupling plugins to the global config singleton.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from scapy.packet import Packet

from core.events import DetectionEvent, Severity


@dataclass
class DetectionContext:
    """
    Shared mutable state passed to every plugin on each packet call.

    thresholds: live-updated by the Scheduler when runtime/thresholds.json changes
                (written by IDS API PATCH /api/v1/config/thresholds).
    whitelist:  hot-reloaded from runtime/whitelist.txt by the Scheduler.
    """
    victim_ip:  str
    monitor_ip: str
    thresholds: dict             # {"syn_flood": {"threshold": 25, ...}, ...}
    whitelist:  set[str] = field(default_factory=set)


class BaseDetector(ABC):
    """
    Abstract base for all detection plugins.

    Contract:
        - Declare class attributes `name` (str) and `severity` (Severity).
        - Implement handle_packet() — return a DetectionEvent or None.
        - Optionally override reset() to clear per-IP sliding-window state.

    Adding a new detector:
        1. Create plugins/<name>.py
        2. Subclass BaseDetector
        3. Register it in idrs_monitor.py (plugins list)
        See docs/development.md for a step-by-step guide.
    """
    name:     str      # e.g. "SYN_FLOOD"
    severity: Severity

    @abstractmethod
    def handle_packet(
        self, pkt: Packet, ctx: DetectionContext
    ) -> Optional[DetectionEvent]:
        """
        Inspect one raw packet.
        Return a DetectionEvent if an attack is detected, else None.
        Must not raise; exceptions are caught by PacketCapture.
        """
        ...

    def reset(self, ip: str | None = None) -> None:
        """
        Clear internal state.
        ip=None  → clear state for ALL tracked IPs.
        ip=<x>   → clear state only for that IP (called on unblock).
        Default implementation is a no-op for stateless detectors.
        """
