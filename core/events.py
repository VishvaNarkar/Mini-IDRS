"""
core/events.py — DetectionEvent dataclass and Severity enum.

Every component in Mini-IDRS consumes this single model:
  - Detection plugins    → produce DetectionEvent
  - Logger               → formats and writes it
  - BlockStore           → persists it to blocked.json
  - FirewallManager      → extracts attacker IP from it
  - VictimBlocker        → extracts attacker IP from it
  - EventPipeline        → routes it to all consumers
  - IDS API              → serialises it for Dashboard
  - Replay tool          → produces it from PCAP packets
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """
    Detection severity levels — ordered from least to most critical.

    LOW      — Reconnaissance only (e.g. XMAS scan). No direct damage.
    MEDIUM   — Mapping / probing (e.g. port scan). Preparation stage.
    HIGH     — Active credential attack (e.g. SSH brute-force).
    CRITICAL — Active DoS / service disruption (e.g. SYN flood).
    """
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DetectionEvent:
    """
    Canonical event produced by every detection plugin.

    All downstream consumers receive this single object instead of
    fragmented string returns — enabling consistent logging, persistence,
    blocking, dashboard display, and offline replay.
    """
    attack:     str        # "SYN_FLOOD" | "XMAS_SCAN" | "SSH_BRUTE_FORCE"
    attacker:   str        # Source IP address of the attacker
    victim:     str        # Destination IP address (usually the Victim VM)
    severity:   Severity
    confidence: float      # 0.0 – 1.0  (1.0 = certain / unambiguous)
    timestamp:  datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: dict[str, Any] = field(default_factory=dict)
    # details examples:
    #   SYN_FLOOD:       {"packet_count": 30, "window_seconds": 5}
    #   XMAS_SCAN:       {"flags": "0x29"}
    #   SSH_BRUTE_FORCE: {"handshake_count": 9, "window_seconds": 60}

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_log_line(self) -> str:
        """Single human-readable log line for ids.log."""
        details_str = " ".join(f"{k}={v}" for k, v in self.details.items())
        return (
            f"{self.attack} | attacker={self.attacker} victim={self.victim} "
            f"severity={self.severity.value} confidence={self.confidence:.2f}"
            + (f" {details_str}" if details_str else "")
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dictionary for API responses and blocked.json."""
        return {
            "attack":     self.attack,
            "attacker":   self.attacker,
            "victim":     self.victim,
            "severity":   self.severity.value,
            "confidence": self.confidence,
            "timestamp":  self.timestamp.isoformat(),
            "details":    self.details,
        }
