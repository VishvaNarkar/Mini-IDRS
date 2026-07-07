"""
tools/replay.py — PCAP Attack Replay Tool

Replays packets from a .pcap file through the SAME EventPipeline used during
live detection. This means replay tests the COMPLETE processing pipeline:
    detection → logging → persistence → Firewall API → Victim SSH

Use --dry-run to detect and print events without applying any blocks.

Usage:
    # Full pipeline replay (blocks ARE applied)
    python tools/replay.py --pcap runtime/pcaps/capture.pcap

    # Dry-run: detect only, print events, no blocking
    python tools/replay.py --pcap runtime/pcaps/capture.pcap --dry-run

    # Show only events with severity >= HIGH
    python tools/replay.py --pcap capture.pcap --dry-run --min-severity HIGH

Capture a PCAP for replay:
    sudo tcpdump -i ens33 -w runtime/pcaps/capture.pcap
    # Run attacks from Kali, then Ctrl-C
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.utils import rdpcap

from core.config import cfg
from core.events import DetectionEvent, Severity
from core.firewall import FirewallManager, NftablesAPIBackend
from core.logger import setup_logging
from core.persistence import BlockStore
from core.pipeline import EventPipeline
from core.victim import VictimBlocker
from core.whitelist import WhitelistManager
from plugins.base import DetectionContext
from plugins.ssh_brute_force import SshBruteForceDetector
from plugins.syn_flood import SynFloodDetector
from plugins.xmas_scan import XmasScanDetector

# Severity ordering for --min-severity filter
_SEV_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _build_pipeline(dry_run: bool) -> tuple[list, DetectionContext, EventPipeline]:
    """Build the same component graph as idrs_monitor.py."""
    whitelist_mgr  = WhitelistManager(cfg.paths.whitelist)
    block_store    = BlockStore(cfg.paths.blocked)
    firewall_mgr   = FirewallManager(
        NftablesAPIBackend(cfg.firewall_api.url, cfg.firewall_api.api_key)
    )
    victim_blocker = VictimBlocker(
        cfg.network.victim_ip, cfg.victim.ssh_port,
        cfg.victim.ssh_user, cfg.victim.ssh_pass,
    )

    plugins = [XmasScanDetector(), SynFloodDetector(), SshBruteForceDetector()]

    thresholds = {
        "syn_flood": {
            "threshold":      cfg.detection.syn_flood.threshold,
            "window_seconds": cfg.detection.syn_flood.window_seconds,
        },
        "ssh_brute_force": {
            "threshold":      cfg.detection.ssh_brute_force.threshold,
            "window_seconds": cfg.detection.ssh_brute_force.window_seconds,
        },
    }
    context = DetectionContext(
        victim_ip  = cfg.network.victim_ip,
        monitor_ip = cfg.network.monitor_ip,
        thresholds = thresholds,
        whitelist  = set(whitelist_mgr.all()),
    )

    if dry_run:
        # In dry-run mode, replace the real firewall/victim with no-op stubs
        class _NoopFirewall:
            def block(self, ip): return True
            def unblock(self, ip): return True
            def list_rules(self): return []

        class _NoopVictim:
            def block(self, ip): return True
            def unblock(self, ip): return True

        # Wrap with FirewallManager for consistent interface
        from core.firewall import FirewallManager as FM
        noop_fw = FM(_NoopFirewall())

        from core.victim import VictimBlocker as VB
        # Monkey-patch the victim blocker
        victim_blocker = type("NoopVB", (), {"block": lambda s, ip: True, "unblock": lambda s, ip: True})()

        pipeline = EventPipeline(whitelist_mgr, block_store, noop_fw, victim_blocker)
    else:
        pipeline = EventPipeline(whitelist_mgr, block_store, firewall_mgr, victim_blocker)

    return plugins, context, pipeline


def replay(
    pcap_path: str,
    dry_run: bool = False,
    min_severity: Severity = Severity.LOW,
) -> list[DetectionEvent]:
    """
    Replay all packets in a PCAP file through the detection pipeline.

    Args:
        pcap_path:    Path to the .pcap file.
        dry_run:      If True, detect but do not block or persist.
        min_severity: Only process/return events at or above this level.

    Returns:
        List of DetectionEvent objects that were produced and processed.
    """
    path = Path(pcap_path)
    if not path.exists():
        print(f"[REPLAY] Error: {pcap_path} not found.")
        sys.exit(1)

    print(f"[REPLAY] Loading {pcap_path} ...")
    packets = rdpcap(str(path))
    print(f"[REPLAY] {len(packets)} packets loaded")
    print(f"[REPLAY] dry_run={dry_run}  min_severity={min_severity.value}")
    print("-" * 60)

    min_idx = _SEV_ORDER.index(min_severity)
    plugins, context, pipeline = _build_pipeline(dry_run)

    events: list[DetectionEvent] = []

    for pkt in packets:
        for plugin in plugins:
            try:
                event = plugin.handle_packet(pkt, context)
                if event is None:
                    continue
                # Severity filter
                if _SEV_ORDER.index(event.severity) < min_idx:
                    continue
                events.append(event)
                if dry_run:
                    print(f"[DRY-RUN] {event.to_log_line()}")
                else:
                    acted = pipeline.process(event)
                    status = "blocked" if acted else "skipped"
                    print(f"[REPLAY]  {event.to_log_line()} → {status}")
            except Exception as exc:
                print(f"[REPLAY] Plugin {plugin.name} error: {exc}")

    print("-" * 60)
    print(f"[REPLAY] Done — {len(events)} events detected")
    return events


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini IDRS — PCAP Attack Replay Tool"
    )
    parser.add_argument("--pcap",         required=True, help="Path to .pcap file")
    parser.add_argument("--dry-run",      action="store_true", help="Detect only — no blocking")
    parser.add_argument("--min-severity", default="LOW",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Minimum severity to process (default: LOW)")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config.yaml (default: config.yaml)")
    args = parser.parse_args()

    import os
    os.environ.setdefault("IDRS_CONFIG", args.config)

    setup_logging(cfg.paths.logs, cfg.logging.level)
    replay(
        pcap_path    = args.pcap,
        dry_run      = args.dry_run,
        min_severity = Severity(args.min_severity),
    )


if __name__ == "__main__":
    main()
