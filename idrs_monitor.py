"""
idrs_monitor.py — Mini IDRS entry point.

This file is intentionally thin (~50 lines of wiring).
All logic lives in core/ modules and plugins/.

Usage:
    sudo python idrs_monitor.py -i ens33

Options:
    -i / --iface   Network interface to sniff (required)
    --config       Path to config.yaml (default: config.yaml)
"""
from __future__ import annotations

import argparse
import logging
import os

# Allow --config flag to set the path before config.py singleton loads
_parser = argparse.ArgumentParser(
    description="Mini IDRS — Intrusion Detection & Response System",
    add_help=False,
)
_parser.add_argument("--config", default="config.yaml")
_known, _remaining = _parser.parse_known_args()
os.environ.setdefault("IDRS_CONFIG", _known.config)

# Now safe to import the config singleton
from core.config import cfg
from core.firewall import FirewallManager, NftablesAPIBackend
from core.logger import setup_logging
from core.packet_capture import PacketCapture
from core.persistence import BlockStore
from core.pipeline import EventPipeline
from core.scheduler import IDRSScheduler
from core.victim import VictimBlocker
from core.whitelist import WhitelistManager
from plugins.base import DetectionContext
from plugins.ssh_brute_force import SshBruteForceDetector
from plugins.syn_flood import SynFloodDetector
from plugins.xmas_scan import XmasScanDetector


def main() -> None:
    # --- CLI ---
    parser = argparse.ArgumentParser(
        description="Mini IDRS — Intrusion Detection & Response System"
    )
    parser.add_argument(
        "-i", "--iface", required=True,
        help="Network interface to sniff (e.g. ens33)"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml (default: config.yaml)"
    )
    args = parser.parse_args()

    # --- Logging ---
    setup_logging(cfg.paths.logs, cfg.logging.level)
    log = logging.getLogger("idrs")
    log.info("=" * 60)
    log.info("Mini IDRS starting")
    log.info(f"  Monitor IP : {cfg.network.monitor_ip}")
    log.info(f"  Victim IP  : {cfg.network.victim_ip}")
    log.info(f"  Firewall IP: {cfg.network.firewall_ip}")
    log.info(f"  Interface  : {args.iface}")
    log.info("=" * 60)

    # --- Core components ---
    whitelist_mgr  = WhitelistManager(cfg.paths.whitelist)
    block_store    = BlockStore(cfg.paths.blocked)
    firewall_mgr   = FirewallManager(
        NftablesAPIBackend(cfg.firewall_api.url, cfg.firewall_api.api_key)
    )
    victim_blocker = VictimBlocker(
        cfg.network.victim_ip,
        cfg.victim.ssh_port,
        cfg.victim.ssh_user,
        cfg.victim.ssh_pass,
    )

    # --- Detection plugins ---
    plugins = [
        XmasScanDetector(),
        SynFloodDetector(),
        SshBruteForceDetector(),
    ]

    # --- Shared detection context (thresholds are a live dict updated by Scheduler) ---
    thresholds: dict = {
        "syn_flood": {
            "threshold":      cfg.detection.syn_flood.threshold,
            "window_seconds": cfg.detection.syn_flood.window_seconds,
        },
        "ssh_brute_force": {
            "threshold":      cfg.detection.ssh_brute_force.threshold,
            "window_seconds": cfg.detection.ssh_brute_force.window_seconds,
        },
    }
    
    # Load existing thresholds from thresholds.json if present
    import json
    from pathlib import Path
    t_path = Path(cfg.paths.thresholds)
    if t_path.exists():
        try:
            with open(t_path, "r") as fh:
                data = json.load(fh)
                if "syn_flood" in data:
                    thresholds["syn_flood"].update(data["syn_flood"])
                if "ssh_brute_force" in data:
                    thresholds["ssh_brute_force"].update(data["ssh_brute_force"])
            log.info(f"Loaded existing thresholds from {t_path}")
        except Exception as exc:
            log.warning(f"Failed to load thresholds from {t_path} at start: {exc}")

    context = DetectionContext(
        victim_ip  = cfg.network.victim_ip,
        monitor_ip = cfg.network.monitor_ip,
        thresholds = thresholds,
        whitelist  = set(whitelist_mgr.all()),
    )

    # --- Event pipeline ---
    pipeline = EventPipeline(whitelist_mgr, block_store, firewall_mgr, victim_blocker)

    # --- Scheduler (background thread) ---
    scheduler = IDRSScheduler(
        firewall_api_url           = cfg.firewall_api.url,
        firewall_api_key           = cfg.firewall_api.api_key,
        whitelist_mgr              = whitelist_mgr,
        block_store                = block_store,
        detection_context          = context,
        thresholds_file            = cfg.paths.thresholds,
        stats_file                 = cfg.paths.stats,
        health_check_interval      = cfg.scheduler.health_check_interval_seconds,
        whitelist_reload_interval  = cfg.scheduler.whitelist_reload_seconds,
        thresholds_reload_interval = cfg.scheduler.thresholds_reload_seconds,
        stats_interval             = cfg.scheduler.stats_interval_seconds,
        block_cleanup_hours        = cfg.scheduler.block_cleanup_hours,
    )
    scheduler.start()

    # --- Packet capture (blocks until Ctrl-C) ---
    capture = PacketCapture(plugins, context, pipeline)
    capture.start(args.iface)


if __name__ == "__main__":
    main()
