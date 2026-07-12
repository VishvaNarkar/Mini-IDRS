"""
core/logger.py — Centralised logging setup for Mini-IDRS.

Sets up a rotating file handler and a console handler on the root logger.
Provides log_event() to write a DetectionEvent at the appropriate level.

Usage:
    from core.logger import setup_logging, log_event
    setup_logging(cfg.paths.logs, cfg.logging.level)
    log_event(event)
"""
from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path

from core.events import DetectionEvent, Severity

_LOG_FORMAT  = "%(asctime)s [%(levelname)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_file: str, level: str = "INFO") -> logging.Logger:
    """
    Configure the root logger with:
      - A rotating file handler (10 MB × 5 backups).
      - A console (stdout) handler.

    Safe to call multiple times — duplicate handlers are not added.
    Returns the root logger.
    """
    parent_dir = Path(log_file).parent
    parent_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(parent_dir, 0o777)
    except Exception:
        pass

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Avoid duplicate handlers on re-import / re-call
    if root.handlers:
        return root

    fmt = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,   # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    try:
        os.chmod(log_file, 0o666)
    except Exception:
        pass

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    return root


# Severity → logging level mapping
_SEVERITY_TO_LEVEL: dict[Severity, int] = {
    Severity.LOW:      logging.INFO,
    Severity.MEDIUM:   logging.WARNING,
    Severity.HIGH:     logging.ERROR,
    Severity.CRITICAL: logging.CRITICAL,
}


def log_event(event: DetectionEvent, logger: logging.Logger | None = None) -> None:
    """Write a DetectionEvent to the log at the level matching its severity."""
    lg    = logger or logging.getLogger("idrs.detections")
    level = _SEVERITY_TO_LEVEL.get(event.severity, logging.INFO)
    lg.log(level, event.to_log_line())
