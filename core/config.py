"""
core/config.py — Configuration loader for Mini-IDRS.

Loads non-secret settings from config.yaml (tracked in git as config.yaml.example)
and injects secrets from the .env file (always gitignored) via python-dotenv.

Other modules import the singleton:
    from core.config import cfg
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

# Load .env into os.environ before any os.environ access.
load_dotenv()


# ---------------------------------------------------------------------------
# Sub-config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class NetworkConfig:
    monitor_ip:  str
    victim_ip:   str
    firewall_ip: str


@dataclass
class FirewallAPIConfig:
    url:       str
    bind_host: str
    port:      int
    api_key:   str = field(default="", repr=False)   # injected from FIREWALL_API_KEY


@dataclass
class IDSAPIConfig:
    host:            str
    port:            int
    allowed_origins: list[str] = field(default_factory=list)
    api_key:         str = field(default="", repr=False)   # injected from IDS_API_KEY


@dataclass
class VictimConfig:
    ssh_port: int
    ssh_user: str = field(default="", repr=False)     # injected from VICTIM_SSH_USER
    ssh_pass: str = field(default="", repr=False)     # injected from VICTIM_SSH_PASS


@dataclass
class SynFloodThresholds:
    threshold:      int
    window_seconds: int


@dataclass
class SshBruteForceThresholds:
    threshold:      int
    window_seconds: int


@dataclass
class DetectionConfig:
    syn_flood:       SynFloodThresholds
    ssh_brute_force: SshBruteForceThresholds


@dataclass
class LoggingConfig:
    level: str


@dataclass
class PathsConfig:
    whitelist:  str
    blocked:    str
    stats:      str
    logs:       str
    pcaps:      str
    thresholds: str


@dataclass
class SchedulerConfig:
    health_check_interval_seconds: int
    whitelist_reload_seconds:      int
    thresholds_reload_seconds:     int
    stats_interval_seconds:        int
    block_cleanup_hours:           int


@dataclass
class Config:
    network:      NetworkConfig
    firewall_api: FirewallAPIConfig
    ids_api:      IDSAPIConfig
    victim:       VictimConfig
    detection:    DetectionConfig
    logging:      LoggingConfig
    paths:        PathsConfig
    scheduler:    SchedulerConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_env(key: str) -> str:
    """Read an optional secret from the environment.

    Secrets are allowed to be empty so imports, API schema generation, and
    tests can run without a fully provisioned lab .env file. Runtime callers
    that actually need a secret should fail gracefully at the point of use.
    """
    return os.environ.get(key, "")


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: str | Path = "config.yaml") -> Config:
    """Parse config.yaml and merge optional secrets from environment variables."""
    config_path = Path(path)
    if not config_path.exists() and config_path.name == "config.yaml":
        config_path = Path("config.yaml.example")
    with open(config_path, "r") as fh:
        raw = yaml.safe_load(fh)

    n  = raw["network"]
    fa = raw["firewall_api"]
    ia = raw["ids_api"]
    v  = raw["victim"]
    d  = raw["detection"]
    lg = raw["logging"]
    p  = raw["paths"]
    sc = raw["scheduler"]

    return Config(
        network=NetworkConfig(
            monitor_ip  = n["monitor_ip"],
            victim_ip   = n["victim_ip"],
            firewall_ip = n["firewall_ip"],
        ),
        firewall_api=FirewallAPIConfig(
            url       = fa["url"],
            bind_host = fa["bind_host"],
            port      = fa["port"],
            api_key   = _get_env("FIREWALL_API_KEY"),
        ),
        ids_api=IDSAPIConfig(
            host            = ia["host"],
            port            = ia["port"],
            allowed_origins = ia.get("allowed_origins", []),
            api_key         = _get_env("IDS_API_KEY"),
        ),
        victim=VictimConfig(
            ssh_port = v["ssh_port"],
            ssh_user = _get_env("VICTIM_SSH_USER"),
            ssh_pass = _get_env("VICTIM_SSH_PASS"),
        ),
        detection=DetectionConfig(
            syn_flood=SynFloodThresholds(**d["syn_flood"]),
            ssh_brute_force=SshBruteForceThresholds(**d["ssh_brute_force"]),
        ),
        logging=LoggingConfig(level=lg["level"]),
        paths=PathsConfig(**p),
        scheduler=SchedulerConfig(**sc),
    )


# ---------------------------------------------------------------------------
# Lazy module-level proxy — imported by other modules as `cfg`
# ---------------------------------------------------------------------------
class LazyConfig:
    """Load configuration on first attribute access and allow test injection."""

    def __init__(self) -> None:
        self._config: Config | None = None

    def _load(self) -> Config:
        if self._config is None:
            config_path = Path(os.environ.get("IDRS_CONFIG", "config.yaml"))
            self._config = load_config(config_path)
        return self._config

    def __getattr__(self, name: str):
        return getattr(self._load(), name)

    def set_config(self, config: Config | None) -> None:
        """Inject an explicit Config for tests, or clear with None."""
        self._config = config


cfg = LazyConfig()
