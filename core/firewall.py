"""
core/firewall.py — FirewallManager abstraction layer.

FirewallBackend is an ABC; multiple backends can be implemented without
changing any caller. The active backend is chosen in idrs_monitor.py.

Included backends:
  NftablesAPIBackend — calls the Firewall REST API over HTTP (primary).
                       No SSH. No Paramiko. No sudo.
                       The API runs on the Linux Firewall VM and executes
                       nft commands locally. Bound to internal interface only.

FirewallManager wraps the chosen backend and adds structured logging.
Only FirewallManager is imported by other modules — never the backend directly.

To add a new backend (e.g. nftables via Unix socket, pfSense, OPNsense):
  1. Subclass FirewallBackend
  2. Implement block(), unblock(), list_rules()
  3. Instantiate it in idrs_monitor.py instead of NftablesAPIBackend
  See docs/development.md for details.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class FirewallBackend(ABC):
    """Abstract interface for any firewall enforcement backend."""

    @abstractmethod
    def block(self, ip: str) -> bool:
        """Add a block rule. Returns True on success, False on failure."""
        ...

    @abstractmethod
    def unblock(self, ip: str) -> bool:
        """Remove a block rule. Returns True on success, False on failure."""
        ...

    @abstractmethod
    def list_rules(self) -> list[str]:
        """Return a list of currently blocked IP addresses."""
        ...


# ---------------------------------------------------------------------------
# Primary backend — nftables via Firewall REST API
# ---------------------------------------------------------------------------

class NftablesAPIBackend(FirewallBackend):
    """
    Calls the Firewall REST API running on the Linux Firewall VM.

    The API executes nftables commands locally — no SSH, no Paramiko,
    no sudo headaches. Communication stays entirely on VMnet2 (internal).
    The API is bound to 192.168.10.1:8080 and requires X-API-Key auth.
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 10) -> None:
        self._base    = base_url.rstrip("/")
        self._headers = {
            "X-API-Key":     api_key,
            "Content-Type":  "application/json",
        }
        self._timeout = timeout

    def block(self, ip: str) -> bool:
        try:
            resp = requests.post(
                f"{self._base}/api/v1/rules",
                json={"ip": ip},
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error(f"[NFTABLES_API] block({ip}) failed: {exc}")
            return False

    def unblock(self, ip: str) -> bool:
        try:
            resp = requests.delete(
                f"{self._base}/api/v1/rules/{ip}",
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error(f"[NFTABLES_API] unblock({ip}) failed: {exc}")
            return False

    def list_rules(self) -> list[str]:
        try:
            resp = requests.get(
                f"{self._base}/api/v1/rules",
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json().get("rules", [])
        except Exception as exc:
            logger.error(f"[NFTABLES_API] list_rules() failed: {exc}")
            return []


# ---------------------------------------------------------------------------
# FirewallManager — the only import other modules should use
# ---------------------------------------------------------------------------

class FirewallManager:
    """
    Wraps a FirewallBackend and adds structured logging.
    This is the single point of contact for all firewall rule changes.
    No other module calls the backend directly.
    """

    def __init__(self, backend: FirewallBackend) -> None:
        self._backend = backend

    def block(self, ip: str) -> bool:
        ok = self._backend.block(ip)
        if ok:
            logger.info(
                f"[FIREWALL] Blocked {ip} via {type(self._backend).__name__}"
            )
        else:
            logger.error(f"[FIREWALL] Failed to block {ip}")
        return ok

    def unblock(self, ip: str) -> bool:
        ok = self._backend.unblock(ip)
        if ok:
            logger.info(
                f"[FIREWALL] Unblocked {ip} via {type(self._backend).__name__}"
            )
        else:
            logger.error(f"[FIREWALL] Failed to unblock {ip}")
        return ok

    def list_rules(self) -> list[str]:
        return self._backend.list_rules()
