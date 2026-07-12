"""
firewall_api/nftables.py — nftables subprocess wrapper.

All nft command execution is isolated here. The Firewall API server
calls these functions; it never shells out directly.

nftables setup assumed on the Linux Firewall VM:
    nft add table inet filter
    nft add chain inet filter FORWARD { type filter hook forward priority 0; policy accept; }
See GATEWAY_CONFIG.md for the full initial setup.

Rules added by IDRS are tagged with a comment ("idrs-block:<ip>") so that
they can be identified and removed precisely without touching other rules.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_TABLE   = "inet filter"
_CHAIN   = "FORWARD"
_COMMENT = "idrs-block"   # prefix used in every IDRS-managed rule


@dataclass
class _NftRule:
    handle: int
    ip:     str


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def add_drop_rule(ip: str) -> bool:
    """
    nft add rule inet filter FORWARD ip saddr <ip> drop comment "idrs-block:<ip>"
    """
    rc, _, err = _run([
        "add", "rule", "inet", "filter", "FORWARD",
        "ip", "saddr", ip, "drop",
        "comment", f'"{_COMMENT}:{ip}"',
    ])
    if rc != 0:
        logger.error(f"[NFT] add_drop_rule({ip}) failed: {err.strip()}")
        return False
    logger.info(f"[NFT] Added FORWARD DROP for {ip}")
    return True


def delete_drop_rule(ip: str) -> bool:
    """Find the IDRS-managed rule for `ip` by handle and delete it."""
    rule = _find_rule(ip)
    if rule is None:
        logger.warning(f"[NFT] No IDRS rule found for {ip}")
        return False
    rc, _, err = _run([
        "delete", "rule", "inet", "filter", "FORWARD",
        "handle", str(rule.handle),
    ])
    if rc != 0:
        logger.error(
            f"[NFT] delete_drop_rule({ip}) handle={rule.handle} failed: {err.strip()}"
        )
        return False
    logger.info(f"[NFT] Deleted FORWARD DROP for {ip} (handle={rule.handle})")
    return True


def list_blocked_ips() -> list[str]:
    """Return a list of IPs currently blocked by IDRS-managed FORWARD DROP rules."""
    rc, out, _ = _run(["list", "chain", "inet", "filter", "FORWARD"])
    if rc != 0:
        return []
    pattern = re.compile(
        rf'ip saddr (\S+) drop.*{re.escape(_COMMENT)}', re.IGNORECASE
    )
    return [m.group(1) for line in out.splitlines() if (m := pattern.search(line))]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["sudo", "nft"] + args,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:
        logger.error(f"[NFT] subprocess error: {exc}")
        return -1, "", str(exc)


def _find_rule(ip: str) -> _NftRule | None:
    """Return the NftRule (handle + IP) for an IDRS-managed rule, or None."""
    rc, out, _ = _run(["list", "chain", "-a", "inet", "filter", "FORWARD"])
    if rc != 0:
        return None
    handle_re = re.compile(r"handle (\d+)")
    ip_re     = re.compile(
        rf'ip saddr {re.escape(ip)} drop.*{re.escape(_COMMENT)}', re.IGNORECASE
    )
    for line in out.splitlines():
        if ip_re.search(line):
            m = handle_re.search(line)
            if m:
                return _NftRule(handle=int(m.group(1)), ip=ip)
    return None
