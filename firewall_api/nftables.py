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
    chain:  str
    handle: int
    ip:     str


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def add_drop_rule(ip: str) -> bool:
    """
    nft add rule inet filter FORWARD ip saddr <ip> drop comment "idrs-block:<ip>"
    nft add rule inet filter INPUT ip saddr <ip> drop comment "idrs-block:<ip>"
    """
    # 1. Block routed traffic through the firewall
    rc_fwd, _, err_fwd = _run([
        "add", "rule", "inet", "filter", "FORWARD",
        "ip", "saddr", ip, "drop",
        "comment", f'"{_COMMENT}:{ip}"',
    ])

    # 2. Block direct traffic targeting the gateway itself
    rc_inp, _, err_inp = _run([
        "add", "rule", "inet", "filter", "INPUT",
        "ip", "saddr", ip, "drop",
        "comment", f'"{_COMMENT}:{ip}"',
    ])

    if rc_fwd != 0 or rc_inp != 0:
        logger.error(
            f"[NFT] add_drop_rule({ip}) failed. "
            f"FORWARD err: {err_fwd.strip() if rc_fwd != 0 else 'none'}, "
            f"INPUT err: {err_inp.strip() if rc_inp != 0 else 'none'}"
        )
        return False

    logger.info(f"[NFT] Added FORWARD and INPUT DROP rules for {ip}")
    return True


def delete_drop_rule(ip: str) -> bool:
    """Find the IDRS-managed rules for `ip` by handle in all chains and delete them."""
    rules = _find_rules(ip)
    if not rules:
        logger.warning(f"[NFT] No IDRS rules found for {ip}")
        return False

    success = True
    for rule in rules:
        rc, _, err = _run([
            "delete", "rule", "inet", "filter", rule.chain,
            "handle", str(rule.handle),
        ])
        if rc != 0:
            logger.error(
                f"[NFT] delete_drop_rule({ip}) chain={rule.chain} handle={rule.handle} failed: {err.strip()}"
            )
            success = False
        else:
            logger.info(f"[NFT] Deleted {rule.chain} DROP for {ip} (handle={rule.handle})")

    return success


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


def _find_rules(ip: str) -> list[_NftRule]:
    """Return the list of NftRules (chain, handle, IP) for all IDRS-managed rules matching this IP."""
    rules: list[_NftRule] = []

    # Search both chains
    for chain in ["FORWARD", "INPUT"]:
        # Global option '-a' must be placed before the 'list' command
        rc, out, _ = _run(["-a", "list", "chain", "inet", "filter", chain])
        if rc != 0:
            continue

        handle_re = re.compile(r"handle (\d+)")
        ip_re     = re.compile(
            rf'ip saddr {re.escape(ip)} drop.*{re.escape(_COMMENT)}', re.IGNORECASE
        )
        for line in out.splitlines():
            if ip_re.search(line):
                m = handle_re.search(line)
                if m:
                    rules.append(_NftRule(chain=chain, handle=int(m.group(1)), ip=ip))

    return rules
