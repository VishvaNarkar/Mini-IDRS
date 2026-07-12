"""
core/victim.py — VictimBlocker

SSHes into the Victim VM (via Paramiko) and manages iptables INPUT DROP rules.

Defense-in-depth: the Linux Firewall blocks at the FORWARD chain (all traffic
from the attacker dropped before reaching the victim), while the Victim blocks
at INPUT (protection even if the Firewall rule is removed or bypassed).

Paramiko is the only SSH library used in the project — Netmiko has been
removed entirely since there is no longer a Cisco router to manage.
"""
from __future__ import annotations

import logging

import paramiko

logger = logging.getLogger(__name__)

_BLOCK_CMD   = "sudo iptables -I INPUT -s {ip} -j DROP"
_UNBLOCK_CMD = "sudo iptables -D INPUT -s {ip} -j DROP"


class VictimBlocker:
    """
    Manages iptables INPUT rules on the Victim VM via SSH.

    The victim user must have passwordless sudo for iptables.
    See README.md § "Victim VM Setup" for the required visudo entry.
    """

    def __init__(
        self,
        host:     str,
        port:     int,
        username: str,
        password: str,
        timeout:  int = 20,
    ) -> None:
        self._host     = host
        self._port     = port
        self._username = username
        self._password = password
        self._timeout  = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block(self, ip: str) -> bool:
        """Insert an iptables INPUT DROP rule for the given IP."""
        if not self._has_credentials():
            logger.error("[VICTIM] Cannot block %s — missing SSH credentials", ip)
            return False
        ok, code, err = self._run_command(_BLOCK_CMD.format(ip=ip))
        if not ok or code != 0:
            logger.error(f"[VICTIM] block({ip}) failed (exit {code}): {err!r}")
            return False
        logger.info(f"[VICTIM] block({ip}) succeeded on {self._host}")
        return True

    def unblock(self, ip: str) -> bool:
        """Remove all instances of the iptables INPUT DROP rule for the given IP."""
        if not self._has_credentials():
            logger.error("[VICTIM] Cannot unblock %s — missing SSH credentials", ip)
            return False

        cmd = _UNBLOCK_CMD.format(ip=ip)
        deleted_count = 0

        # Loop to delete all duplicate instances of this rule.
        # iptables -D returns non-zero (typically 1) when the rule no longer exists.
        while True:
            ok, code, err = self._run_command(cmd)
            if not ok:
                # SSH connection error — stop loop to avoid infinite loop
                break
            if code == 0:
                deleted_count += 1
                logger.info(f"[VICTIM] Deleted iptables DROP rule copy #{deleted_count} for {ip}")
            else:
                # Exit code non-zero means no more copies of this rule exist
                break

        if deleted_count > 0:
            logger.info(f"[VICTIM] Successfully removed all {deleted_count} iptables rule(s) for {ip}")
            return True
        else:
            logger.warning(f"[VICTIM] No matching iptables rule found to delete for {ip}")
            return False

    def _has_credentials(self) -> bool:
        return bool(self._username and self._password)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_command(self, cmd: str) -> tuple[bool, int, str]:
        """Execute a command over SSH and return (success, exit_code, stderr)."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self._host,
                port     = self._port,
                username = self._username,
                password = self._password,
                timeout  = self._timeout,
            )
            _, stdout, stderr = client.exec_command(cmd, timeout=self._timeout)
            exit_code = stdout.channel.recv_exit_status()
            err_msg = stderr.read().decode().strip()
            return True, exit_code, err_msg
        except Exception as exc:
            logger.error(f"[VICTIM] SSH error on {self._host}: {exc}")
            return False, -1, str(exc)
        finally:
            try:
                client.close()
            except Exception:
                pass
