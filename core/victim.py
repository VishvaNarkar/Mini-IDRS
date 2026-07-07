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
        return self._run(_BLOCK_CMD.format(ip=ip), action=f"block({ip})")

    def unblock(self, ip: str) -> bool:
        """Remove the iptables INPUT DROP rule for the given IP."""
        return self._run(_UNBLOCK_CMD.format(ip=ip), action=f"unblock({ip})")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run(self, cmd: str, action: str = "") -> bool:
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
            if exit_code != 0:
                err = stderr.read().decode().strip()
                logger.error(f"[VICTIM] {action} failed (exit {exit_code}): {err!r}")
                return False
            logger.info(f"[VICTIM] {action} succeeded on {self._host}")
            return True
        except Exception as exc:
            logger.error(f"[VICTIM] SSH error on {self._host} during {action}: {exc}")
            return False
        finally:
            try:
                client.close()
            except Exception:
                pass
