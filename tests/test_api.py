import importlib

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from core.events import DetectionEvent, Severity
from core.persistence import BlockStore
from core.whitelist import WhitelistManager
from ids_api.models import BlockRequest


class StubBlocker:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def block(self, ip):
        self.calls.append(("block", ip))
        return self.result

    def unblock(self, ip):
        self.calls.append(("unblock", ip))
        return self.result


def server_with_state(monkeypatch, tmp_path, fw=True, victim=True):
    monkeypatch.setenv("IDS_API_KEY", "test-key")
    monkeypatch.setenv("FIREWALL_API_KEY", "fw-key")
    monkeypatch.setenv("VICTIM_SSH_USER", "victim")
    monkeypatch.setenv("VICTIM_SSH_PASS", "victim")
    server = importlib.import_module("ids_api.server")
    monkeypatch.setattr(server, "block_store", BlockStore(str(tmp_path / "blocked.json")))
    monkeypatch.setattr(server, "whitelist_mgr", WhitelistManager(str(tmp_path / "whitelist.txt")))
    monkeypatch.setattr(server, "firewall_mgr", StubBlocker(fw))
    monkeypatch.setattr(server, "victim_blocker", StubBlocker(victim))
    return server


def test_manual_block_validates_invalid_ip():
    with pytest.raises(ValidationError):
        BlockRequest(ip="not-an-ip")


@pytest.mark.anyio
async def test_manual_block_rejects_whitelisted_ip(monkeypatch, tmp_path):
    server = server_with_state(monkeypatch, tmp_path)
    server.whitelist_mgr.add("10.0.0.9")

    with pytest.raises(HTTPException) as exc:
        await server.block_ip(BlockRequest(ip="10.0.0.9"), _key="test-key")

    assert exc.value.status_code == 400
    assert "whitelisted" in exc.value.detail


@pytest.mark.anyio
async def test_manual_block_rejects_duplicate_ip(monkeypatch, tmp_path):
    server = server_with_state(monkeypatch, tmp_path)
    evt = DetectionEvent("MANUAL_BLOCK", "10.0.0.9", "10.0.0.2", Severity.HIGH, 1.0)
    server.block_store.add(evt, firewall_blocked=True, victim_blocked=True)

    with pytest.raises(HTTPException) as exc:
        await server.block_ip(BlockRequest(ip="10.0.0.9"), _key="test-key")

    assert exc.value.status_code == 400
    assert "already blocked" in exc.value.detail


@pytest.mark.anyio
async def test_manual_block_persists_statuses(monkeypatch, tmp_path):
    server = server_with_state(monkeypatch, tmp_path, fw=True, victim=False)

    response = await server.block_ip(BlockRequest(ip="10.0.0.9"), _key="test-key")

    assert response.ip == "10.0.0.9"
    record = server.block_store.all()[0]
    assert record["firewall_blocked"] is True
    assert record["victim_blocked"] is False


@pytest.mark.anyio
async def test_manual_block_fails_when_all_blockers_fail(monkeypatch, tmp_path):
    server = server_with_state(monkeypatch, tmp_path, fw=False, victim=False)

    with pytest.raises(HTTPException) as exc:
        await server.block_ip(BlockRequest(ip="10.0.0.9"), _key="test-key")

    assert exc.value.status_code == 500
