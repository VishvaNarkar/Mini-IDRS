import importlib
from ipaddress import IPv4Address
from typing import get_type_hints

import pytest
from pydantic import ValidationError

from firewall_api.models import BlockRequest


def server(monkeypatch):
    monkeypatch.setenv("FIREWALL_API_KEY", "fw-key")
    return importlib.import_module("firewall_api.server")


def test_firewall_post_rejects_invalid_ip():
    with pytest.raises(ValidationError):
        BlockRequest(ip="bad")


def test_firewall_delete_path_is_annotated_for_ipv4_validation(monkeypatch):
    s = server(monkeypatch)

    assert get_type_hints(s.unblock_ip)["ip"] is IPv4Address


def test_firewall_post_passes_valid_ip_as_string(monkeypatch):
    s = server(monkeypatch)
    seen = []
    monkeypatch.setattr(s.nftables, "add_drop_rule", lambda ip: seen.append(ip) or True)

    response = s.block_ip(BlockRequest(ip="10.0.0.9"), _key="fw-key")

    assert response.blocked == "10.0.0.9"
    assert seen == ["10.0.0.9"]
