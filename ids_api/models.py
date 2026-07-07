"""ids_api/models.py — Pydantic request/response models for the IDS API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class BlockRequest(BaseModel):
    ip:     str
    reason: str = "manual"

    model_config = {
        "json_schema_extra": {"example": {"ip": "192.168.10.15", "reason": "manual"}}
    }


class BlockResponse(BaseModel):
    ip:          str
    firewall_ok: bool
    victim_ok:   bool


class UnblockResponse(BaseModel):
    ip:          str
    firewall_ok: bool
    victim_ok:   bool


class WhitelistAddRequest(BaseModel):
    ip: str = Field(..., description="IP address to add to the whitelist")


class ThresholdPatch(BaseModel):
    """
    Partial update for detection thresholds.
    Only provided keys are updated; others remain unchanged.
    Changes are written to runtime/thresholds.json and reloaded by the
    Scheduler into the live DetectionContext within ~30 seconds.
    """
    syn_flood:       dict[str, int] | None = None
    ssh_brute_force: dict[str, int] | None = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "syn_flood": {"threshold": 50, "window_seconds": 5}
            }
        }
    }


class AttackEntry(BaseModel):
    attack:     str
    attacker:   str
    victim:     str
    severity:   str
    confidence: float
    timestamp:  str
    details:    dict[str, Any] = {}


class HealthResponse(BaseModel):
    status:                str
    firewall_api_reachable: bool
    version:               str = "1.0"
