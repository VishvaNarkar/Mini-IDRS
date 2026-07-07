"""firewall_api/models.py — Pydantic request/response models for the Firewall API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class BlockRequest(BaseModel):
    ip: str = Field(..., description="IPv4 address to block in the FORWARD chain")

    model_config = {"json_schema_extra": {"example": {"ip": "192.168.10.15"}}}


class BlockResponse(BaseModel):
    blocked: str

    model_config = {"json_schema_extra": {"example": {"blocked": "192.168.10.15"}}}


class UnblockResponse(BaseModel):
    unblocked: str

    model_config = {"json_schema_extra": {"example": {"unblocked": "192.168.10.15"}}}


class RulesResponse(BaseModel):
    rules: list[str]

    model_config = {
        "json_schema_extra": {"example": {"rules": ["192.168.10.15", "192.168.10.20"]}}
    }


class HealthResponse(BaseModel):
    status:  str = "ok"
    version: str = "1.0"
