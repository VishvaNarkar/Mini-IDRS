"""
firewall_api/server.py — Firewall REST API (runs on the Linux Firewall VM).

This is a separate deployment from the IDS Monitor/Dashboard.
It runs as a systemd service on the Linux Firewall VM and is the only
process that calls nft commands — nothing else in the project does.

Security:
  - Bound to 192.168.10.1:8080 (internal VMnet2 interface only — not internet-facing)
  - All endpoints require X-API-Key authentication
  - API key is set via FIREWALL_API_KEY environment variable (.env file)

Start for development:
    uvicorn firewall_api.server:app --host 192.168.10.1 --port 8080 --reload

Production (systemd service on Firewall VM):
    See GATEWAY_CONFIG.md for the systemd unit file.

Interactive API docs (lab use only):
    http://192.168.10.1:8080/docs
"""
from __future__ import annotations

import logging

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status

load_dotenv()   # load .env on the Firewall VM

from firewall_api import nftables
from firewall_api.auth import require_api_key
from firewall_api.models import (
    BlockRequest,
    BlockResponse,
    HealthResponse,
    RulesResponse,
    UnblockResponse,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Mini IDRS — Firewall API",
    description=(
        "Controls nftables FORWARD chain rules on the Linux Firewall VM. "
        "Bound to the internal lab interface only. Requires X-API-Key auth."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


# ---------------------------------------------------------------------------
# /api/v1/
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Liveness check",
)
def health(_key: str = Depends(require_api_key)) -> HealthResponse:
    return HealthResponse(status="ok")


@app.post(
    "/api/v1/rules",
    response_model=BlockResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Rules"],
    summary="Block an IP in the FORWARD chain",
)
def block_ip(
    req: BlockRequest,
    _key: str = Depends(require_api_key),
) -> BlockResponse:
    ok = nftables.add_drop_rule(req.ip)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail=f"nftables: failed to add DROP rule for {req.ip}",
        )
    return BlockResponse(blocked=req.ip)


@app.delete(
    "/api/v1/rules/{ip}",
    response_model=UnblockResponse,
    tags=["Rules"],
    summary="Unblock an IP — remove its FORWARD DROP rule",
)
def unblock_ip(
    ip: str,
    _key: str = Depends(require_api_key),
) -> UnblockResponse:
    ok = nftables.delete_drop_rule(ip)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"No IDRS-managed DROP rule found for {ip}",
        )
    return UnblockResponse(unblocked=ip)


@app.get(
    "/api/v1/rules",
    response_model=RulesResponse,
    tags=["Rules"],
    summary="List all IPs blocked by IDRS",
)
def list_rules(_key: str = Depends(require_api_key)) -> RulesResponse:
    return RulesResponse(rules=nftables.list_blocked_ips())
