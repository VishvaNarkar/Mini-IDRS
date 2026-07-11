"""
ids_api/server.py — IDS REST API + WebSocket Server (runs on the Monitor VM).

Features:
  - WebSocket broadcasts (/api/v1/ws) for real-time dashboard events
  - CORS middleware configured from config.yaml
  - Dynamic threshold endpoints (PATCH/GET)
  - Whitelist and block endpoints
  - System performance stats (/api/v1/system/stats) using psutil
  - Mounts dashboard/ directory to serve the frontend on http://<host>:5000/dashboard/index.html
"""
from __future__ import annotations

import json
import logging
import os
import re
from ipaddress import IPv4Address
from pathlib import Path
from typing import Set

import psutil
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path)

from core.config import cfg
from core.events import DetectionEvent, Severity
from core.firewall import FirewallManager, NftablesAPIBackend
from core.persistence import BlockStore
from core.victim import VictimBlocker
from core.whitelist import WhitelistManager
from ids_api.auth import require_api_key
from ids_api.models import (
    AttackEntry,
    BlockRequest,
    BlockResponse,
    HealthResponse,
    ThresholdPatch,
    UnblockResponse,
    WhitelistAddRequest,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Mini IDRS — IDS API & SOC Control Plane",
    description=(
        "Control plane for Mini-IDRS. "
        "Bound to the lab VM IP. Support CORS, WebSockets, and static dashboard serving."
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS Configuration
# ---------------------------------------------------------------------------
allowed = cfg.ids_api.allowed_origins or ["*"]
# FastAPI CORSMiddleware raises RuntimeError if allow_credentials=True and allow_origins contains "*"
allow_creds = True
if "*" in allowed:
    allow_creds = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed,
    allow_credentials=allow_creds,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
whitelist_mgr  = WhitelistManager(cfg.paths.whitelist)
block_store    = BlockStore(cfg.paths.blocked)
firewall_mgr   = FirewallManager(
    NftablesAPIBackend(cfg.firewall_api.url, cfg.firewall_api.api_key)
)
victim_blocker = VictimBlocker(
    cfg.network.victim_ip,
    cfg.victim.ssh_port,
    cfg.victim.ssh_user,
    cfg.victim.ssh_pass,
)

# Active WebSocket connections
_active_websockets: Set[WebSocket] = set()

_thresholds: dict[str, dict[str, int]] = {
    "syn_flood": {
        "threshold":      cfg.detection.syn_flood.threshold,
        "window_seconds": cfg.detection.syn_flood.window_seconds,
    },
    "ssh_brute_force": {
        "threshold":      cfg.detection.ssh_brute_force.threshold,
        "window_seconds": cfg.detection.ssh_brute_force.window_seconds,
    },
}


def _load_thresholds() -> None:
    path = Path(cfg.paths.thresholds)
    if path.exists():
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
                if "syn_flood" in data:
                    _thresholds["syn_flood"].update(data["syn_flood"])
                if "ssh_brute_force" in data:
                    _thresholds["ssh_brute_force"].update(data["ssh_brute_force"])
            logger.info(f"Loaded existing thresholds from {path}")
        except Exception as exc:
            logger.warning(f"Failed to load thresholds from {path}: {exc}")


_load_thresholds()


def _write_thresholds() -> None:
    path = Path(cfg.paths.thresholds)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(_thresholds, fh, indent=2)


# ---------------------------------------------------------------------------
# WebSockets Real-Time Channel
# ---------------------------------------------------------------------------

@app.websocket("/api/v1/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(None)
):
    """
    WebSocket endpoint for real-time alert broadcasts.
    Authenticates using token parameter due to browser WebSocket limitations.
    """
    expected = os.environ.get("IDS_API_KEY", "").strip()
    clean_token = token.strip() if token else None
    if not expected or clean_token != expected:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    _active_websockets.add(websocket)
    logger.info(f"[WS] Active connection accepted. Total active: {len(_active_websockets)}")

    try:
        while True:
            # Keep connection alive; discard any client messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        _active_websockets.discard(websocket)
        logger.info(f"[WS] Connection disconnected. Total active: {len(_active_websockets)}")
    except Exception as exc:
        logger.error(f"[WS] WebSocket error: {exc}")
        _active_websockets.discard(websocket)


async def broadcast_event(event_dict: dict):
    """Broadcast an event dictionary to all active WebSockets."""
    if not _active_websockets:
        return
    
    dead_connections = set()
    message = json.dumps(event_dict)
    
    for ws in _active_websockets:
        try:
            await ws.send_text(message)
        except Exception:
            dead_connections.add(ws)
            
    for ws in dead_connections:
        _active_websockets.discard(ws)


# ---------------------------------------------------------------------------
# /api/v1/ — Monitor Incoming Events (Internal)
# ---------------------------------------------------------------------------

@app.post("/api/v1/events", status_code=status.HTTP_202_ACCEPTED, tags=["Events"])
async def post_event(
    event_data: dict,
    _key: str = Depends(require_api_key)
):
    """
    Internal endpoint called by the Monitor VM when an alert is triggered.
    Broadcasts it to all active WebSockets for real-time display.
    """
    logger.info(f"[EVENTS] Received alert notification for {event_data.get('attack')}")
    await broadcast_event(event_data)
    return {"status": "broadcasted"}


# ---------------------------------------------------------------------------
# /api/v1/ — Health
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
def health(_key: str = Depends(require_api_key)) -> HealthResponse:
    reachable = False
    try:
        r = requests.get(
            f"{cfg.firewall_api.url}/api/v1/health",
            headers={"X-API-Key": cfg.firewall_api.api_key},
            timeout=3,
        )
        reachable = r.status_code == 200
    except Exception:
        pass
    return HealthResponse(status="ok", firewall_api_reachable=reachable)


# ---------------------------------------------------------------------------
# /api/v1/ — System Stats
# ---------------------------------------------------------------------------

@app.get("/api/v1/system/stats", tags=["Stats"])
def get_system_stats(_key: str = Depends(require_api_key)) -> dict:
    """Return CPU, Memory, and Disk stats of the Monitor VM."""
    try:
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        return {"cpu": cpu, "memory": memory}
    except Exception as exc:
        logger.error(f"Failed to fetch system stats: {exc}")
        return {"cpu": 0, "memory": 0}


# ---------------------------------------------------------------------------
# /api/v1/ — Blocking
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/block",
    response_model=BlockResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Blocking"],
)
async def block_ip(
    req: BlockRequest, _key: str = Depends(require_api_key)
) -> BlockResponse:
    ip = str(req.ip)
    if whitelist_mgr.is_whitelisted(ip):
        raise HTTPException(status_code=400, detail=f"{ip} is whitelisted")
    if block_store.is_blocked(ip):
        raise HTTPException(status_code=400, detail=f"{ip} is already blocked")

    fw_ok     = firewall_mgr.block(ip)
    victim_ok = victim_blocker.block(ip)
    if not (fw_ok or victim_ok):
        raise HTTPException(status_code=500, detail=f"Failed to block {ip}")

    # Persist the manual block as a DetectionEvent
    evt = DetectionEvent(
        attack     = "MANUAL_BLOCK",
        attacker   = ip,
        victim     = cfg.network.victim_ip,
        severity   = Severity.HIGH,
        confidence = 1.0,
        details    = {"reason": req.reason},
    )
    block_store.add(evt, firewall_blocked=fw_ok, victim_blocked=victim_ok)

    # Broadcast manual block
    await broadcast_event(evt.to_dict())

    return BlockResponse(ip=ip, firewall_ok=fw_ok, victim_ok=victim_ok)


@app.delete("/api/v1/block/{ip}", response_model=UnblockResponse, tags=["Blocking"])
def unblock_ip(
    ip: IPv4Address, _key: str = Depends(require_api_key)
) -> UnblockResponse:
    ip_str = str(ip)
    fw_ok     = firewall_mgr.unblock(ip_str)
    victim_ok = victim_blocker.unblock(ip_str)
    block_store.remove(ip_str)
    return UnblockResponse(ip=ip_str, firewall_ok=fw_ok, victim_ok=victim_ok)


@app.get("/api/v1/blocks", tags=["Blocking"])
def list_blocks(_key: str = Depends(require_api_key)) -> dict:
    return {"blocks": block_store.all()}


# ---------------------------------------------------------------------------
# /api/v1/ — Attack Events
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/attacks",
    response_model=list[AttackEntry],
    tags=["Events"],
)
def get_attacks(
    n: int = Query(default=200, ge=1, le=500),
    _key: str = Depends(require_api_key),
) -> list[AttackEntry]:
    return _parse_log(cfg.paths.logs, n)


# ---------------------------------------------------------------------------
# /api/v1/ — Whitelist
# ---------------------------------------------------------------------------

@app.get("/api/v1/whitelist", tags=["Whitelist"])
def get_whitelist(_key: str = Depends(require_api_key)) -> dict:
    return {"whitelist": whitelist_mgr.all()}


@app.post("/api/v1/whitelist", status_code=201, tags=["Whitelist"])
def add_whitelist(
    req: WhitelistAddRequest, _key: str = Depends(require_api_key)
) -> dict:
    ip = str(req.ip)
    whitelist_mgr.add(ip)
    return {"added": ip}


@app.delete("/api/v1/whitelist/{ip}", tags=["Whitelist"])
def remove_whitelist(ip: IPv4Address, _key: str = Depends(require_api_key)) -> dict:
    ip_str = str(ip)
    removed = whitelist_mgr.remove(ip_str)
    if not removed:
        raise HTTPException(status_code=404, detail=f"{ip_str} not in whitelist")
    return {"removed": ip_str}


# ---------------------------------------------------------------------------
# /api/v1/ — Config (dynamic thresholds)
# ---------------------------------------------------------------------------

@app.get("/api/v1/config/thresholds", tags=["Config"])
def get_thresholds(_key: str = Depends(require_api_key)) -> dict:
    return {"thresholds": _thresholds}


@app.patch("/api/v1/config/thresholds", tags=["Config"])
def patch_thresholds(
    patch: ThresholdPatch, _key: str = Depends(require_api_key)
) -> dict:
    if patch.syn_flood:
        _thresholds["syn_flood"].update(patch.syn_flood)
    if patch.ssh_brute_force:
        _thresholds["ssh_brute_force"].update(patch.ssh_brute_force)
    _write_thresholds()
    logger.info(f"[CONFIG] Thresholds updated: {_thresholds}")
    return {"thresholds": _thresholds}


# ---------------------------------------------------------------------------
# /api/v1/ — Stats
# ---------------------------------------------------------------------------

@app.get("/api/v1/stats", tags=["Stats"])
def get_stats(_key: str = Depends(require_api_key)) -> dict:
    stats_path = Path(cfg.paths.stats)
    if not stats_path.exists():
        return {"stats": {}}
    with open(stats_path) as fh:
        return {"stats": json.load(fh)}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEV_MAP: dict[str, str] = {
    "SYN_FLOOD":       "CRITICAL",
    "SSH_BRUTE_FORCE": "HIGH",
    "XMAS_SCAN":       "LOW",
    "MANUAL_BLOCK":    "HIGH",
}

_TYPE_RE = re.compile(r"\b([A-Z][A-Z0-9_]*) \| attacker=")
_TS_RE   = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_IP_RE   = re.compile(r"attacker=(\S+)")
_VIC_RE  = re.compile(r"victim=(\S+)")
_SEV_RE  = re.compile(r"severity=(\S+)")


def _parse_log(log_file: str, n: int) -> list[dict]:
    path = Path(log_file)
    if not path.exists():
        return []
    with open(path, "r", errors="ignore") as fh:
        lines = fh.readlines()

    results: list[dict] = []
    for line in reversed(lines):
        tm = _TYPE_RE.search(line)
        if not tm:
            continue
        attack   = tm.group(1)
        ts_match = _TS_RE.search(line)
        ip_match = _IP_RE.search(line)
        vc_match = _VIC_RE.search(line)
        sev_match = _SEV_RE.search(line)
        results.append({
            "attack":     attack,
            "attacker":   ip_match.group(1) if ip_match else "N/A",
            "victim":     vc_match.group(1) if vc_match else "N/A",
            "severity":   sev_match.group(1) if sev_match else _SEV_MAP.get(attack, "MEDIUM"),
            "confidence": 1.0,
            "timestamp":  ts_match.group(1) if ts_match else "",
            "details":    {},
        })
        if len(results) >= n:
            break
    return results


# ---------------------------------------------------------------------------
# Serve Dashboard Static Directory
# ---------------------------------------------------------------------------
_dash_dir = Path(__file__).resolve().parent.parent / "dashboard"
if _dash_dir.exists():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(_dash_dir)),
        name="dashboard"
    )
    logger.info(f"Dashboard mounted at http://localhost:{cfg.ids_api.port}/dashboard/index.html")
