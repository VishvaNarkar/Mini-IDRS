# docs/api.md — Mini-IDRS API Reference

Both APIs are versioned at `/api/v1/` and require `X-API-Key` authentication.

---

## Firewall API

**Runs on:** Linux Firewall VM  
**Bound to:** `192.168.10.1:8080` (internal interface only — not internet-facing)  
**Auth:** `X-API-Key: <FIREWALL_API_KEY>` header  
**Interactive docs:** `http://192.168.10.1:8080/docs` (lab only)

### Endpoints

#### `GET /api/v1/health`
Liveness check.

**Response:**
```json
{ "status": "ok", "version": "1.0" }
```

---

#### `POST /api/v1/rules`
Add a FORWARD DROP rule for the given IP.

**Request body:**
```json
{ "ip": "192.168.10.15" }
```

**Response (201):**
```json
{ "blocked": "192.168.10.15" }
```

**Effect:** `nft add rule inet filter FORWARD ip saddr 192.168.10.15 drop comment "idrs-block:192.168.10.15"`

---

#### `DELETE /api/v1/rules/{ip}`
Remove the IDRS-managed FORWARD DROP rule for the given IP.

**Response (200):**
```json
{ "unblocked": "192.168.10.15" }
```

**Response (404):** IP not found in nftables chain.

---

#### `GET /api/v1/rules`
List all IPs currently blocked by IDRS-managed rules.

**Response:**
```json
{ "rules": ["192.168.10.15", "192.168.10.20"] }
```

---

## IDS API

**Runs on:** Monitor VM  
**Address:** `http://192.168.10.12:5000`  
**Auth:** `X-API-Key: <IDS_API_KEY>` header  
**Interactive docs:** `http://192.168.10.12:5000/docs`

### Health

#### `GET /api/v1/health`

**Response:**
```json
{
  "status": "ok",
  "firewall_api_reachable": true,
  "version": "1.0"
}
```

---

### Blocking

#### `POST /api/v1/block`
Block an IP on both the Firewall (FORWARD) and Victim (INPUT).

**Request body:**
```json
{ "ip": "192.168.10.15", "reason": "manual" }
```

**Response (201):**
```json
{ "ip": "192.168.10.15", "firewall_ok": true, "victim_ok": true }
```

---

#### `DELETE /api/v1/block/{ip}`
Unblock an IP on Firewall + Victim. Removes from `blocked.json`.

**Response (200):**
```json
{ "ip": "192.168.10.15", "firewall_ok": true, "victim_ok": true }
```

---

#### `GET /api/v1/blocks`
List all entries in `runtime/blocked.json`.

**Response:**
```json
{
  "blocks": [
    {
      "ip": "192.168.10.15",
      "attack": "SYN_FLOOD",
      "severity": "CRITICAL",
      "confidence": 0.96,
      "reason": "SYN_FLOOD | attacker=192.168.10.15 ...",
      "timestamp": "2025-10-14T10:53:42+00:00"
    }
  ]
}
```

---

### Events

#### `GET /api/v1/attacks?n=200`
Return the last `n` attack log entries parsed from `ids.log`.

**Query params:** `n` (1–500, default 200)

**Response:** Array of `AttackEntry` objects:
```json
[
  {
    "attack": "SYN_FLOOD",
    "attacker": "192.168.10.15",
    "victim": "192.168.10.14",
    "severity": "CRITICAL",
    "confidence": 0.96,
    "timestamp": "2025-10-14 10:53:42",
    "details": {}
  }
]
```

---

### Whitelist

#### `GET /api/v1/whitelist`
```json
{ "whitelist": ["192.168.10.1", "192.168.10.12"] }
```

#### `POST /api/v1/whitelist`
```json
{ "ip": "192.168.10.99" }
```
Response (201): `{ "added": "192.168.10.99" }`

#### `DELETE /api/v1/whitelist/{ip}`
Response (200): `{ "removed": "192.168.10.99" }`  
Response (404): IP not in whitelist.

---

### Config (Dynamic Thresholds)

#### `GET /api/v1/config/thresholds`
```json
{
  "thresholds": {
    "syn_flood":       { "threshold": 25, "window_seconds": 5 },
    "ssh_brute_force": { "threshold": 8,  "window_seconds": 60 }
  }
}
```

#### `PATCH /api/v1/config/thresholds`
Partial update — only provided keys are changed.

**Request:**
```json
{ "syn_flood": { "threshold": 50 } }
```

**Response:** Updated full thresholds object.  
**Side effect:** Writes `runtime/thresholds.json` → picked up by the Monitor's Scheduler within ~30 s.

---

### Stats

#### `GET /api/v1/stats`
Returns the latest `runtime/stats.json` (updated every 5 minutes by Scheduler).

```json
{
  "stats": {
    "generated_at": "2025-10-14T11:00:00+00:00",
    "total_blocked": 3,
    "by_attack_type": { "SYN_FLOOD": 2, "XMAS_SCAN": 1 },
    "by_severity":    { "CRITICAL": 2, "LOW": 1 }
  }
}
```

---

### System Statistics & Real-Time Stream

#### `GET /api/v1/system/stats`
Returns current CPU and virtual memory usage percentages on the Monitor VM.

**Response:**
```json
{
  "cpu": 12.5,
  "memory": 64.2
}
```

---

#### `POST /api/v1/events` (Internal)
Internal webhook used by the Monitor VM when an alert is processed to broadcast it to connected clients.

**Request body:** (Serialized `DetectionEvent` dictionary)
```json
{
  "attack": "SYN_FLOOD",
  "attacker": "192.168.10.15",
  "victim": "192.168.10.14",
  "severity": "CRITICAL",
  "confidence": 1.0,
  "timestamp": "2026-07-07T18:45:00Z",
  "details": {
    "packet_count": 30,
    "window_seconds": 5
  }
}
```

**Response (202):**
```json
{
  "status": "broadcasted"
}
```

---

#### `GET /api/v1/ws` (WebSocket)
WebSocket connection endpoint for real-time alert broadcasts.
Due to standard browser limitations, authentication is verified via the `token` URL query parameter.

**Connection URL format:**
`ws://<IDS_API_HOST>:5000/api/v1/ws?token=<IDS_API_KEY>`

**Broadcast payload format:**
Real-time JSON events identical to the `DetectionEvent` structure are pushed down as text frames whenever a new alert occurs.

---

## Authentication Notes

- Both APIs use the `X-API-Key` header scheme.
- Keys are stored in `.env` and never in `config.yaml`.
- Generate strong keys: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- The Dashboard reads `IDS_API_KEY` from its environment (same `.env` file).
- The Monitor reads `FIREWALL_API_KEY` to authenticate to the Firewall API.
