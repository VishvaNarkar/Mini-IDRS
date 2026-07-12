# docs/architecture.md — Mini-IDRS System Architecture

## Overview

Mini-IDRS is a modular, Python-based Intrusion Detection & Response System
built for an educational VMware-only lab environment.

It detects network attacks in real time, responds automatically, and provides a
web dashboard for monitoring and control.

---

## Network Topology

```
[Kali Attacker VM]  ──┐
[Ubuntu Victim VM]    ─┼── VMnet2 (Host-Only, 192.168.10.0/24)
[Ubuntu Monitor VM]   ─┘         │
                                   ▼
                       ┌──────────────────────────┐
                       │     Linux Firewall VM    │
                       │  ens34: 192.168.10.1/24  │ ← dnsmasq (DHCP + DNS)
                       │  ens33: DHCP (VMnet8)    │ ← NAT / masquerade
                       │  nftables FORWARD+INPUT  │ ← drops attacker traffic
                       │  Firewall API :8080       │ ← internal only, API-key auth
                       └──────────────────────────┘
                                   │
                               VMnet8 (NAT) → Internet
```

| VM | Role | Default IP |
|----|------|-----------|
| Linux Firewall | Routes traffic, runs nftables + dnsmasq + Firewall API | 192.168.10.1 |
| Monitor | Runs IDS engine, IDS API, Dashboard | 192.168.10.12 |
| Victim | SSH target, protected by iptables INPUT | 192.168.10.14 |
| Attacker | Kali Linux — launches nmap, hping3, hydra | DHCP from pool |

---

## Control Plane

```
┌─────────────┐
│  Dashboard  │  Pure HTML/CSS/JS (FastAPI served :5000/dashboard/index.html)
└──────┬──────┘
       │ HTTP / WS (token auth)
       ▼
┌─────────────────────┐     ┌───────────────┐
│     IDS API         │────►│  BlockStore   │ runtime/blocked.json
│  FastAPI :5000      │     └───────────────┘
│  (Monitor VM)       │     ┌───────────────┐
└──────┬──────────────┘────►│  Whitelist    │ runtime/whitelist.txt
       │  ▲                 └───────────────┘
       │  │ HTTP POST /api/v1/events (Threaded notify)
       │  │
       │  │             ┌───────────────┐
       │  └─────────────│  IDS Monitor  │ (runs independently)
       │                └───────────────┘
       │ HTTP  X-API-Key
       ▼
┌──────────────────────┐
│    Firewall API      │  FastAPI :8080 — bound to 192.168.10.1 only
│  (Linux Firewall VM) │  systemd service
└──────┬───────────────┘
       │ subprocess
       ▼
   nftables FORWARD and INPUT chains — DROP rules per blocked IP



IDS Monitor (runs independently on Monitor VM):

PacketCapture (Scapy sniff loop)
    │  raw packet
    ▼
[XmasScanDetector]   →  DetectionEvent (severity=LOW)
[SynFloodDetector]   →  DetectionEvent (severity=CRITICAL)
[SshBruteForce...]   →  DetectionEvent (severity=HIGH)
    │
    ▼
EventPipeline.process(event)
    ├── WhitelistManager  — skip if whitelisted
    ├── BlockStore.is_blocked — skip if already blocked
    ├── Logger            — write to runtime/logs/ids.log
    ├── FirewallManager   → HTTP → Firewall API → nftables FORWARD + INPUT DROP
    ├── VictimBlocker     → SSH  → iptables INPUT DROP
    └── BlockStore.add    — persist to runtime/blocked.json

Scheduler (APScheduler, background thread):
    ├── every 60s   → health_check()       ping Firewall API
    ├── every 30s   → reload_whitelist()   hot-reload whitelist.txt
    ├── every 30s   → reload_thresholds()  read runtime/thresholds.json
    ├── every 5min  → aggregate_stats()    write runtime/stats.json
    └── every 1h    → cleanup_blocks()     TTL expiry (future)
```

---

## Module Map

```
core/
  config.py         Config singleton (config.yaml + .env)
  events.py         DetectionEvent, Severity enum
  logger.py         Rotating file + console logging
  whitelist.py      WhitelistManager (thread-safe, hot-reload)
  persistence.py    BlockStore (blocked.json, SQLite-ready)
  firewall.py       FirewallBackend ABC, NftablesAPIBackend, FirewallManager
  victim.py         VictimBlocker (Paramiko SSH → iptables)
  pipeline.py       EventPipeline (routes DetectionEvent to all consumers)
  packet_capture.py PacketCapture (Scapy sniff + plugin dispatcher)
  scheduler.py      IDRSScheduler (APScheduler background jobs)

plugins/
  base.py           BaseDetector ABC, DetectionContext
  xmas_scan.py      XMAS scan → Severity.LOW
  syn_flood.py      SYN flood → Severity.CRITICAL
  ssh_brute_force.py SSH brute-force → Severity.HIGH

ids_api/
  server.py         FastAPI IDS API (/api/v1/)
  auth.py           X-API-Key dependency
  models.py         Pydantic request/response models

firewall_api/
  server.py         FastAPI Firewall API (/api/v1/)
  auth.py           X-API-Key dependency
  models.py         Pydantic models
  nftables.py       nft subprocess wrapper

tools/
  replay.py         PCAP → DetectionEvent → full EventPipeline
```

---

## DetectionEvent Model

Every component in the system consumes this single model:

```python
@dataclass
class DetectionEvent:
    attack:     str        # "SYN_FLOOD" | "XMAS_SCAN" | "SSH_BRUTE_FORCE"
    attacker:   str        # source IP
    victim:     str        # destination IP
    severity:   Severity   # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float      # 0.0 – 1.0
    timestamp:  datetime
    details:    dict       # plugin-specific metadata
```

| Detector | Severity | Confidence |
|----------|----------|-----------|
| XMAS Scan | LOW | 1.0 (flag is unambiguous) |
| SSH Brute-Force | HIGH | min(1.0, count/threshold) |
| SYN Flood | CRITICAL | min(1.0, count/threshold) |

---

## Defense-in-Depth

When an attack is detected, blocking happens in **two places**:

1. **Linux Firewall VM** — `nftables FORWARD` (routed) and `INPUT` (direct) DROP rules via Firewall API.  
   Drops all traffic from the attacker before it enters the internal network or targets the gateway itself.

2. **Victim VM** — `iptables INPUT` DROP rule via SSH.  
   Second line of defence if the Firewall rule is temporarily bypassed.
