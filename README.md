# Mini Intrusion Detection & Response System (IDRS)

**A modular, Python-based IDS/IPS lab system built for VMware Workstation Pro.**  

---

## Project Overview

Mini-IDRS is an educational cybersecurity project that:

- Captures live network traffic with **Scapy**
- Detects attacks using a **plugin-based engine** (each detector is an independent module)
- Responds automatically via a **dual-layer block**:
  - Linux Firewall VM — `nftables FORWARD` DROP rule (via Firewall REST API)
  - Victim VM — `iptables INPUT` DROP rule (via Paramiko SSH)
- Exposes a **REST API** (FastAPI) for programmatic control
- Provides a **custom SOC dashboard** (HTML/CSS/JS) served directly from the IDS API (FastAPI) or stand-alone, featuring real-time WebSockets and Apache ECharts visualizations.
- Persists blocked IPs to `runtime/blocked.json` — state survives monitor restarts
- Supports **PCAP replay** for testing new detection logic without live attacks

---

## Key Features

| Feature | Detail |
|---------|--------|
| **Real-time detection** | Scapy packet analysis, plugin per attack type |
| **Modular plugins** | Add detectors by dropping a file in `plugins/` |
| **FirewallManager abstraction** | Swap nftables → iptables → pfSense without touching IDS logic |
| **REST API control plane** | Versioned (`/api/v1/`), authenticated (`X-API-Key`) |
| **Dashboard → IDS API only** | Dashboard has zero firewall/SSH knowledge |
| **Persistence** | `blocked.json` survives restarts; SQLite-ready interface |
| **Dynamic thresholds** | Update SYN/SSH thresholds live via dashboard sliders |
| **PCAP Replay** | Replay captures through the full pipeline (`--dry-run` mode) |
| **APScheduler** | Background jobs: health check, whitelist reload, stats, cleanup |
| **Docker support** | `docker compose up` starts monitor + IDS API (hosting the dashboard) |
| **No GNS3/Cisco** | Pure VMware — one Linux Firewall VM replaces the entire emulated router |

---

## Architecture

```
[Kali Attacker VM]  ──┐
[Ubuntu Victim VM]    ─┼── VMnet2 (Host-Only, 192.168.10.0/24)
[Ubuntu Monitor VM]   ─┘         │
                                   ▼
                       ┌──────────────────────────┐
                       │     Linux Firewall VM    │
                       │  eth0: 192.168.10.1/24   │ ← dnsmasq DHCP
                       │  eth1: DHCP (VMnet8)     │ ← NAT / internet
                       │  nftables FORWARD chain  │ ← drops attacker traffic
                       │  Firewall API :8080       │ ← internal-only, API-key auth
                       └──────────────────────────┘
                                   │
                               VMnet8 (NAT) → Internet
```

**Control flow:**
```
Dashboard → IDS API → FirewallManager → Firewall API → nftables
IDS Monitor → detects → EventPipeline → FirewallManager + VictimBlocker
```

See [docs/architecture.md](docs/architecture.md) for full diagrams and component map.

---

## Project Structure

```
Mini-IDRS/
├── core/              IDS engine modules
├── plugins/           Detection plugins (one per attack type)
├── ids_api/           IDS REST API (Monitor VM)
├── firewall_api/      Firewall REST API (Linux Firewall VM)
├── tools/             PCAP replay tool
├── docs/              Architecture, API, development, deployment guides
├── runtime/           Generated files (logs, blocked.json, pcaps) — gitignored
├── config.yaml.example  Non-secret config template
├── .env.example          Secrets template
├── idrs_monitor.py    Entry point
├── dashboard/         Pure HTML/CSS/JS SOC Dashboard frontend
├── requirements.txt
├── docker-compose.yml
└── GATEWAY_CONFIG.md  Linux Firewall VM setup guide
```

---

## Prerequisites

- **VMware Workstation Pro** (no GNS3 required)
- **4 VMs**: Linux Firewall (Ubuntu), Monitor (Ubuntu), Victim (Ubuntu), Attacker (Kali)
- **Python 3.11+** on Monitor and Linux Firewall VMs
- Root/sudo on Monitor VM (for Scapy raw socket sniffing)

---

## Quick Start

### 1. Linux Firewall VM
Follow [GATEWAY_CONFIG.md](GATEWAY_CONFIG.md) — sets up nftables, dnsmasq, and the Firewall API service.

### 2. Monitor VM

```bash
git clone https://github.com/VishvaNarkar/Mini-IDRS.git
cd Mini-IDRS
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml   # Edit IPs
cp .env.example .env                  # Edit secrets (API keys, SSH creds)

# Create runtime directories + initial whitelist
mkdir -p runtime/logs runtime/pcaps runtime/cache
echo "192.168.10.1"  >  runtime/whitelist.txt   # Firewall VM
echo "192.168.10.12" >> runtime/whitelist.txt   # Monitor (this host)
```

### 3. Victim VM

```bash
sudo apt install openssh-server -y
sudo visudo  # Add: victim ALL=(ALL) NOPASSWD: /sbin/iptables
```

### 4. Run (three terminals on Monitor VM)

```bash
# Terminal 1 — IDS Monitor
sudo -E python idrs_monitor.py -i ens33

# Terminal 2 — IDS API (serves dashboard at http://localhost:5000/dashboard/index.html)
uvicorn ids_api.server:app --host 0.0.0.0 --port 5000

# Terminal 3 — Standalone Dashboard Web Server (Optional fallback)
cd dashboard && python -m http.server 8080
# Open http://192.168.10.12:8080 in a browser
```

Or with Docker:
```bash
docker compose up -d
# Dashboard is available at: http://192.168.10.12:5000/dashboard/index.html
```

---

## Detection Capabilities

| Attack | Method | Severity | Default Threshold |
|--------|--------|----------|------------------|
| **XMAS Scan** | TCP FIN+PSH+URG flags | LOW | Immediate (any packet) |
| **SYN Flood** | Sliding window SYN count | CRITICAL | 25 SYNs / 5 seconds |
| **SSH Brute-Force** | TCP handshake tracking on port 22 | HIGH | 8 handshakes / 60 seconds |

Thresholds are adjustable live via the dashboard — no restart required.

---

## Attack Simulation (Kali VM only)

> **Warning:** Use in a controlled lab environment only.

```bash
nmap -sX 192.168.10.14                              # XMAS scan
sudo hping3 -S 192.168.10.14 -p 22 --flood         # SYN flood
hydra -l root -P wordlist.txt ssh://192.168.10.14  # SSH brute-force
```

**Verify blocks:**
```bash
# Firewall VM
sudo nft list chain inet filter FORWARD

# Victim VM
sudo iptables -L INPUT -n -v

# IDS API
curl -H "X-API-Key: your-key" http://192.168.10.12:5000/api/v1/blocks
```

---

## PCAP Replay

Test new detectors without live attacks:
```bash
# Capture
sudo tcpdump -i ens33 -w runtime/pcaps/session.pcap

# Replay with dry-run (no blocking)
python tools/replay.py --pcap runtime/pcaps/session.pcap --dry-run

# Full pipeline replay
python tools/replay.py --pcap runtime/pcaps/session.pcap
```

---

## Documentation

| File | Contents |
|------|----------|
| [docs/architecture.md](docs/architecture.md) | System design, diagrams, component map |
| [docs/api.md](docs/api.md) | Full API reference (both APIs) |
| [docs/development.md](docs/development.md) | Adding plugins and firewall backends |
| [docs/deployment.md](docs/deployment.md) | Step-by-step lab setup |
| [GATEWAY_CONFIG.md](GATEWAY_CONFIG.md) | Linux Firewall VM configuration |

---

## Security Notes

- Credentials go in `.env` — never in `config.yaml` or source code
- Generate strong API keys: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- The Firewall API is bound to the internal interface only (`192.168.10.1:8080`)
- Do not use in production — this is a lab/educational system

---

## Future Improvements

- SQLite database (swap `BlockStore` backend — interface is ready)
- TTL-based block expiry (`_cleanup_blocks` job is already scheduled)
- nftables via Unix socket instead of HTTP (for even tighter security)
- Threat intelligence integration (AbuseIPDB)
- ML-based anomaly detection plugin
- Additional detectors: UDP flood, ICMP flood, ARP spoofing, port scan

---

## Libraries Used

`scapy` · `paramiko` · `fastapi` · `uvicorn` · `pyyaml` · `python-dotenv` · `requests` · `apscheduler` · `psutil` · `websockets`

---

## License

MIT License — see `LICENSE`.

---

## Authors

**Vishva Narkar** — Student  
**Himesh Nayak** — Student

*iM.Sc. IT Architecture & Network Security — Gujarat University*

---

## Acknowledgements

Thanks to the open-source communities behind Scapy, Paramiko, FastAPI, and Apache ECharts.
