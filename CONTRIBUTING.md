# Contributing to Mini IDRS

Thank you for contributing to **Mini IDRS** — a modular, educational  
Intrusion Detection & Response System built on Python and VMware.

---

## Workflow

```bash
# 1. Fork and clone
git clone https://github.com/VishvaNarkar/Mini-IDRS.git
cd Mini-IDRS

# 2. Create a feature branch
git checkout -b feature/<name>

# 3. Set up environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml
cp .env.example .env   # fill in test values

# 4. Make changes → commit → push
git add .
git commit -m "feat: describe your change"
git push origin feature/<name>

# 5. Open a Pull Request on GitHub
```

---

## Development Setup

- Python 3.11+
- VMware Workstation Pro (no GNS3 required)
- See [docs/deployment.md](docs/deployment.md) for full lab setup

Run the IDS monitor:
```bash
sudo venv/bin/python idrs_monitor.py -i ens33
```

Run the IDS API:
```bash
uvicorn ids_api.server:app --host 0.0.0.0 --port 5000 --reload
```

Run the dashboard (either served automatically by FastAPI, or locally using python http.server):
```bash
# Served by FastAPI: http://localhost:5000/dashboard/index.html
# Or served stand-alone:
cd dashboard && python -m http.server 8080
```

---

## Code Style

- Follow **PEP 8**
- Use **type hints** on all functions and class attributes
- Use `logging.getLogger(__name__)` — never `print()` in library code
- Keep functions focused and well-commented, especially detection logic
- Never commit secrets — everything sensitive goes in `.env`

---

## Adding a Detection Plugin

1. Create `plugins/<attack_name>.py` — subclass `BaseDetector`
2. Return a `DetectionEvent` when the attack is detected, `None` otherwise
3. Register it in `idrs_monitor.py` (`plugins` list)
4. Add severity mapping in `ids_api/server.py` (`_SEV_MAP`)
5. Optionally add a color map in `dashboard/js/charts.js`

Full walkthrough → [docs/development.md](docs/development.md)

---

## Adding a Firewall Backend

1. Subclass `FirewallBackend` in `core/firewall.py`
2. Implement `block()`, `unblock()`, `list_rules()`
3. Swap the backend in `idrs_monitor.py`

No other changes needed — the pipeline, API, and dashboard are unaffected.

---

## Testing

Use the PCAP replay tool to test detectors without live attacks:

```bash
# Capture attacks
sudo tcpdump -i ens33 -w runtime/pcaps/test.pcap

# Replay with dry-run (no actual blocking)
python tools/replay.py --pcap runtime/pcaps/test.pcap --dry-run --min-severity LOW
```

Verify detections in `runtime/logs/ids.log` and check `runtime/blocked.json`.

Verify Firewall rules on the Linux Firewall VM:
```bash
sudo nft list chain inet filter FORWARD
```

Verify Victim iptables:
```bash
sudo iptables -L INPUT -n -v
```

---

## Contribution Ideas

- New detector plugins: UDP flood, ICMP flood, ARP spoofing, port scan, DNS amplification
- SQLite backend for `BlockStore` (interface is ready — just swap `persistence.py`)
- Email / Slack / Telegram alerting on CRITICAL events
- TTL-based block expiry (Scheduler job stub already exists)
- ELK stack log shipper
- JWT authentication for IDS API (upgrade from simple API key)
- Unit tests for detection plugins using PCAP fixtures

---

## Reporting Issues

1. Verify the issue is reproducible
2. Open a GitHub Issue with:
   - Steps to reproduce
   - Log excerpt from `runtime/logs/ids.log`
   - Expected vs actual behaviour
   - Screenshot if applicable

---

## Code of Conduct

- Be respectful and constructive
- Do not share real credentials or production IP addresses
- This is an educational project — keep it that way

---

## Acknowledgements

Developed as part of the **iM.Sc. IT Architecture & Network Security** programme  
at **Gujarat University**. Educational collaborations and feedback are welcome.