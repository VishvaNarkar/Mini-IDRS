# docs/development.md — Mini-IDRS Development Guide

## Adding a New Detection Plugin

Plugins live in `plugins/`. Each file is one detector. No core changes needed.

### Steps

1. **Create `plugins/my_detector.py`**

```python
from __future__ import annotations
from typing import Optional
from scapy.packet import Packet
from core.events import DetectionEvent, Severity
from plugins.base import BaseDetector, DetectionContext

class MyDetector(BaseDetector):
    name     = "MY_ATTACK"
    severity = Severity.MEDIUM

    def handle_packet(self, pkt: Packet, ctx: DetectionContext) -> Optional[DetectionEvent]:
        # Inspect the packet.
        # Return DetectionEvent if attack detected, else None.
        src = pkt["IP"].src if pkt.haslayer("IP") else None
        if not src or src in ctx.whitelist:
            return None

        # ... detection logic ...

        if attack_detected:
            return DetectionEvent(
                attack     = self.name,
                attacker   = src,
                victim     = pkt["IP"].dst,
                severity   = self.severity,
                confidence = 0.85,
                details    = {"extra_info": "value"},
            )
        return None

    def reset(self, ip=None):
        # Clear any per-IP state (sliding windows etc.)
        if ip is None:
            self._state.clear()
        else:
            self._state.pop(ip, None)
```

2. **Register in `idrs_monitor.py`**

```python
from plugins.my_detector import MyDetector

plugins = [
    XmasScanDetector(),
    SynFloodDetector(),
    SshBruteForceDetector(),
    MyDetector(),          # ← add here
]
```

3. **Add severity mapping in `ids_api/server.py`**

```python
_SEV_MAP["MY_ATTACK"] = "MEDIUM"
```

4. **Add a color in `dashboard/js/charts.js`** (optional):

Update `_getThemeColors()` color lists in `dashboard/js/charts.js`.

That's it. The EventPipeline, Logger, BlockStore, and Firewall Manager
all receive the event automatically.

---

## Adding a New Firewall Backend

Firewall backends live in `core/firewall.py`.

### Steps

1. **Subclass `FirewallBackend`**

```python
class MyFirewallBackend(FirewallBackend):
    def block(self, ip: str) -> bool:
        # Add a deny rule on your firewall
        ...
        return True

    def unblock(self, ip: str) -> bool:
        # Remove the deny rule
        ...
        return True

    def list_rules(self) -> list[str]:
        # Return list of currently blocked IPs
        ...
        return []
```

2. **Instantiate in `idrs_monitor.py`**

```python
firewall_mgr = FirewallManager(MyFirewallBackend(...))
```

No other changes required. `EventPipeline`, `IDS API`, and `Dashboard` are
completely unaffected — they always call `FirewallManager.block()`.

---

## Config Structure

- `config.yaml` — non-secrets (IPs, thresholds, paths). Gitignored; ship as `config.yaml.example`.
- `.env` — secrets (API keys, SSH passwords). Always gitignored; ship as `.env.example`.
- `core/config.py` — loads both; exposes the `cfg` singleton.

Import the config anywhere:
```python
from core.config import cfg
print(cfg.network.victim_ip)
```

---

## Testing a Detector with Replay

Capture a live attack:
```bash
sudo tcpdump -i ens33 -w runtime/pcaps/test.pcap
# Run attack from Kali, then Ctrl-C
```

Replay offline:
```bash
# Dry-run — detect only, no blocking
python tools/replay.py --pcap runtime/pcaps/test.pcap --dry-run

# Only show HIGH and CRITICAL events
python tools/replay.py --pcap runtime/pcaps/test.pcap --dry-run --min-severity HIGH
```

---

## Code Style

- Follow **PEP 8**.
- Use **type hints** throughout.
- Keep functions small and well-commented.
- Log using `logging.getLogger(__name__)` — never `print()` in library code.
- Never commit secrets — keep them in `.env`.
- Document new plugins in `CONTRIBUTING.md`.
