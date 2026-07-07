# docs/deployment.md — Mini-IDRS Deployment Guide

## Prerequisites

- VMware Workstation Pro (no GNS3, no Cisco router required)
- 4 VMs: Linux Firewall, Monitor, Victim, Attacker
- Python 3.11+ on Monitor and Firewall VMs

---

## Step 1 — VMware Network Setup

Open **Virtual Network Editor** (run as Administrator):

| VMnet | Type | Subnet | DHCP |
|-------|------|--------|------|
| VMnet2 | Host-Only | 192.168.10.0/24 | **Disabled** (dnsmasq handles it) |
| VMnet8 | NAT | (default) | Enabled |

Configure each VM's network adapters:

| VM | NIC 1 | NIC 2 |
|----|-------|-------|
| Linux Firewall | VMnet2 (eth0) | VMnet8 (eth1) |
| Monitor | VMnet2 | — |
| Victim | VMnet2 | — |
| Attacker (Kali) | VMnet2 | — |

---

## Step 2 — Linux Firewall VM

See **GATEWAY_CONFIG.md** for the complete setup guide covering:
- Static IP on eth0 (`192.168.10.1/24`)
- IP forwarding
- nftables table + chains + NAT masquerade
- dnsmasq DHCP pool
- Firewall REST API as a systemd service

---

## Step 3 — Monitor VM Setup

```bash
# Get an IP from dnsmasq (or set static 192.168.10.12)
sudo dhclient eth0

# Clone the repo
git clone https://github.com/VishvaNarkar/Mini-IDRS.git
cd Mini-IDRS

# Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Config
cp config.yaml.example config.yaml
nano config.yaml    # set monitor_ip, victim_ip, firewall_ip

cp .env.example .env
nano .env           # set FIREWALL_API_KEY (same as Firewall VM), IDS_API_KEY,
                    # VICTIM_SSH_USER, VICTIM_SSH_PASS

# Create runtime directories
mkdir -p runtime/logs runtime/pcaps runtime/cache

# Create initial whitelist (your own IPs won't be blocked)
echo "192.168.10.1"  >  runtime/whitelist.txt   # Linux Firewall
echo "192.168.10.12" >> runtime/whitelist.txt   # Monitor (this host)
```

---

## Step 4 — Victim VM Setup

```bash
# Get an IP or set static 192.168.10.14
sudo dhclient eth0

# Enable SSH
sudo apt install openssh-server -y
sudo systemctl enable --now ssh

# Allow passwordless sudo for iptables (required by VictimBlocker)
sudo visudo
# Add this line (replace 'victim' with your username):
victim ALL=(ALL) NOPASSWD: /sbin/iptables, /usr/sbin/iptables
```

---

## Step 5 — Running the System

### On Monitor VM — three separate terminals:

**Terminal 1 — IDS Monitor (requires root for packet capture):**
```bash
cd ~/Mini-IDRS
source venv/bin/activate
sudo -E python idrs_monitor.py -i ens33
```
> `-E` preserves the virtual environment when running with sudo.

**Terminal 2 — IDS REST API:**
```bash
cd ~/Mini-IDRS
source venv/bin/activate
uvicorn ids_api.server:app --host 0.0.0.0 --port 5000
```

**Terminal 3 — Dashboard (Optional: if serving stand-alone):**
```bash
cd ~/Mini-IDRS/dashboard
python -m http.server 8080
# Open http://192.168.10.12:8080 in a browser
# Alternatively, open: http://192.168.10.12:5000/dashboard/index.html
```

### Or with Docker:
```bash
# On Monitor VM (after installing Docker)
docker compose up -d
# Dashboard is available at: http://192.168.10.12:5000/dashboard/index.html
```

---

## Step 6 — Attack Simulation (Kali VM)

> **Warning:** Run these commands **only in the lab environment**.

```bash
# XMAS Scan (Severity: LOW)
nmap -sX 192.168.10.14

# SYN Flood (Severity: CRITICAL)
sudo hping3 -S 192.168.10.14 -p 22 --flood

# SSH Brute-Force (Severity: HIGH)
hydra -l root -P wordlist.txt ssh://192.168.10.14
```

---

## Step 7 — Verification

**Check attack log:**
```bash
tail -f runtime/logs/ids.log
```

**Check Firewall rules (on Linux Firewall VM):**
```bash
sudo nft list chain inet filter FORWARD
```

**Check Victim iptables:**
```bash
sudo iptables -L INPUT -n -v
```

**IDS API — list blocked IPs:**
```bash
curl -H "X-API-Key: your-key" http://192.168.10.12:5000/api/v1/blocks
```

**Dashboard:** Open `http://192.168.10.12:5000/dashboard/index.html` (or `http://192.168.10.12:8080` if serving stand-alone)


---

## Unblocking an IP

**Via Dashboard:** Use the "Unblock IP" field in the Manual IP Control section.

**Via IDS API:**
```bash
curl -X DELETE -H "X-API-Key: your-key" \
     http://192.168.10.12:5000/api/v1/block/192.168.10.15
```

**Via PCAP Replay (offline testing):**
```bash
python tools/replay.py --pcap runtime/pcaps/capture.pcap --dry-run
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Permission denied` on sniff | Run monitor with `sudo` |
| Interface not found | `ip link show` or `python3 -c "from scapy.all import get_if_list; print(get_if_list())"` |
| Firewall API unreachable | Check systemd service: `sudo systemctl status idrs-firewall-api` |
| Victim SSH auth error | Verify `VICTIM_SSH_USER`/`VICTIM_SSH_PASS` in `.env` |
| IDS API returns 401 | Check `IDS_API_KEY` in `.env` matches what Dashboard uses |
| No DHCP on VMs | Verify dnsmasq is running on Firewall VM: `sudo systemctl status dnsmasq` |
| IP forwarding not working | `cat /proc/sys/net/ipv4/ip_forward` should be `1` |
| False positives | Adjust `SYN_THRESHOLD`/`SSH_THRESHOLD` via Dashboard threshold sliders |
| Dashboard Connection Error | Ensure IDS API is running and configured URL/key are correct in Settings |

