# Mini IDRS — Linux Firewall VM Setup Guide

This document replaces the old `ROUTER_CONFIG.md` (Cisco IOS).  
No GNS3 or Cisco router required — this guide sets up an Ubuntu/Debian VM as a  
**Linux Firewall** using `nftables`, `dnsmasq`, and the Mini IDRS Firewall REST API.

---

## VM Creation in VMware Workstation Pro

1. **Create a new VM** — Ubuntu Server 22.04 LTS (minimal install), 1 vCPU, 1 GB RAM.
2. **Add two network adapters**:
   - **NIC 1 (eth0)** → VMnet2 (Host-Only) — internal lab segment
   - **NIC 2 (eth1)** → VMnet8 (NAT) — internet access
3. **Install Ubuntu** — create a user (e.g. `fwadmin`). **Do NOT use default passwords.**

---

## Basic System Setup

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nftables dnsmasq python3 python3-pip python3-venv git curl
```

---

## Static IP on Internal Interface (eth0)

Edit `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
      addresses: [192.168.10.1/24]
    eth1:
      dhcp4: yes   # gets IP from VMnet8 NAT
```

Apply:
```bash
sudo netplan apply
```

Verify:
```bash
ip addr show eth0   # should show 192.168.10.1/24
ip route            # should show default via VMnet8 gateway
```

---

## IP Forwarding (routing between eth0 and eth1)

```bash
# Enable now
sudo sysctl -w net.ipv4.ip_forward=1

# Persist across reboots
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## nftables Setup

### Create the base ruleset

```bash
sudo nft flush ruleset

sudo nft add table inet filter
sudo nft add chain inet filter INPUT   '{ type filter hook input priority 0; policy accept; }'
sudo nft add chain inet filter FORWARD '{ type filter hook forward priority 0; policy accept; }'
sudo nft add chain inet filter OUTPUT  '{ type filter hook output priority 0; policy accept; }'

# NAT table for masquerade
sudo nft add table ip nat
sudo nft add chain ip nat POSTROUTING '{ type nat hook postrouting priority 100; }'
sudo nft add rule  ip nat POSTROUTING oifname "eth1" masquerade
```

### Persist the ruleset

```bash
sudo nft list ruleset | sudo tee /etc/nftables.conf
sudo systemctl enable nftables
sudo systemctl start  nftables
```

### Verify

```bash
sudo nft list ruleset
ping 8.8.8.8            # from Firewall VM — internet access via eth1
ping 192.168.10.12      # from Firewall VM — reach Monitor VM
```

---

## dnsmasq — DHCP + DNS for the Lab

Edit `/etc/dnsmasq.conf`:

```ini
# Listen only on the internal interface
interface=eth0
bind-interfaces

# DHCP pool for lab VMs (192.168.10.10 – 192.168.10.200)
dhcp-range=192.168.10.10,192.168.10.200,255.255.255.0,12h

# Default gateway = this Firewall VM
dhcp-option=3,192.168.10.1

# DNS server
dhcp-option=6,8.8.8.8

# Static DHCP leases (optional but recommended for consistency)
# dhcp-host=<mac>,192.168.10.12,monitor
# dhcp-host=<mac>,192.168.10.14,victim

# Don't forward local queries upstream
local=/lab.local/
domain=lab.local
```

Enable and start:
```bash
sudo systemctl enable dnsmasq
sudo systemctl start  dnsmasq
sudo systemctl status dnsmasq
```

---

## Firewall REST API Deployment

The Firewall API (`firewall_api/server.py`) runs on this VM and is the only process
that calls `nft`. It is **bound to 192.168.10.1:8080** (internal interface only).

### Clone the repository

```bash
cd /opt
sudo git clone https://github.com/VishvaNarkar/Mini-IDRS.git
sudo chown -R fwadmin:fwadmin /opt/Mini-IDRS
cd /opt/Mini-IDRS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure secrets

```bash
cp .env.example .env
nano .env          # Set a strong FIREWALL_API_KEY — share it with Monitor .env
```

### Allow the API user passwordless nft access

```bash
sudo visudo
# Add this line (replace fwadmin with your username):
fwadmin ALL=(ALL) NOPASSWD: /usr/sbin/nft
```

### Create systemd service

```ini
# /etc/systemd/system/idrs-firewall-api.service
[Unit]
Description=Mini IDRS Firewall REST API
After=network.target nftables.service

[Service]
Type=simple
User=fwadmin
WorkingDirectory=/opt/Mini-IDRS
EnvironmentFile=/opt/Mini-IDRS/.env
ExecStart=/opt/Mini-IDRS/venv/bin/uvicorn firewall_api.server:app \
    --host 192.168.10.1 --port 8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable idrs-firewall-api
sudo systemctl start  idrs-firewall-api
sudo systemctl status idrs-firewall-api
```

---

## Smoke Tests

```bash
# From the Monitor VM (or any internal VM):
curl -H "X-API-Key: your-key" http://192.168.10.1:8080/api/v1/health
# Expected: {"status":"ok","version":"1.0"}

curl -H "X-API-Key: your-key" http://192.168.10.1:8080/api/v1/rules
# Expected: {"rules":[]}

# Block a test IP
curl -X POST -H "X-API-Key: your-key" -H "Content-Type: application/json" \
     -d '{"ip":"192.168.10.99"}' \
     http://192.168.10.1:8080/api/v1/rules
# Expected: {"blocked":"192.168.10.99"}

# Verify in nftables
sudo nft list chain inet filter FORWARD
# Expected: rule with "ip saddr 192.168.10.99 drop comment "idrs-block:192.168.10.99""

# Remove the test block
curl -X DELETE -H "X-API-Key: your-key" \
     http://192.168.10.1:8080/api/v1/rules/192.168.10.99
```

---

## Security Notes

- The Firewall API is bound to `192.168.10.1:8080` only — it is **not reachable from internet**.
- Use a strong, randomly generated `FIREWALL_API_KEY` (e.g. `python3 -c "import secrets; print(secrets.token_hex(32))"`).
- Never expose port 8080 on the external interface (eth1).
- Monitor SSH access to this VM (it's the most privileged host in the lab).
