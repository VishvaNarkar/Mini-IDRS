import argparse
import logging
import sys
import threading
import time
import os
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, get_if_list
from netmiko import ConnectHandler
import paramiko

# ----------------------------- Configuration -----------------------------
ACL_NAME = "IDS_BLOCK_LIST"

ROUTER_IP = "192.168.10.1"
ROUTER_SSH_USER = "admin"
ROUTER_SSH_PASS = "admin"
ROUTER_SSH_PORT = 22

VICTIM_IP = "192.168.10.14"
VICTIM_SSH_USER = "victim"
VICTIM_SSH_PASS = "victim"
VICTIM_SSH_PORT = 22

MONITOR_IP = "192.168.10.12"

WHITELIST_FILE = "/home/monitor/Mini-IDRS/whitelist.txt"

VICTIM_IPTABLES_INSERT_RULE = "sudo iptables -I INPUT -s {ip} -j DROP"
VICTIM_IPTABLES_REMOVE_RULE = "sudo iptables -S INPUT | grep '{ip}' | while read -r rule; do sudo iptables ${{rule/-A/-D}}; done"

LOG_FILE = "/var/log/ids.log"
LOG_LEVEL = logging.INFO

# Detection thresholds
SYN_WINDOW_SECONDS = 5
SYN_THRESHOLD = 25
SSH_WINDOW_SECONDS = 60
SSH_THRESHOLD = 8

# -------------------------------------------------------------------------
# State tracking
blocked_ips = set()
_unblock_lock = threading.Lock()

syn_windows = defaultdict(lambda: deque())          # SYNs per attacker
syn_pending = defaultdict(lambda: deque())          # (src,dst,dport)
ssh_handshake_windows = defaultdict(lambda: deque())# confirmed SSH handshakes

# ----------------------------- Logging setup -----------------------------
logging.basicConfig(filename=LOG_FILE, level=LOG_LEVEL,
                    format="%(asctime)s [%(levelname)s] %(message)s")
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(console)

# ----------------------------- Whitelist Loader -----------------------------
def load_whitelist():
    wl = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    wl.add(ip)
    logging.info(f"[WHITELIST] Loaded whitelist: {wl}")
    return wl

MONITOR_EXEMPT = load_whitelist()

def should_skip_block(ip):
    if ip in MONITOR_EXEMPT:
        return True
    with _unblock_lock:
        if ip in blocked_ips:
            return True
    return False

# ----------------------------- SSH Helpers -----------------------------
def _ssh_run_cmd(host, port, username, password, cmd, timeout=20):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=timeout)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, stdout.read().decode(), stderr.read().decode()
    except Exception as e:
        logging.error(f"[SSH_RUN_CMD] error on {host}: {e}")
        return -1, "", str(e)
    finally:
        try:
            client.close()
        except Exception:
            pass

def block_ip_on_victim(attacker_ip):
    if attacker_ip in MONITOR_EXEMPT:
        return False, "exempt"
    cmd = VICTIM_IPTABLES_INSERT_RULE.format(ip=attacker_ip)
    exit_code, out, err = _ssh_run_cmd(VICTIM_IP, VICTIM_SSH_PORT, VICTIM_SSH_USER, VICTIM_SSH_PASS, cmd)
    if exit_code == 0:
        logging.info(f"[VICTIM] Blocked {attacker_ip} on victim.")
        with _unblock_lock:
            blocked_ips.add(attacker_ip)
        return True, "iptables rule inserted"
    logging.error(f"[VICTIM] iptables failed: {err}")
    return False, err

# ----------------------------- Router Helpers -----------------------------
def block_ip_on_router(attacker_ip):
    if attacker_ip in MONITOR_EXEMPT:
        return False, "exempt"
    device = {
        "device_type": "cisco_ios",
        "host": ROUTER_IP,
        "username": ROUTER_SSH_USER,
        "password": ROUTER_SSH_PASS,
        "port": ROUTER_SSH_PORT,
    }
    try:
        with ConnectHandler(**device) as ssh:
            cfg = [
                f"ip access-list extended {ACL_NAME}",
                f"deny ip host {attacker_ip} any",
                "exit"
            ]
            ssh.send_config_set(cfg)
            with _unblock_lock:
                blocked_ips.add(attacker_ip)
        logging.info(f"[ROUTER] Added deny for {attacker_ip}")
        return True, "router ACL updated"
    except Exception as e:
        logging.error(f"[ROUTER] Block failed: {e}")
        return False, str(e)

# ----------------------------- Block Logic -----------------------------
def block_attacker(attacker_ip):
    if should_skip_block(attacker_ip):
        logging.info(f"[BLOCK] Skip {attacker_ip} (whitelisted or already blocked)")
        return
    logging.info(f"[BLOCK] Triggering block for {attacker_ip}")
    v = block_ip_on_victim(attacker_ip)
    r = block_ip_on_router(attacker_ip)
    logging.info(f"[BLOCK_RESULT] {attacker_ip} router={r} victim={v}")

# ----------------------------- Detection Logic -----------------------------
def handle_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip, tcp = pkt[IP], pkt[TCP]
    src, dst, flags, dport, sport = ip.src, ip.dst, tcp.flags, tcp.dport, tcp.sport
    now = time.time()

    # ignore internal sources
    if src in MONITOR_EXEMPT:
        return

    # XMAS scan
    if flags == 0x29:
        logging.info(f"XMAS_SCAN | attacker={src} victim={dst}")
        block_attacker(src)
        return

    # SYN flood detection (many SYNs without ACKs)
    if flags & 0x02 and not (flags & 0x10):  # SYN set, ACK not set
        if dst == VICTIM_IP:
            dq = syn_windows[src]
            dq.append(now)
            while dq and dq[0] < now - SYN_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= SYN_THRESHOLD:
                logging.info(f"SYN_FLOOD | attacker={src} -> {dst} ({len(dq)} SYNs/{SYN_WINDOW_SECONDS}s)")
                block_attacker(src)
                dq.clear()
        return

    # Track SYN -> SYN-ACK -> ACK handshake for SSH brute-force
    # Step 1: SYN seen → record pending
    if flags & 0x02 and not (flags & 0x10):
        syn_pending[(src, dst, dport)].append(now)
        return

    # Step 2: SYN-ACK seen → mark half-open
    if flags & 0x12 == 0x12:
        if (dst, src, tcp.sport) in syn_pending:
            syn_pending[(dst, src, tcp.sport)].append(now)
        return

    # Step 3: ACK seen → complete handshake
    if flags & 0x10:
        if (dst, src, dport) in syn_pending and dport == 22:
            dq = ssh_handshake_windows[src]
            dq.append(now)
            while dq and dq[0] < now - SSH_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= SSH_THRESHOLD:
                logging.info(f"SSH_BRUTE_FORCE | attacker={src} -> victim={dst} ({len(dq)} handshakes/{SSH_WINDOW_SECONDS}s)")
                block_attacker(src)
                dq.clear()
        return

# ----------------------------- Main -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Mini IDRS monitor (auto-unblock removed)")
    parser.add_argument("-i", "--iface", required=True, help="interface (e.g. ens33)")
    args = parser.parse_args()
    iface = args.iface

    logging.info(f"Starting IDRS on interface {iface}")
    logging.info(f"SYN_THRESHOLD={SYN_THRESHOLD}, SSH_THRESHOLD={SSH_THRESHOLD}")

    try:
        sniff(iface=iface, prn=handle_packet, store=False)
    except OSError as e:
        logging.error(f"[!] Sniff error on iface {iface}: {e}")
        print(f"Available interfaces: {get_if_list()}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting IDRS...")
        sys.exit(0)

if __name__ == "__main__":
    main()
