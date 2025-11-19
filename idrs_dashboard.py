import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import streamlit as st
import pandas as pd
import time
st_autorefresh = st.empty()
import os
import re
import plotly.express as px
from netmiko import ConnectHandler
import paramiko

# ------------------ Configuration ------------------
LOG_FILE = "/var/log/ids.log"
WHITELIST_FILE = "/home/monitor/Mini-IDRS/whitelist.txt"

ROUTER_IP = "192.168.10.1"
ROUTER_USER = "admin"
ROUTER_PASS = "admin"
VICTIM_IP = "192.168.10.14"
VICTIM_USER = "victim"
VICTIM_PASS = "victim"
ACL_NAME = "IDS_BLOCK_LIST"

# ------------------ Streamlit Layout ------------------
st.set_page_config(
    page_title="Mini IDRS Dashboard",
    page_icon="🧠"
)

st.title("🧠 Mini Intrusion Detection & Response System (IDRS)")
st.caption("Real-time attack monitoring • Automated blocking • Network defense visualization")

# ------------------ Helper Functions ------------------
def tail_log(file_path, n=200):
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", errors="ignore") as f:
        return f.readlines()[-n:]

def parse_log(lines):
    # More robust parsing: detect known attack keywords, extract timestamp and IPs.
    data = []
    type_pattern = re.compile(r"\b(XMAS_SCAN|SYN_FLOOD|SSH_BRUTE_FORCE)\b")
    ts_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d+)")
    ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

    for line in lines:
        # skip lines that don't mention a known attack type
        tmatch = type_pattern.search(line)
        if not tmatch:
            continue

        atk_type = tmatch.group(1)

        # timestamp (if present)
        ts = ""
        tsm = ts_pattern.search(line)
        if tsm:
            ts = tsm.group(1)

        # find IPs: attacker is usually the first IP, victim the second
        ips = ip_pattern.findall(line)
        attacker = ips[0] if len(ips) >= 1 else "N/A"
        victim = ips[1] if len(ips) >= 2 else "N/A"

        severity = "HIGH" if atk_type in ["SYN_FLOOD", "SSH_BRUTE_FORCE"] else "MEDIUM"

        data.append({
            "Time": ts,
            "Type": atk_type,
            "Attacker": attacker,
            "Victim": victim,
            "Severity": severity,
        })

    df = pd.DataFrame(data)
    if not df.empty:
        df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
        df = df.sort_values("Time", ascending=False)
    return df

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return []
    with open(WHITELIST_FILE) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def save_whitelist(ips):
    with open(WHITELIST_FILE, "w") as f:
        for ip in sorted(set(ips)):
            f.write(ip + "\n")

# ------------------ SSH Helpers ------------------
def ssh_run_cmd(host, username, password, cmd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()
        client.close()
        return out, err
    except Exception as e:
        return "", str(e)

def router_block(ip):
    device = {
        "device_type": "cisco_ios",
        "host": ROUTER_IP,
        "username": ROUTER_USER,
        "password": ROUTER_PASS,
    }
    try:
        with ConnectHandler(**device) as conn:
            cmds = [
                f"ip access-list extended {ACL_NAME}",
                f"deny ip host {ip} any",
                "exit"
            ]
            conn.send_config_set(cmds)
        return True, "Router block successful"
    except Exception as e:
        return False, str(e)

def router_unblock(ip):
    device = {
        "device_type": "cisco_ios",
        "host": ROUTER_IP,
        "username": ROUTER_USER,
        "password": ROUTER_PASS,
    }
    try:
        with ConnectHandler(**device) as conn:
            out = conn.send_command(f"show ip access-lists {ACL_NAME}")
            cmds = []
            for line in out.splitlines():
                if ip in line and "deny ip host" in line:
                    if line.strip()[0].isdigit():
                        line = " ".join(line.split()[1:])
                    cmds.append("no " + line.strip())
            if cmds:
                conn.send_config_set([f"ip access-list extended {ACL_NAME}"] + cmds + ["exit"])
        return True, "Router unblock successful"
    except Exception as e:
        return False, str(e)

def victim_block(ip):
    cmd = f"sudo iptables -I INPUT -s {ip} -j DROP"
    out, err = ssh_run_cmd(VICTIM_IP, VICTIM_USER, VICTIM_PASS, cmd)
    if err:
        return False, err
    return True, "Victim blocked via iptables"

def victim_unblock(ip):
    cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
    out, err = ssh_run_cmd(VICTIM_IP, VICTIM_USER, VICTIM_PASS, cmd)
    if err:
        return False, err
    return True, "Victim unblocked via iptables"

# ------------------ Sidebar ------------------
st.sidebar.header("⚙️ Control Panel")

with st.sidebar.expander("Whitelist Management", expanded=True):
    wl = load_whitelist()
    st.write("Current Whitelisted IPs:")
    if wl:
        for ip in wl.copy():
            c1, c2 = st.columns([3, 1])
            c1.markdown(f"<span style='color:green'>{ip}</span>", unsafe_allow_html=True)
            # create a removal button per IP with a stable unique key
            if c2.button("Remove", key=f"remove_{ip.replace('.', '_')}"):
                wl.remove(ip)
                save_whitelist(wl)
                st.success(f"Removed {ip} from whitelist")
                time.sleep(1)
                st.rerun()
    else:
        st.info("No whitelisted IPs yet.")

    new_ip = st.text_input("Add IP to Whitelist:")
    if st.button("➕ Add"):
        if new_ip:
            if new_ip in wl:
                st.warning(f"{new_ip} is already whitelisted")
            else:
                wl.append(new_ip)
                save_whitelist(wl)
                st.success(f"Added {new_ip}")
                time.sleep(1)
                st.rerun()
        else:
            st.warning("Enter a valid IP to add")

    if st.button("🗑️ Clear Whitelist"):
        save_whitelist([])
        st.warning("Whitelist cleared")
        time.sleep(1)
        st.rerun()

refresh_rate = st.sidebar.slider("Refresh every (seconds):", 3, 20, 3)
st.sidebar.caption("⏳ Auto-refresh enabled")

# ------------------ Attack Logs ------------------
st.subheader("📡 Real-Time Attack Log")

log_placeholder = st.empty()
chart_placeholder = st.empty()

def render_dashboard():
    lines = tail_log(LOG_FILE, 300)
    df = parse_log(lines)

    if df.empty:
        st.info("No recent detections.")
        return

    # Color severity
    def highlight_row(row):
        color = "background-color: #ff4d4d" if row["Severity"] == "HIGH" else \
                "background-color: #ffeb99" if row["Severity"] == "MEDIUM" else \
                "background-color: #d4ed91"
        return [color] * len(row)

    st.dataframe(
        df.style.apply(highlight_row, axis=1),
        use_container_width=True,
        hide_index=True
    )

    # ------------------ Attack Chart ------------------
    chart_df = df.groupby("Type").size().reset_index(name="Count")
    fig = px.bar(
        chart_df,
        x="Type",
        y="Count",
        color="Type",
        title="📈 Attack Type Frequency (Live)",
        color_discrete_sequence=["#ff4d4d", "#ffaa00", "#3399ff"]
    )
    fig.update_layout(height=350, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

# ------------------ Manual Block/Unblock ------------------
st.subheader("🧱 Manual IP Control")

col1, col2 = st.columns(2)
with col1:
    ip_block = st.text_input("Enter IP to BLOCK:")
    if st.button("🚫 Block"):
        if ip_block:
            r_ok, r_msg = router_block(ip_block)
            v_ok, v_msg = victim_block(ip_block)
            st.success(f"Router: {r_msg} | Victim: {v_msg}")
        else:
            st.warning("Enter a valid IP")

with col2:
    ip_unblock = st.text_input("Enter IP to UNBLOCK:")
    if st.button("✅ Unblock"):
        if ip_unblock:
            r_ok, r_msg = router_unblock(ip_unblock)
            v_ok, v_msg = victim_unblock(ip_unblock)
            st.success(f"Router: {r_msg} | Victim: {v_msg}")
        else:
            st.warning("Enter a valid IP")

# ------------------ Live Loop ------------------
while True:
    with log_placeholder.container():
        render_dashboard()
    time.sleep(refresh_rate)
    st.rerun()