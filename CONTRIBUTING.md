# 🤝 Contributing to Mini Intrusion Detection & Response System (IDRS)

Thank you for considering contributing to **Mini IDRS**!  
This project is a student-led cybersecurity lab simulation demonstrating real-time Intrusion Detection & Response using Python, Scapy, and Cisco IOS automation.

---

## 🧭 How to Contribute

### 1️⃣ Fork the repository
Click the **Fork** button (top-right on GitHub) to create your copy of the project.

### 2️⃣ Clone your fork
```bash
git clone https://github.com/VishvaNarkar/Mini-IDRS.git
cd Mini-IDRS
```

### 3️⃣ Create a feature branch
```bash
git checkout -b feature/<feature-name>
```

### 4️⃣ Make your changes

You can:

- Add or enhance detection logic in idrs_monitor.py

- Improve the Streamlit dashboard (idrs_dashboard.py)

- Update documentation or add test cases

### 5️⃣ Commit and push your changes
```bash
git add .
git commit -m "Add <feature-name>: brief description"
git push origin feature/<feature-name>
```

### 6️⃣ Create a Pull Request

Go to your fork on GitHub and click `“New Pull Request”`.
Explain your changes clearly — include screenshots if applicable.

---

## 🧰 Development Setup

Requirements:

- Python 3.13

- VMware / GNS3 for network emulation (optional)

- Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

- Required packages:

```bash
pip3 install -r requirements.txt
```

Run the IDS:
```bash
sudo python3 idrs_monitor.py -i ens33
```

Launch the dashboard:
```bash
streamlit run idrs_dashboard.py
```

---

## 🧱 Code Style & Guidelines

To keep the codebase clean and readable:

- Follow **PEP 8** for Python style.

- Use descriptive variable names.

- Comment your detection logic clearly.

- Log events consistently (`/var/log/ids.log`).

- Keep credentials out of commits — use environment variables or `.env` files.

---

## 🧪 Testing Guidelines

To test new detection logic:

1. Use the Kali attacker VM to run simulated attacks:  

   - `nmap -sX` for XMAS scan

   - `hping3 -S` for SYN flood

   - `hydra` for SSH brute-force

2. Observe `/var/log/ids.log` for new detection entries.

3. Verify router ACL and iptables changes.

---

## 🧠 Contribution Ideas

- Add new detection types (UDP flood, ICMP flood, ARP spoof)

- Implement alerting (email/Slack/Telegram)

- Integrate with a central logging system (ELK stack)

- Add visualization improvements in the dashboard

- Implement persistent database logging (SQLite / MongoDB)

- Develop a CLI tool for managing whitelist/blocks

---

## ⚙️ Reporting Issues

If you find a bug or false positive:

1. Check if it’s reproducible.

2. Open an **issue** on GitHub.

3. Include:
   - Steps to reproduce
   - Log excerpt
   - Expected vs actual behavior
   - Screenshot if helpful

---

## 💬 Code of Conduct

We’re a respectful learning community.

  - Be kind, patient, and professional.
  
  - Avoid sharing sensitive data or real credentials.

  - Focus on constructive feedback.

---

## 🧩 Acknowledgements

This project was developed as part of the **iM.Sc. IT Architecture & Network Security** program at **Gujarat University**.
We welcome educational collaborations, improvements, and feedback!