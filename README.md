# 🕸 HoneytrapX — Wireless Honeypot Attack Analysis System

> A real-time network honeypot that mimics vulnerable services to capture, analyze, and visualize attacker behavior — with auto-generated defense strategies.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-Dashboard-green?style=flat-square&logo=flask)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📌 Overview

**HoneytrapX** is a wireless honeypot system developed as part of a Mobile Security course project. It simulates vulnerable network services (SSH, FTP, Telnet, HTTP, MySQL) to lure and capture attacker behavior. All captured data is logged, analyzed, and displayed on a live web dashboard with real-time defense strategy generation.

### What it does:
- **Mimics** real vulnerable services with convincing fake banners and responses
- **Captures** every connection attempt — IP, port, payload, timestamp, geolocation
- **Analyzes** attack patterns — port scans, brute force, credential stuffing
- **Visualizes** everything on a live auto-refreshing web dashboard
- **Generates** defense strategies specific to each attacker IP and attack type

---

## ✨ Features

| Feature                     | Description                                                                                           |
|-----------------------------|-------------------------------------------------------------------------------------------------------|
| 🎯 Multi-port Honeypot      | Listens on SSH (22), FTP (21), Telnet (23), HTTP (80), MySQL (3306)                                   |
| 🐚 Interactive Fake Shell   | Attacker gets a real-looking Linux shell (ls, pwd, echo, cat, touch, rm, mkdir, ps, env)              |
| 🌐 HTTP Fake Login Page     | Port 80 serves a fake Admin portal — captures submitted credentials                                   |
| 📡 Real-time Dashboard      | Live attack feed, charts, threat level meter — auto-updates every 10s                                 |
| 🌍 Geolocation Tracking     |     Identifies attacker country and city via IP lookup                                                |
| 🛡 Dynamic Defense Engine   |   Generates specific countermeasures per attacker IP based on what they actually did                   |
| 📊 Attack Analytics         |         Pie charts, bar charts, attack timeline — regenerated automatically                           |
| 💾 Dual Logging             |             Logs to both CSV and JSON for easy analysis                                               |
| ⚡ SocketIO Live Stream     |     Dashboard receives attack events instantly via WebSocket                                          |

---

## 🏗 Structure

```
HoneyTrapX
    ├── honeypot.py        ← Core listener (captures attacks)
    ├── analyzer.py        ← Analyzes attack patterns
    ├── app.py             ← Flask web dashboard
    ├── test_fake_shell.py ← Attack log Generator
    ├── requirements.txt
    ├── templates/
    │   └── index.html     ← Beautiful dashboard UI
    ├── logs/
    │     └── attacks.csv    ← Auto-created
    └── reports/           ← Charts saved here
```

---

## 🔌 Ports & Services Monitored

| Port | Service | Attack Type Detected | Fake Response |
|------|---------|---------------------|---------------|
| 22 | SSH | Brute Force / Scan | OpenSSH banner + fake shell |
| 21 | FTP | FTP Probe | ProFTPD banner + file listing |
| 23 | Telnet | Exploit Attempt | Cisco Router login prompt |
| 80 | HTTP | Web Scan / Probe | Fake Admin login HTML page |
| 3306 | MySQL | Database Attack | MySQL handshake bytes |

---

## ⚙ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/PavanKumarCCB-001/HoneyTrapX.git
cd HoneytrapX
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Execution Flow

### i. Run the Listener (keep Running)
```bash
python honeypot.py
```

### ii. Run the Dashboard (Keep Running)
```bash
python app.py
```

### iii. Generate Attack Log (New Terminal)
```bash
python test_fake_shell.py
```

### iv. For Showing Charts
```bash
python analyzer.py
```

> Open browser → `http://127.0.0.1:5000` or `http://<your-ip>:5000` for network access

---

## 🧪 Testing Each Service

| Service | How to Test |
|---|---|
| SSH / Telnet Shell | `python test_fake_shell.py 22` — login: `admin` / `admin` |
| FTP | `ftp 127.0.0.1` — then `ls`, `get <file>`, `bye` |
| HTTP | Open browser → `http://127.0.0.1:80` |
| MySQL | Any MySQL client — logs the handshake automatically |

### Fake Shell Commands Available
```
ls, pwd, whoami, id, uname, echo, cat, touch, rm, mkdir, ps, env, history, clear, exit
```

---

## 📊 Dashboard

The web dashboard at `http://127.0.0.1:5000` shows:

- **Live attack counter** — total attacks, unique IPs, last 24h activity
- **Threat level meter** — LOW / MEDIUM / HIGH based on attack volume
- **Live attack log** — real-time feed of every connection with payload
- **Attack type distribution** — pie chart of attack categories
- **Top attacker IPs** — bar chart ranked by hit count
- **Service hit count** — which ports are being targeted most
- **Attack timeline** — hourly attack frequency graph
- **Dynamic defense strategies** — per attacker IP, based on what they actually did

---

## 🛡 Defense Strategy Engine

HoneytrapX doesn't just log attacks — it tells you exactly what to do about them.

| Attack Detected | Auto-Generated Strategy |
|---|---|
| Port Scan (3+ ports) | Block IP on firewall, enable IDS, close unused ports |
| SSH Brute Force | Disable password auth, deploy fail2ban, use key pairs |
| FTP Probe | Disable FTP, switch to SFTP, restrict by IP whitelist |
| Telnet Exploit | Disable Telnet immediately, replace with SSH |
| HTTP Probe | Deploy WAF, hide server banners, enable rate limiting |
| Database Attack | Never expose DB ports, bind to localhost only |

---

## 🔒 Ethical & Legal Notice

> This tool is built **strictly for educational purposes** as part of a university Mobile Security assignment.
> Run it **only on networks you own or have explicit written permission to monitor.**
> Unauthorized use of honeypots on public or shared networks may violate local laws.

---

## 🛠 Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Web Framework | Flask + Flask-SocketIO |
| Data Analysis | Pandas |
| Visualization | Matplotlib |
| Real-time | WebSocket (SocketIO) |
| Logging | CSV + JSON |
| Geolocation | ip-api.com |

---

*HoneytrapX — Catch them before they catch you.* 🕸
