import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os
from datetime import datetime, timedelta
from collections import Counter

LOG_FILE = "logs/attacks.csv"
REPORTS_DIR = "reports"

os.makedirs(REPORTS_DIR, exist_ok=True)

DEFENSE_MAP = {
    "SSH Brute Force / Scan": [
        "Disable password auth — use SSH key pairs only",
        "Deploy fail2ban to auto-ban repeated attempts",
        "Move SSH to a non-standard port (e.g., 2222)",
        "Enable MFA (multi-factor authentication)",
    ],
    "FTP Probe": [
        "Disable FTP — use SFTP or SCP instead",
        "Restrict FTP access by IP whitelist",
        "Use TLS encryption for file transfers",
    ],
    "Telnet Exploit Attempt": [
        "Disable Telnet immediately — it sends data in plaintext",
        "Replace with SSH for all remote access",
        "Block port 23 on your firewall",
    ],
    "Web Scan / HTTP Probe": [
        "Deploy a Web Application Firewall (WAF)",
        "Use rate limiting on your web server",
        "Keep web server software updated",
        "Hide server version banners",
    ],
    "Database Attack": [
        "Never expose MySQL/database ports to the internet",
        "Use strong, unique database passwords",
        "Restrict DB access to localhost or internal IPs only",
        "Enable database audit logging",
    ],
    "Web App Attack": [
        "Update Tomcat/app server to latest version",
        "Implement input validation and sanitization",
        "Use a reverse proxy (Nginx) in front of app servers",
    ],
    "Generic Probe": [
        "Enable a host-based firewall (Windows Defender Firewall)",
        "Close all unused ports",
        "Monitor network traffic with IDS/IPS",
    ],
}

def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=["timestamp","attacker_ip","attacker_port",
                                      "target_port","service","attack_type","payload","duration_ms"])
    df = pd.read_csv(LOG_FILE)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def get_stats(df):
    if df.empty:
        return {
            "total_attacks": 0, "unique_ips": 0, "top_attacked_port": "N/A",
            "top_attack_type": "N/A", "attack_type_counts": {},
            "top_ips": [], "service_counts": {}, "recent_attacks": [],
            "last_24h": 0, "defense_strategies": [], "port_scan_ips": [],
            "brute_force_ips": [],
        }

    attack_type_counts = df["attack_type"].value_counts().to_dict()
    service_counts = df["service"].value_counts().to_dict()
    top_ips = df["attacker_ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["ip", "count"]

    # Detect port scanners (1 IP hitting 3+ different ports)
    ip_ports = df.groupby("attacker_ip")["target_port"].nunique()
    port_scan_ips = ip_ports[ip_ports >= 3].index.tolist()

    # Detect brute force (1 IP hitting SSH 5+ times)
    ssh_hits = df[df["target_port"] == 22].groupby("attacker_ip").size()
    brute_force_ips = ssh_hits[ssh_hits >= 5].index.tolist()

    # Recent attacks (last 20)
    recent = df.sort_values("timestamp", ascending=False).head(20)
    recent_attacks = recent[["timestamp","attacker_ip","service","attack_type"]].to_dict("records")
    for r in recent_attacks:
        r["timestamp"] = str(r["timestamp"])

    # Defense strategies based on detected attack types
    seen_types = df["attack_type"].unique().tolist()
    strategies = {}
    for t in seen_types:
        if t in DEFENSE_MAP:
            strategies[t] = DEFENSE_MAP[t]
    if not strategies:
        strategies["Generic Probe"] = DEFENSE_MAP["Generic Probe"]

    last_24h = df[df["timestamp"] >= datetime.now() - timedelta(hours=24)].shape[0]

    return {
        "total_attacks": len(df),
        "unique_ips": df["attacker_ip"].nunique(),
        "top_attacked_port": str(df["target_port"].mode()[0]) if not df.empty else "N/A",
        "top_attack_type": df["attack_type"].mode()[0] if not df.empty else "N/A",
        "attack_type_counts": attack_type_counts,
        "service_counts": service_counts,
        "top_ips": top_ips.to_dict("records"),
        "recent_attacks": recent_attacks,
        "last_24h": last_24h,
        "defense_strategies": strategies,
        "port_scan_ips": port_scan_ips,
        "brute_force_ips": brute_force_ips,
    }

def generate_charts(df):
    if df.empty:
        return
    plt.style.use("dark_background")

    # Chart 1: Attack Types Pie
    fig, ax = plt.subplots(figsize=(6, 5), facecolor="#0d1117")
    counts = df["attack_type"].value_counts()
    colors = ["#00ff88", "#ff4444", "#ffaa00", "#00aaff", "#cc44ff", "#ff6600"]
    wedges, texts, autotexts = ax.pie(
        counts.values, labels=counts.index, autopct="%1.1f%%",
        colors=colors[:len(counts)], startangle=140,
        textprops={"color": "white", "fontsize": 9},
    )
    for at in autotexts:
        at.set_color("white")
        at.set_fontsize(8)
    ax.set_title("Attack Type Distribution", color="#00ff88", fontsize=13, pad=15)
    fig.tight_layout()
    fig.savefig(f"{REPORTS_DIR}/attack_types.png", dpi=100, bbox_inches="tight", facecolor="#0d1117")
    plt.close()

    # Chart 2: Top IPs Bar
    fig, ax = plt.subplots(figsize=(7, 4), facecolor="#0d1117")
    ax.set_facecolor("#161b22")
    top = df["attacker_ip"].value_counts().head(8)
    bars = ax.barh(top.index[::-1], top.values[::-1], color="#00ff88", height=0.6)
    for bar, val in zip(bars, top.values[::-1]):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                str(val), va="center", color="white", fontsize=9)
    ax.set_xlabel("Attack Count", color="#aaaaaa")
    ax.set_title("Top Attacker IPs", color="#00ff88", fontsize=13)
    ax.tick_params(colors="white")
    ax.spines[:].set_color("#333")
    fig.tight_layout()
    fig.savefig(f"{REPORTS_DIR}/top_ips.png", dpi=100, bbox_inches="tight", facecolor="#0d1117")
    plt.close()

    # Chart 3: Service Hits Bar
    fig, ax = plt.subplots(figsize=(7, 4), facecolor="#0d1117")
    ax.set_facecolor("#161b22")
    svc = df["service"].value_counts()
    ax.bar(svc.index, svc.values, color=["#ff4444","#ffaa00","#00aaff","#cc44ff","#00ff88","#ff6600"][:len(svc)])
    ax.set_ylabel("Hits", color="#aaaaaa")
    ax.set_title("Attacks per Service", color="#00ff88", fontsize=13)
    ax.tick_params(colors="white")
    ax.spines[:].set_color("#333")
    fig.tight_layout()
    fig.savefig(f"{REPORTS_DIR}/services.png", dpi=100, bbox_inches="tight", facecolor="#0d1117")
    plt.close()

if __name__ == "__main__":
    df = load_data()
    stats = get_stats(df)
    generate_charts(df)
    print(f"Total Attacks  : {stats['total_attacks']}")
    print(f"Unique IPs     : {stats['unique_ips']}")
    print(f"Top Attack Type: {stats['top_attack_type']}")
    print(f"Port Scanners  : {stats['port_scan_ips']}")
    print(f"Brute Force IPs: {stats['brute_force_ips']}")