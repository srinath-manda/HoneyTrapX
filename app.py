from flask import Flask, render_template, jsonify, send_from_directory
from analyzer import load_data, get_stats, generate_charts
import os, json

app = Flask(__name__, static_folder=".")

@app.route('/reports/<path:filename>')
def reports(filename):
    return send_from_directory('reports', filename)

def add_demo_data():
    """Add demo attack data so dashboard looks great on first run."""
    import csv, random
    from datetime import datetime, timedelta
    log_file = "logs/attacks.csv"
    if os.path.exists(log_file):
        with open(log_file) as f:
            lines = f.readlines()
        if len(lines) > 1:
            return  # Already has real data

    sample_ips = [
        "192.168.1.105", "10.0.0.47", "172.16.0.22", "192.168.0.89",
        "10.10.5.33", "192.168.2.14", "172.20.1.9", "10.0.1.200",
    ]
    services = [
        (22, "SSH", "SSH Brute Force / Scan"),
        (21, "FTP", "FTP Probe"),
        (23, "Telnet", "Telnet Exploit Attempt"),
        (80, "HTTP", "Web Scan / HTTP Probe"),
        (3306, "MySQL", "Database Attack"),
        (8080, "HTTP-ALT", "Web App Attack"),
    ]
    payloads = [
        "USER admin", "PASS 123456", "GET / HTTP/1.1", "root login attempt",
        "nmap scan detected", "SELECT * FROM users", "", "admin admin",
    ]
    with open(log_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","attacker_ip","attacker_port","target_port",
                         "service","attack_type","payload","duration_ms"])
        base = datetime.now()
        for i in range(60):
            ts = base - timedelta(minutes=random.randint(0, 1440))
            ip = random.choice(sample_ips)
            port, svc, atype = random.choice(services)
            writer.writerow([
                ts.strftime("%Y-%m-%d %H:%M:%S"),
                ip, random.randint(40000, 65000), port,
                svc, atype, random.choice(payloads),
                round(random.uniform(10, 500), 2)
            ])
    print("[*] Demo data loaded. Replace with real attacks from honeypot.py")

@app.route("/")
def index():
    add_demo_data()
    df = load_data()
    generate_charts(df)
    stats = get_stats(df)
    return render_template("index.html", stats=stats)

@app.route("/api/stats")
def api_stats():
    df = load_data()
    stats = get_stats(df)
    # Convert to JSON-safe format
    stats["attack_type_counts"] = dict(stats["attack_type_counts"])
    stats["service_counts"] = dict(stats["service_counts"])
    return jsonify(stats)

@app.route("/api/refresh")
def api_refresh():
    df = load_data()
    generate_charts(df)
    stats = get_stats(df)
    return jsonify({
        "total_attacks": stats["total_attacks"],
        "unique_ips": stats["unique_ips"],
        "last_24h": stats["last_24h"],
        "recent_attacks": stats["recent_attacks"][:5],
    })

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    print("=" * 50)
    print("  HONEYPOT DASHBOARD → http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)