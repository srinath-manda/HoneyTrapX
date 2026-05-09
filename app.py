import threading
from flask import Flask, render_template, jsonify, send_from_directory, request
from flask_socketio import SocketIO, emit
from analyzer import load_data, get_stats, generate_charts
import os
import json
import random
import csv
from datetime import datetime, timedelta

app = Flask(__name__, static_folder=".")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'honeypot-default-secret-change-me')
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "logs/attacks.csv"


@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/x-icon')

@app.route('/reports/<path:filename>')
def reports(filename):
    return send_from_directory('reports', filename)

def add_demo_data():
    """Add demo attack data so dashboard looks great on first run."""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                lines = f.readlines()
            if len(lines) > 1:
                return  # Already has real data
        except:
            pass

    sample_ips = [
        ("185.156.74.65", "Russia", "Moscow"),
        ("45.33.22.11", "United States", "Dallas"),
        ("103.21.244.5", "China", "Beijing"),
        ("92.242.140.21", "United Kingdom", "London"),
        ("210.10.5.33", "Japan", "Tokyo"),
    ]
    services = [
        (2222, "SSH", "SSH Brute Force / Scan"),
        (2121, "FTP", "FTP Probe"),
        (2323, "Telnet", "Telnet Exploit Attempt"),
        (8080, "HTTP", "Web Scan / HTTP Probe"),
        (33060, "MySQL", "Database Attack"),
        (8081, "HTTP-ALT", "Web App Attack"),
    ]
    payloads = [
        "USER admin | PASS 123456", "GET /admin HTTP/1.1", "nmap scan detected",
        "SELECT * FROM users", "root login attempt", "admin | admin",
    ]

    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","attacker_ip","attacker_port","target_port",
                         "service","attack_type","payload","duration_ms","country","city"])
        base = datetime.now()
        for i in range(40):
            ts = base - timedelta(minutes=random.randint(0, 1440))
            ip, country, city = random.choice(sample_ips)
            port, svc, atype = random.choice(services)
            writer.writerow([
                ts.strftime("%Y-%m-%d %H:%M:%S"),
                ip, random.randint(40000, 65000), port,
                svc, atype, random.choice(payloads),
                round(random.uniform(10, 500), 2),
                country, city
            ])
    print("[*] Demo data loaded for new schema.")

@app.route("/")
def index():
    add_demo_data()
    df    = load_data()
    stats = get_stats(df)
    # Charts generated in background — don't block page load
    threading.Thread(target=generate_charts, args=(df,), daemon=True).start()
    return render_template("index.html", stats=stats)

@app.route("/api/report_attack", methods=["POST"])
def report_attack():
    attack_data = request.json
    # Broadcast to all connected web clients
    socketio.emit('new_attack', attack_data)

    # Trigger chart regeneration periodically or every N attacks
    # For now, just return success
    return jsonify({"status": "received"}), 200

@app.route("/api/stats")
def api_stats():
    df = load_data()
    stats = get_stats(df)
    return jsonify(stats)

@app.route("/api/refresh_charts")
def api_refresh_charts():
    df = load_data()
    generate_charts(df)
    return jsonify({"status": "charts_updated"})

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    print("=" * 50)
    print("  REAL-TIME HONEYPOT DASHBOARD → http://127.0.0.1:5000")
    print("=" * 50)
    socketio.run(app, debug=True, port=5000, host="0.0.0.0")