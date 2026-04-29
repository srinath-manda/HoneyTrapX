import socket
import threading
import csv
import os
import time
from datetime import datetime

LOG_FILE = "logs/attacks.csv"

# Fake service banners to lure attackers
BANNERS = {
    21:  b"220 FTP server ready (vsftpd 2.0.1)\r\n",
    22:  b"SSH-2.0-OpenSSH_4.3\r\n",
    23:  b"\r\nWelcome to Cisco Router\r\nlogin: ",
    80:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.3\r\nContent-Length: 0\r\n\r\n",
    3306:b"5.0.51a-community\r\n",
    8080:b"HTTP/1.1 200 OK\r\nServer: Tomcat/4.1\r\n\r\n",
}

PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    3306: "MySQL",
    8080: "HTTP-ALT",
}

ATTACK_TYPES = {
    21:  "FTP Probe",
    22:  "SSH Brute Force / Scan",
    23:  "Telnet Exploit Attempt",
    80:  "Web Scan / HTTP Probe",
    3306:"Database Attack",
    8080:"Web App Attack",
}

os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

# Initialize CSV with headers if not exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "attacker_ip", "attacker_port", "target_port",
                         "service", "attack_type", "payload", "duration_ms"])

log_lock = threading.Lock()

def log_attack(ip, attacker_port, target_port, payload, duration_ms):
    service = PORT_NAMES.get(target_port, "Unknown")
    attack_type = ATTACK_TYPES.get(target_port, "Generic Probe")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_payload = payload.replace("\n", " ").replace("\r", " ")[:100]
    with log_lock:
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, ip, attacker_port, target_port,
                             service, attack_type, clean_payload, round(duration_ms, 2)])
    print(f"[{timestamp}] ATTACK → IP: {ip}:{attacker_port} | Port: {target_port} ({service}) | Type: {attack_type}")

def handle_connection(conn, addr, port):
    start = time.time()
    attacker_ip, attacker_port = addr
    try:
        banner = BANNERS.get(port, b"Connected.\r\n")
        conn.sendall(banner)
        conn.settimeout(3)
        try:
            data = conn.recv(1024)
            payload = data.decode("utf-8", errors="replace") if data else ""
        except:
            payload = ""
    except Exception as e:
        payload = f"[Error: {e}]"
    finally:
        duration_ms = (time.time() - start) * 1000
        log_attack(attacker_ip, attacker_port, port, payload, duration_ms)
        try:
            conn.close()
        except:
            pass

def start_listener(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        print(f"[+] Honeypot listening on port {port} ({PORT_NAMES.get(port, 'Unknown')})")
        while True:
            try:
                conn, addr = server.accept()
                t = threading.Thread(target=handle_connection, args=(conn, addr, port), daemon=True)
                t.start()
            except Exception as e:
                print(f"[!] Error on port {port}: {e}")
    except OSError as e:
        print(f"[!] Could not bind port {port}: {e} — skipping")

def start_honeypot():
    print("=" * 55)
    print("   WIRELESS HONEYPOT — ATTACK CAPTURE ENGINE")
    print("=" * 55)
    print(f"   Logging to: {LOG_FILE}")
    print("=" * 55)
    threads = []
    for port in BANNERS.keys():
        t = threading.Thread(target=start_listener, args=(port,), daemon=True)
        t.start()
        threads.append(t)
    print("\n[*] All honeypot listeners active. Waiting for connections...\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped by user.")

if __name__ == "__main__":
    start_honeypot()