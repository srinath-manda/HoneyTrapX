import socket
import threading
import csv
import json
import os
import time
import requests
from datetime import datetime

LOG_FILE_CSV  = "logs/attacks.csv"
LOG_FILE_JSON = "logs/attacks.json"
DASHBOARD_URL = "http://127.0.0.1:5000/api/report_attack"

PORT_NAMES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    3306: "MySQL",
}

ATTACK_TYPES = {
    21:   "FTP Probe",
    22:   "SSH Brute Force / Scan",
    23:   "Telnet Exploit Attempt",
    80:   "Web Scan / HTTP Probe",
    3306: "Database Attack",
}

BANNERS = {
    21:   b"220 ProFTPD 1.3.5 Server ready.\r\n",
    22:   b"SSH-2.0-OpenSSH_7.4\r\n",
    23:   b"\r\nCisco IOS Router v12.4\r\nUsername: ",
    80:   None,   # handled separately
    3306: b"\x4a\x00\x00\x00\x0a" b"5.7.33-MySQL\x00\x08\x00\x00\x00fakesalt\x00\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00fakesalt2\x00",
}

# ── Fake filesystem state (per-session, lives in memory) ─────────
BASE_FS = {
    "/root": ["bin", "etc", "home", "tmp", "var", "secret.txt"],
    "/root/tmp": [],
    "/root/etc": ["passwd", "shadow", "hosts"],
}

FILE_CONTENTS = {
    "secret.txt":      "API_KEY=sk-prod-abc123xyz\nDB_PASS=Sup3rS3cret!\n",
    "/etc/passwd":     "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/sh\n",
    "/etc/shadow":     "root:$6$fakehash:18000:0:99999:7:::\nadmin:$6$fakehash2:18000:0:99999:7:::\n",
    "/etc/hosts":      "127.0.0.1 localhost\n192.168.1.1 router\n10.0.0.1 gateway\n",
}

# ── HTTP fake page ───────────────────────────────────────────────
HTTP_LOGIN_PAGE = b"""\
HTTP/1.1 200 OK\r
Server: Apache/2.2.34 (Unix)\r
Content-Type: text/html\r
Connection: close\r
\r
<html><head><title>Network Admin Portal</title>
<style>body{background:#111;color:#0f0;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{border:1px solid #0f0;padding:40px;min-width:320px}h2{text-align:center;margin-bottom:24px}
input{background:#000;border:1px solid #0f0;color:#0f0;padding:8px;width:100%;margin-bottom:12px;box-sizing:border-box}
button{background:#0f0;color:#000;border:none;padding:10px;width:100%;cursor:pointer;font-weight:bold}
</style></head>
<body><div class="box"><h2>&#x1F512; Admin Login</h2>
<form method="post" action="/login">
Username: <input name="user" placeholder="admin"/><br/>
Password: <input type="password" name="pass" placeholder="password"/><br/>
<button type="submit">LOGIN</button>
</form></div></body></html>
"""

HTTP_401 = b"""\
HTTP/1.1 401 Unauthorized\r
Server: Apache/2.2.34\r
Content-Type: text/html\r
\r
<html><body><h1>401 Unauthorized</h1><p>Invalid credentials.</p></body></html>
"""

# ── Geo lookup with local-IP fast-path ──────────────────────────
geo_cache = {}
LOCAL_PREFIXES = ("127.", "192.168.", "10.", "172.16.", "172.17.",
                  "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                  "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                  "172.28.", "172.29.", "172.30.", "172.31.")

def get_geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if any(ip.startswith(p) for p in LOCAL_PREFIXES):
        return "Local Network", "Internal"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city",
                         timeout=2).json()
        if r.get("status") == "success":
            result = (r.get("country", "Unknown"), r.get("city", "Unknown"))
            geo_cache[ip] = result
            return result
    except Exception:
        pass
    geo_cache[ip] = ("Unknown", "Unknown")
    return "Unknown", "Unknown"

# ── Log init ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
if not os.path.exists(LOG_FILE_CSV):
    with open(LOG_FILE_CSV, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp","attacker_ip","attacker_port","target_port",
            "service","attack_type","payload","duration_ms","country","city"
        ])

log_lock = threading.Lock()

def notify_dashboard(data):
    try:
        requests.post(DASHBOARD_URL, json=data, timeout=1)
    except Exception:
        pass

def log_attack(ip, attacker_port, target_port, payload, duration_ms):
    country, city = get_geo(ip)
    row = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": ip,
        "attacker_port": attacker_port,
        "target_port": target_port,
        "service":     PORT_NAMES.get(target_port, "Unknown"),
        "attack_type": ATTACK_TYPES.get(target_port, "Generic Probe"),
        "payload":     str(payload).replace("\n"," ")[:200],
        "duration_ms": round(duration_ms, 2),
        "country":     country,
        "city":        city,
    }
    with log_lock:
        with open(LOG_FILE_CSV, "a", newline="") as f:
            csv.writer(f).writerow(list(row.values()))
        with open(LOG_FILE_JSON, "a") as f:
            f.write(json.dumps(row) + "\n")
    color = "\033[91m" if target_port == 22 else "\033[93m"
    print(f"{color}[{row['timestamp']}]\033[0m {row['service']} ← {ip} ({country}/{city}) | {str(payload)[:60]!r}")
    threading.Thread(target=notify_dashboard, args=(row,), daemon=True).start()

# ── Fake shell ──────────────────────────────────────────────────
def run_fake_shell(conn, payload_parts):
    """Interactive fake Linux shell. Supports ls, pwd, whoami, echo,
       touch, cat, rm, mkdir, uname, id, ps, env, history, clear, help."""

    # Per-session virtual filesystem (copy so each session is independent)
    session_fs    = {k: list(v) for k, v in BASE_FS.items()}
    session_files = dict(FILE_CONTENTS)  # filename → content
    cwd = "/root"

    def fs_list(path):
        return session_fs.get(path, [])

    def send(msg):
        conn.sendall(msg if isinstance(msg, bytes) else msg.encode())

    conn.sendall(b"\r\nWelcome to the restricted shell. Type 'help' for commands.\r\n$ ")

    while True:
        try:
            cmd_data = conn.recv(2048)
        except socket.timeout:
            break
        if not cmd_data:
            break

        cmd = cmd_data.decode(errors="ignore").strip()
        if not cmd:
            send(b"$ ")
            continue

        payload_parts.append(f"CMD:{cmd}")

        # ── parse ──
        parts = cmd.split(None, 2)
        base  = parts[0].lower()

        # exit / quit
        if base in ("exit", "quit", "logout"):
            send(b"logout\r\n")
            break

        # help
        elif base == "help":
            send("Available: ls, pwd, whoami, id, uname, echo, cat, touch, rm, mkdir, ps, env, history, clear, exit\r\n$ ")

        # clear
        elif base == "clear":
            send(b"\033[2J\033[H$ ")

        # pwd
        elif base == "pwd":
            send(f"{cwd}\r\n$ ")

        # whoami
        elif base == "whoami":
            send(b"root\r\n$ ")

        # id
        elif base == "id":
            send(b"uid=0(root) gid=0(root) groups=0(root)\r\n$ ")

        # uname
        elif base == "uname":
            send(b"Linux honeypot-server 4.19.0-6-amd64 #1 SMP x86_64 GNU/Linux\r\n$ ")

        # ls
        elif base == "ls":
            target = parts[1] if len(parts) > 1 else cwd
            if not target.startswith("/"):
                target = cwd + "/" + target
            items = fs_list(target)
            if items:
                send("  ".join(items) + "\r\n$ ")
            else:
                send(f"ls: cannot access '{target}': No such file or directory\r\n$ ")

        # echo
        elif base == "echo":
            text = cmd[5:].strip()   # everything after 'echo '
            # handle echo "text" > file
            if ">" in text:
                left, right = text.split(">", 1)
                content = left.strip().strip('"').strip("'")
                fname   = right.strip()
                session_files[fname] = content + "\n"
                # add to current dir listing
                dirname = cwd
                if fname not in session_fs.get(dirname, []):
                    session_fs.setdefault(dirname, []).append(fname)
                send(f"[wrote {len(content)} bytes to {fname}]\r\n$ ")
            else:
                out = text.strip('"').strip("'")
                send(f"{out}\r\n$ ")

        # touch
        elif base == "touch":
            if len(parts) < 2:
                send(b"touch: missing file operand\r\n$ ")
            else:
                fname = parts[1]
                if fname not in session_files:
                    session_files[fname] = ""
                dirname = cwd
                if fname not in session_fs.get(dirname, []):
                    session_fs.setdefault(dirname, []).append(fname)
                send(f"touched: {fname}\r\n$ ")

        # cat
        elif base == "cat":
            if len(parts) < 2:
                send(b"cat: missing operand\r\n$ ")
            else:
                fname = parts[1]
                # try bare name first, then full path
                content = session_files.get(fname) or session_files.get(cwd+"/"+fname)
                if content is not None:
                    send(content + "\r\n$ ")
                else:
                    send(f"cat: {fname}: No such file or directory\r\n$ ")

        # rm
        elif base == "rm":
            if len(parts) < 2:
                send(b"rm: missing operand\r\n$ ")
            else:
                fname = parts[1]
                removed = False
                if fname in session_files:
                    del session_files[fname]
                    removed = True
                for path in session_fs:
                    if fname in session_fs[path]:
                        session_fs[path].remove(fname)
                        removed = True
                if removed:
                    send(f"removed '{fname}'\r\n$ ")
                else:
                    send(f"rm: cannot remove '{fname}': No such file or directory\r\n$ ")

        # mkdir
        elif base == "mkdir":
            if len(parts) < 2:
                send(b"mkdir: missing operand\r\n$ ")
            else:
                dname = parts[1]
                full  = cwd + "/" + dname
                session_fs[full] = []
                session_fs.setdefault(cwd, []).append(dname)
                send(f"mkdir: created directory '{dname}'\r\n$ ")

        # ps
        elif base == "ps":
            send(b"  PID TTY          TIME CMD\r\n"
                 b"    1 ?        00:00:01 systemd\r\n"
                 b"  312 ?        00:00:00 sshd\r\n"
                 b"  891 pts/0    00:00:00 bash\r\n"
                 b"  892 pts/0    00:00:00 ps\r\n$ ")

        # env
        elif base == "env":
            send(b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\r\n"
                 b"HOME=/root\r\nUSER=root\r\nSHELL=/bin/bash\r\n"
                 b"DB_HOST=localhost\r\nDB_PASS=Sup3rS3cret!\r\n$ ")

        # history
        elif base == "history":
            hist = "\r\n".join(
                f"  {i+1}  {c.replace('CMD:','')}"
                for i, c in enumerate(payload_parts)
            )
            send(hist + "\r\n$ ")

        # unknown
        else:
            send(f"bash: {cmd}: command not found\r\n$ ")

# ── Port 80 handler ─────────────────────────────────────────────
def handle_http(conn, payload_parts):
    conn.settimeout(5)
    try:
        data = conn.recv(4096).decode(errors="ignore")
        if not data:
            return
        lines = data.split("\r\n")
        method_line = lines[0] if lines else ""
        payload_parts.append(method_line[:100])

        # Check if POST (login attempt)
        if "POST" in method_line and "login" in data.lower():
            body = data.split("\r\n\r\n", 1)[-1]
            payload_parts.append(f"CREDS:{body[:80]}")
            conn.sendall(HTTP_401)
        else:
            conn.sendall(HTTP_LOGIN_PAGE)
    except socket.timeout:
        pass

# ── FTP handler ─────────────────────────────────────────────────
def handle_ftp(conn, payload_parts):
    conn.settimeout(8)
    conn.sendall(b"220 ProFTPD 1.3.5 Server ready.\r\n")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            cmd = data.decode(errors="ignore").strip()
            if not cmd:
                continue
            payload_parts.append(cmd[:60])
            cl = cmd.upper()
            if cl.startswith("USER"):
                conn.sendall(b"331 Password required.\r\n")
            elif cl.startswith("PASS"):
                conn.sendall(b"230 Login successful.\r\n")
            elif cl.startswith("LIST") or cl.startswith("NLST"):
                conn.sendall(
                    b"150 Opening ASCII mode data connection.\r\n"
                    b"-rw-r--r-- 1 root root  1024 Jan 01 config.bak\r\n"
                    b"-rw-r--r-- 1 root root  2048 Jan 01 passwords.txt\r\n"
                    b"-rw-r--r-- 1 root root   512 Jan 01 .ssh_keys\r\n"
                    b"226 Transfer complete.\r\n"
                )
            elif cl.startswith("RETR"):
                conn.sendall(b"550 Permission denied.\r\n")
            elif cl.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"200 OK\r\n")
    except socket.timeout:
        pass

# ── Main connection handler ─────────────────────────────────────
def handle_connection(conn, addr, port):
    start        = time.time()
    attacker_ip, attacker_port = addr
    payload_parts = []

    try:
        conn.settimeout(15)

        if port == 80:
            handle_http(conn, payload_parts)

        elif port == 21:
            handle_ftp(conn, payload_parts)

        elif port in (22, 23):
            # Send banner
            conn.sendall(BANNERS[port])
            # Read initial probe byte (nmap etc.)
            try:
                conn.recv(64)
            except socket.timeout:
                pass

            conn.sendall(b"Username: ")
            try:
                user_data = conn.recv(1024)
            except socket.timeout:
                user_data = b""
            u = user_data.decode(errors="ignore").strip()

            conn.sendall(b"Password: ")
            try:
                pw_data = conn.recv(1024)
            except socket.timeout:
                pw_data = b""
            p = pw_data.decode(errors="ignore").strip()

            if u == "admin" and p == "admin":
                run_fake_shell(conn, payload_parts)
            else:
                payload_parts.append("[Auth failed]")
                conn.sendall(b"\r\nAuthentication failed.\r\n")

        elif port == 3306:
            conn.sendall(BANNERS[3306])
            try:
                data = conn.recv(1024)
                if data:
                    payload_parts.append(f"DB_HANDSHAKE:{data[:40].hex()}")
            except socket.timeout:
                pass

        else:
            try:
                data = conn.recv(1024)
                if data:
                    payload_parts.append(data.decode(errors="ignore").strip()[:80])
            except socket.timeout:
                pass

    except socket.timeout:
        pass   # clean — no [Error] logged
    except Exception as e:
        payload_parts.append(f"[ERR:{e}]")
    finally:
        duration_ms = (time.time() - start) * 1000
        payload     = " | ".join(payload_parts) if payload_parts else "(connection probe)"
        log_attack(attacker_ip, attacker_port, port, payload, duration_ms)
        try:
            conn.close()
        except Exception:
            pass

# ── Listener ────────────────────────────────────────────────────
def start_listener(port):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(10)
        svc = PORT_NAMES.get(port, "?")
        print(f"  \033[92m[+]\033[0m Port {port:5d}  ({svc})")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_connection,
                             args=(conn, addr, port), daemon=True).start()
    except OSError as e:
        print(f"  \033[91m[!]\033[0m Port {port} unavailable — {e}")

# ── Entry point ─────────────────────────────────────────────────
def run():
    print("\033[92m")
    print("╔══════════════════════════════════════════════════════╗")
    print("║         HONEYTRAPX — WIRELESS HONEYPOT v2.1          ║")
    print("╚══════════════════════════════════════════════════════╝\033[0m")
    print("  Active listeners:")
    ports = list(PORT_NAMES.keys())
    enable_mysql = os.environ.get("ENABLE_MYSQL_LISTENER", "0") == "1"
    for p in ports:
        if p == 3306 and not enable_mysql:
            print(f"  \033[90m[-] Port  3306  (MySQL) — skipped (set ENABLE_MYSQL_LISTENER=1 to enable)\033[0m")
            continue
        threading.Thread(target=start_listener, args=(p,), daemon=True).start()
        time.sleep(0.05)

    print("\n\033[92m  [*] All listeners active. Waiting for attackers...\033[0m\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\033[91m[!] Honeypot stopped.\033[0m")

if __name__ == "__main__":
    run()