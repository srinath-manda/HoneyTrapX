import socket
import time
import threading

def ssh_brute_force():
    print("[*] Simulating SSH Brute Force...")
    for _ in range(5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 2222))
            s.recv(1024)
            s.sendall(b'admin\n')
            s.recv(1024)
            s.sendall(b'wrongpass\n')
            s.close()
            time.sleep(0.5)
        except: pass

def ssh_success_canary():
    print("[*] Simulating SSH success and Canary access...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2222))
        s.recv(1024) # banner
        s.sendall(b'admin\n')
        s.recv(1024) # User:
        s.sendall(b'admin\n')
        s.recv(1024) # Pass:
        s.sendall(b'admin\n')
        s.recv(1024) # Welcome
        s.sendall(b'cat /etc/shadow\n')
        time.sleep(1)
        s.sendall(b'exit\n')
        s.close()
    except: pass

def ftp_probe():
    print("[*] Simulating FTP Probe...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2121))
        s.recv(1024)
        s.sendall(b'USER anonymous\r\n')
        s.recv(1024)
        s.sendall(b'PASS guest\r\n')
        s.recv(1024)
        s.sendall(b'LIST\r\n')
        s.recv(1024)
        s.sendall(b'QUIT\r\n')
        s.close()
    except: pass

def http_scan():
    print("[*] Simulating HTTP Scan...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 8080))
        s.sendall(b'GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n')
        s.recv(1024)
        s.close()
    except: pass

if __name__ == "__main__":
    ssh_brute_force()
    ssh_success_canary()
    ftp_probe()
    http_scan()
    print("[+] Simulations complete.")
