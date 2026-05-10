#!/bin/bash

# Kill existing processes
echo "[*] Cleaning up existing services..."
kill $(lsof -t -i :5000) 2>/dev/null || true
kill $(lsof -t -i :2222) 2>/dev/null || true
kill $(lsof -t -i :2121) 2>/dev/null || true
kill $(lsof -t -i :2323) 2>/dev/null || true
kill $(lsof -t -i :8080) 2>/dev/null || true
kill $(lsof -t -i :33060) 2>/dev/null || true

echo "[+] Starting HoneyTrapX Dashboard (Port 5000)..."
python app.py > logs/app.log 2>&1 &

echo "[+] Starting Honeypot Services..."
python honeypot.py > logs/honeypot.log 2>&1 &

echo "[!] HoneyTrapX is now running."
echo "[!] Dashboard: http://localhost:5000"
echo "[!] Use 'python attacker_sim.py' in a new terminal to simulate attacks."
