# HoneyTrapX

### 1. Install Dependencies
```
pip install flask pandas matplotlib
```

### 2. Structure:
```
HoneyTrapX
    ├── honeypot.py        ← Core listener (captures attacks)
    ├── analyzer.py        ← Analyzes attack patterns
    ├── app.py             ← Flask web dashboard
    ├── templates/
    │   └── index.html     ← Beautiful dashboard UI
    ├── logs/
    │     └── attacks.csv    ← Auto-created
    └── reports/           ← Charts saved here
```

### 3. Execution Flow:
#### i. Run the Listener (keep Running)
```
python honeypot.py
```
#### ii. Run the Dashboard (Keep Running)
```
python app.py
```

#### iii.Generate Attack Log (New Terminal)
```
python -c "
import socket, time
ports = [21, 22, 23, 80, 8080, 3306]
for p in ports:
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('127.0.0.1', p))
        s.send(b'admin\r\n')
        s.close()
        print(f'Hit port {p}')
        time.sleep(0.5)
    except: pass
print('Done!') "
```

#### iv. For Showing Charts 
```
python analyzer.py
```
