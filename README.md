# HoneyTrapX

### 1. Install Dependencies
```
pip install requirements.txt
```

### 2. Structure:
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
python test_fake_shell.py
```

#### iv. For Showing Charts 
```
python analyzer.py
```
