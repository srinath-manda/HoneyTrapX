CANARY_FILES = {
    "/etc/shadow": "T1003.008 (OS Credential Dumping: /etc/shadow)",
    "secret.txt": "T1567 (Exfiltration to Cloud Repository / Sensitive File Access)",
    "/etc/passwd": "T1083 (File and Directory Discovery)",
}

def check_canary(filepath):
    """Returns the MITRE technique if the file is a canary, else None."""
    for canary, technique in CANARY_FILES.items():
        if filepath.endswith(canary):
            return technique
    return None
