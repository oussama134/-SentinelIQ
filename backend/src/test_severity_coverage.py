#!/usr/bin/env python3
"""
SentinelIQ — Severity Coverage Test
=====================================
Verifies that LOW, MEDIUM, HIGH, and CRITICAL alerts are all generated.

Run from backend/src/:
    python test_severity_coverage.py

What each test triggers:
  LOW      R025 — single SSH failure (first failure from new IP)
  LOW      R026 — SSH invalid username
  LOW      R027 — 3 nginx 4xx errors
  MEDIUM   R004 — port scan (rule-based, 30+ ports)
  MEDIUM   R018 — 15 nginx 4xx errors
  HIGH     R013 — 3 SSH failures in 60s (auth.log brute force)
  HIGH     R017 — attack-tool User-Agent (gobuster/sqlmap)
  CRITICAL R012 — root login attempt
  CRITICAL R015 — SQL injection in nginx log
"""
import requests
import time
from datetime import datetime

SIEM = "http://localhost:8000"
ATTACKER = "10.99.88.77"   # fresh IP not in your real traffic


def ts():
    return datetime.now().strftime("%b %d %H:%M:%S").replace("  ", " 0")


def nginx_ts():
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")


def send(source, raw):
    r = requests.post(f"{SIEM}/api/logs/ingest",
                      json={"source": source, "raw": raw}, timeout=5)
    return r.json()


def get_alerts(limit=30):
    r = requests.get(f"{SIEM}/api/siem/alerts?limit={limit}", timeout=5)
    return r.json().get("alerts", [])


def section(title):
    print(f"\n{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}")


def check_severity(label, expected_sev, alerts_before):
    time.sleep(1.2)
    after = get_alerts()
    new_alerts = [a for a in after if a["id"] not in {x["id"] for x in alerts_before}]
    matched = [a for a in new_alerts
               if expected_sev in str(a.get("severity", "")).upper()]
    if matched:
        a = matched[0]
        print(f"  ✅ {label}: [{a['severity'].replace('SeverityLevel.','')}] "
              f"{a['title']} | {a['attack_type']}")
    else:
        if new_alerts:
            sev = new_alerts[0]['severity'].replace('SeverityLevel.', '')
            print(f"  ⚠  {label}: got [{sev}] instead of [{expected_sev}] — "
                  f"{new_alerts[0]['title']}")
        else:
            print(f"  ❌ {label}: no new alert (check suppressor / rule threshold)")
    return new_alerts


# ── connectivity ──────────────────────────────────────────────
try:
    requests.get(f"{SIEM}/", timeout=3)
    print(f"✅ Connected to SentinelIQ at {SIEM}")
except Exception:
    print(f"❌ Cannot reach {SIEM} — start the backend first")
    exit(1)

baseline = get_alerts()
baseline_ids = {a["id"] for a in baseline}
print(f"   Baseline: {len(baseline)} existing alerts in DB\n")


# ════════════════════════════════════════════════════════════
section("TEST 1 — LOW: First SSH Login Failure (R025)")
# ════════════════════════════════════════════════════════════
# Use a fresh IP so the suppressor hasn't seen it
ip_low1 = "10.99.1.1"
result = send("linux-auth",
              f"{ts()} server sshd[2001]: Failed password for testuser "
              f"from {ip_low1} port 11111 ssh2")
print(f"  Sent: {result.get('status')} | event={result.get('event_type')}")
check_severity("SSH failure #1", "LOW", baseline)


# ════════════════════════════════════════════════════════════
section("TEST 2 — LOW: Invalid SSH Username (R026)")
# ════════════════════════════════════════════════════════════
ip_low2 = "10.99.1.2"
result = send("linux-auth",
              f"{ts()} server sshd[2002]: Invalid user hacker "
              f"from {ip_low2} port 22222 ssh2")
print(f"  Sent: {result.get('status')} | event={result.get('event_type')}")
check_severity("SSH invalid user", "LOW", baseline)


# ════════════════════════════════════════════════════════════
section("TEST 3 — LOW: 3 nginx 4xx errors (R027)")
# ════════════════════════════════════════════════════════════
ip_low3 = "10.99.1.3"
before = get_alerts()
for path in ["/admin", "/.env", "/config.php"]:
    send("nginx",
         f'{ip_low3} - - [{nginx_ts()}] "GET {path} HTTP/1.1" 404 162 "-" "curl/7.68.0"')
    time.sleep(0.15)
print(f"  Sent 3 x 404 requests")
check_severity("HTTP probing (3x 404)", "LOW", before)


# ════════════════════════════════════════════════════════════
section("TEST 4 — MEDIUM: 15 nginx 4xx errors (R018)")
# ════════════════════════════════════════════════════════════
ip_med1 = "10.99.2.1"
before = get_alerts()
for i in range(15):
    send("nginx",
         f'{ip_med1} - - [{nginx_ts()}] "GET /probe{i} HTTP/1.1" 404 162 "-" "curl/7.68.0"')
    time.sleep(0.05)
print(f"  Sent 15 x 404 requests")
check_severity("Web scanning (15x 404)", "MEDIUM", before)


# ════════════════════════════════════════════════════════════
section("TEST 5 — HIGH: SSH Brute Force via auth.log (R013)")
# ════════════════════════════════════════════════════════════
ip_high1 = "10.99.3.1"
before = get_alerts()
for i in range(5):
    send("linux-auth",
         f"{ts()} server sshd[{3000+i}]: Failed password for root "
         f"from {ip_high1} port {40000+i} ssh2")
    time.sleep(0.1)
print(f"  Sent 5 SSH failures from {ip_high1}")
check_severity("SSH brute force (5 failures)", "HIGH", before)


# ════════════════════════════════════════════════════════════
section("TEST 6 — HIGH: Attack-tool User-Agent (R017)")
# ════════════════════════════════════════════════════════════
ip_high2 = "10.99.3.2"
before = get_alerts()
result = send("nginx",
              f'{ip_high2} - - [{nginx_ts()}] '
              f'"GET /wp-admin HTTP/1.1" 404 162 "-" "gobuster/3.1.0"')
print(f"  Sent gobuster UA: {result.get('status')} | event={result.get('event_type')}")
check_severity("Scanner UA (gobuster)", "HIGH", before)


# ════════════════════════════════════════════════════════════
section("TEST 7 — CRITICAL: Root Login Attempt (R012)")
# ════════════════════════════════════════════════════════════
ip_crit1 = "10.99.4.1"
before = get_alerts()
result = send("linux-auth",
              f"{ts()} server sshd[4001]: Failed password for root "
              f"from {ip_crit1} port 55001 ssh2")
print(f"  Sent root login attempt: {result.get('status')} | event={result.get('event_type')}")
check_severity("Root login attempt", "CRITICAL", before)


# ════════════════════════════════════════════════════════════
section("TEST 8 — CRITICAL: SQL Injection (R015)")
# ════════════════════════════════════════════════════════════
ip_crit2 = "10.99.4.2"
before = get_alerts()
result = send("nginx",
              f'{ip_crit2} - - [{nginx_ts()}] '
              f'"GET /api?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 512 "-" "python-requests/2.28.0"')
print(f"  Sent SQLi payload: {result.get('status')} | event={result.get('event_type')}")
check_severity("SQL injection", "CRITICAL", before)


# ════════════════════════════════════════════════════════════
section("SUMMARY — Severity Distribution")
# ════════════════════════════════════════════════════════════
time.sleep(1)
final = get_alerts(50)
new_all = [a for a in final if a["id"] not in baseline_ids]
from collections import Counter
dist = Counter(a["severity"].replace("SeverityLevel.", "") for a in new_all)
print(f"\n  New alerts from this test run: {len(new_all)}")
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    n = dist.get(sev, 0)
    bar = "█" * n
    status = "✅" if n > 0 else "❌"
    print(f"  {status} {sev:<10} {n:>3}  {bar}")

# dashboard check
dr = requests.get(f"{SIEM}/api/siem/dashboard", timeout=5).json()
by_sev = dr.get("by_severity", {})
print(f"\n  DB totals (all time):")
for k, v in by_sev.items():
    print(f"    {k:<35} {v}")

print(f"\n  Dashboard: http://localhost:3000")
print(f"  API docs:  http://localhost:8000/docs")
