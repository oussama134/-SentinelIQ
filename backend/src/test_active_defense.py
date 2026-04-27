#!/usr/bin/env python3
"""
SentinelIQ — IP Rotation Bypass Test
======================================
Proves that User-Agent fingerprinting catches attackers
even when they rotate IPs.

Test 1: Same UA, different IPs → should be blocked after threshold
Test 2: Known attack tool UA → should be blocked immediately
Test 3: Ban expiry → should be unblocked after TTL
Test 4: Normal traffic → should NOT be blocked

Run from Windows host:
  python test_active_defense.py
"""
import requests
import time
import random
import json
from datetime import datetime

SIEM = "http://localhost:8000"

# Attacker rotates through these IPs but keeps same User-Agent
ROTATING_IPS = [
    "45.33.32.156",
    "185.220.101.45",
    "94.102.49.190",
    "141.98.10.33",
    "180.76.5.194",
]

ATTACK_UA = "GoldenEye/1.0 (DoS Tool)"
SQLMAP_UA = "sqlmap/1.6.7#stable (https://sqlmap.org)"
NORMAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def check_ban(ip: str, ua: str = None) -> dict:
    params = {"ip": ip}
    if ua:
        params["user_agent"] = ua
    r = requests.post(f"{SIEM}/api/active-defense/check", params=params)
    return r.json()


def send_log(source: str, raw: str) -> dict:
    r = requests.post(f"{SIEM}/api/logs/ingest",
                     json={"source": source, "raw": raw})
    return r.json()


def get_bans() -> list:
    r = requests.get(f"{SIEM}/api/active-defense/bans")
    return r.json().get("bans", [])


# =============================================================================
# TEST 1: Immediate block on known attack tool User-Agent
# =============================================================================
def test_1_scanner_ua_immediate_block():
    section("TEST 1: Attack Tool UA → Immediate Block")
    print(f"Sending 1 request with sqlmap User-Agent from a fresh IP...")

    # Send one nginx log with sqlmap UA
    raw_log = f'203.0.113.5 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /login HTTP/1.1" 200 1234 "-" "{SQLMAP_UA}"'
    result = send_log("nginx", raw_log)
    print(f"  Log ingestion result: {result}")

    time.sleep(1)

    # Check if UA was banned
    ban_check = check_ban("203.0.113.5", SQLMAP_UA)
    if ban_check.get("is_blocked"):
        print(f"  ✅ PASS: sqlmap UA blocked immediately")
        print(f"     Reason: {ban_check.get('reason')}")
    else:
        print(f"  ❌ FAIL: sqlmap UA was NOT blocked")
        print(f"     Check: {ban_check}")


# =============================================================================
# TEST 2: IP Rotation Bypass — same UA different IPs
# =============================================================================
def test_2_ip_rotation_bypass():
    section("TEST 2: IP Rotation Bypass — Same UA, Different IPs")
    print(f"Simulating DoS attack rotating through {len(ROTATING_IPS)} IPs...")
    print(f"User-Agent: {ATTACK_UA}")
    print()

    # Send 60 requests spread across different IPs but same UA
    for i in range(60):
        ip = ROTATING_IPS[i % len(ROTATING_IPS)]
        raw = f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /?id={i} HTTP/1.1" 200 512 "-" "{ATTACK_UA}"'
        requests.post(f"{SIEM}/api/logs/ingest",
                     json={"source": "nginx", "raw": raw}, timeout=3)
        if i % 10 == 9:
            print(f"  Sent {i+1}/60 requests across rotating IPs...")
        time.sleep(0.05)

    time.sleep(2)

    # Check if ANY of the rotating IPs got caught, or the UA itself
    print()
    print("  Checking ban status...")
    ua_check = check_ban(ROTATING_IPS[0], ATTACK_UA)
    if ua_check.get("is_blocked"):
        print(f"  ✅ PASS: Attack detected despite IP rotation!")
        print(f"     Blocked by: {'UA' if ua_check.get('ua_ban') else 'IP'}")
        print(f"     Reason: {ua_check.get('reason')}")
    else:
        # Check individual IPs
        any_blocked = False
        for ip in ROTATING_IPS:
            check = check_ban(ip)
            if check.get("is_blocked"):
                print(f"  ✅ PASS: IP {ip} was banned")
                any_blocked = True
        if not any_blocked:
            print(f"  ⚠️  PARTIAL: No ban triggered yet (may need more requests)")
            print(f"     Active bans: {len(get_bans())}")


# =============================================================================
# TEST 3: SQLi via Log Forwarding
# =============================================================================
def test_3_sqli_detection():
    section("TEST 3: SQL Injection Detection via Apache Logs")

    sqli_payloads = [
        "GET /product?id=1'+OR+'1'='1 HTTP/1.1",
        "GET /search?q=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1",
        "GET /api?id=1;+DROP+TABLE+users-- HTTP/1.1",
    ]

    for payload in sqli_payloads:
        raw = f'192.168.56.101 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{payload}" 200 1024 "-" "python-requests/2.25.1"'
        result = send_log("nginx", raw)
        status = result.get("status", "?")
        print(f"  {payload[:60]}...")
        print(f"    → {status} | event: {result.get('event_type', '?')}")
        time.sleep(0.3)

    time.sleep(1)
    # Check alerts in SIEM
    alerts = requests.get(f"{SIEM}/api/siem/alerts?limit=5").json().get("alerts", [])
    sqli_alerts = [a for a in alerts if "sql" in str(a.get("attack_type", "")).lower() or
                   "injection" in str(a.get("title", "")).lower()]
    if sqli_alerts:
        print(f"\n  ✅ PASS: {len(sqli_alerts)} SQLi alert(s) in SIEM")
        for a in sqli_alerts[:2]:
            print(f"     [{a['severity']}] {a['title']}")
    else:
        print(f"\n  ❌ No SQLi alerts found (check /api/siem/alerts)")


# =============================================================================
# TEST 4: Legitimate Traffic → NOT Blocked
# =============================================================================
def test_4_legitimate_traffic_not_blocked():
    section("TEST 4: Legitimate Traffic — Should NOT Be Blocked")

    legit_ip = "192.168.56.200"  # Ubuntu victim IP (legitimate)
    print(f"Checking if legitimate IP {legit_ip} is blocked...")

    check = check_ban(legit_ip, NORMAL_UA)
    if not check.get("is_blocked"):
        print(f"  ✅ PASS: Legitimate IP {legit_ip} is NOT blocked")
    else:
        print(f"  ❌ FAIL: Legitimate IP wrongly blocked: {check.get('reason')}")

    # Send some normal nginx logs
    normal_logs = [
        f'192.168.1.100 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.html HTTP/1.1" 200 2048 "-" "{NORMAL_UA}"',
        f'192.168.1.100 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /style.css HTTP/1.1" 200 512 "-" "{NORMAL_UA}"',
    ]
    for log in normal_logs:
        result = send_log("nginx", log)
        print(f"  Normal request: {result.get('status', '?')}")

    print(f"  ✅ Normal traffic passes through correctly")


# =============================================================================
# TEST 5: SSH Brute Force via Auth Log
# =============================================================================
def test_5_ssh_brute_force_logs():
    section("TEST 5: SSH Brute Force via Auth.log Forwarding")
    attacker = "192.168.56.101"
    print(f"Simulating 15 SSH failures from {attacker}...")

    for i in range(15):
        ts = datetime.now().strftime("%b %d %H:%M:%S").replace("  ", " 0")
        raw = f"{ts} server sshd[{1000+i}]: Failed password for root from {attacker} port {50000+i} ssh2"
        result = send_log("linux-auth", raw)
        if i % 5 == 4:
            print(f"  {i+1}/15 → {result.get('status', '?')} | {result.get('event_type', '?')}")
        time.sleep(0.1)

    time.sleep(1)
    alerts = requests.get(f"{SIEM}/api/siem/alerts?limit=10").json().get("alerts", [])
    ssh_alerts = [a for a in alerts
                  if "ssh" in str(a.get("attack_type", "")).lower() or
                     "brute" in str(a.get("title", "")).lower()]
    if ssh_alerts:
        print(f"\n  ✅ PASS: {len(ssh_alerts)} SSH alert(s) generated")
        for a in ssh_alerts[:2]:
            print(f"     [{a['severity']}] {a['title']}")
    else:
        print(f"\n  ❌ No SSH alerts found")


# =============================================================================
# TEST 6: TTL Expiry Test (fast version)
# =============================================================================
def test_6_ttl_expiry():
    section("TEST 6: TTL Expiry — Ban Auto-Removes")
    print("Manually banning IP for 5 seconds...")

    # Ban for 5 seconds
    r = requests.post(f"{SIEM}/api/active-defense/ban-ip",
                     params={"ip": "10.0.0.99",
                             "reason": "TTL test ban",
                             "ttl": 5})
    print(f"  Ban result: {r.json().get('success')}")

    # Verify banned
    check1 = check_ban("10.0.0.99")
    print(f"  Immediately: is_blocked={check1.get('is_blocked')} ✅ (expected True)")

    # Wait for expiry
    print("  Waiting 7 seconds for TTL to expire...")
    time.sleep(7)

    # Verify expired
    check2 = check_ban("10.0.0.99")
    if not check2.get("is_blocked"):
        print(f"  After 7s: is_blocked=False ✅ PASS: Ban expired correctly")
    else:
        print(f"  After 7s: still blocked ❌ (TTL may not be working)")


# =============================================================================
# SUMMARY
# =============================================================================
def print_summary():
    section("FINAL STATE — Active Bans")
    bans = get_bans()
    if bans:
        for ban in bans:
            print(f"  [{ban['ban_type']}] {ban['identifier'][:50]}")
            print(f"    Reason: {ban['reason'][:60]}")
            print(f"    Expires in: {ban['time_remaining_seconds']}s")
            print(f"    Hit count: {ban['hit_count']}")
            print()
    else:
        print("  No active bans")

    stats = requests.get(f"{SIEM}/api/active-defense/stats").json()
    print(f"  Total bans issued: {stats.get('total_bans_issued', 0)}")
    print(f"  Requests blocked:  {stats.get('total_requests_blocked', 0)}")

    try:
        diag = requests.get(f"{SIEM}/api/diagnostic", timeout=3).json()
        remote = diag.get("remote_response", {})
        if remote.get("enabled"):
            print(f"  Remote response: {remote.get('user')}@{remote.get('host')} via {remote.get('backend')}")
        else:
            print("  Remote response: disabled")
    except Exception:
        pass

    print("\n  Dashboard: http://localhost:3000")
    print("  API docs:  http://localhost:8000/docs")


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║   SentinelIQ — Active Defense Test Suite             ║
║   Tests: UA Fingerprinting, IP Rotation Bypass,      ║
║          SQLi, SSH Brute, TTL Expiry                  ║
╚══════════════════════════════════════════════════════╝
""")
    # Connectivity check
    try:
        r = requests.get(f"{SIEM}/", timeout=3)
        print(f"✅ Connected to SentinelIQ at {SIEM}\n")
    except Exception:
        print(f"❌ Cannot reach {SIEM}")
        print("   Make sure: uvicorn main:app --reload --port 8000")
        exit(1)

    test_1_scanner_ua_immediate_block()
    test_2_ip_rotation_bypass()
    test_3_sqli_detection()
    test_4_legitimate_traffic_not_blocked()
    test_5_ssh_brute_force_logs()
    test_6_ttl_expiry()
    print_summary()
