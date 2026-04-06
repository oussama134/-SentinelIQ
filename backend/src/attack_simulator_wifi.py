#!/usr/bin/env python3
"""
SentinelIQ — WiFi Attack Simulator
====================================
Sends ALL traffic through the REAL WiFi adapter (interface 4).
This means tshark captures it, the ML model classifies it,
and the SIEM generates diverse alerts (not just DDoS).

Attack types covered:
  • DDoS     → UDP flood to external IPs          → CRITICAL
  • PortScan → TCP SYN sweep to many ports        → MEDIUM
  • SSH-Brut → Many TCP connections to port 22    → HIGH
  • FTP-Brut → Many TCP connections to port 21    → HIGH
  • Bot      → Periodic beaconing (C2 patterns)   → HIGH
  • DoS Hulk → HTTP GET flood to gateway (port 80)→ CRITICAL

⚠️  USE ONLY ON YOUR OWN NETWORK
"""

import socket
import threading
import time
import random
import subprocess
import sys
import os

# ── External IPs (traffic routes through WiFi, NOT loopback) ──────────────────
EXTERNAL_IPS = [
    "8.8.8.8",          # Google DNS
    "8.8.4.4",          # Google DNS 2
    "1.1.1.1",          # Cloudflare
    "1.0.0.1",          # Cloudflare 2
    "9.9.9.9",          # Quad9
    "208.67.222.222",   # OpenDNS
    "94.140.14.14",     # AdGuard
]

BANNER = """
╔══════════════════════════════════════════════════════════╗
║   SentinelIQ WiFi Attack Simulator (Interface 4)        ║
║   ⚠️  USE ONLY ON YOUR OWN NETWORK  ⚠️                   ║
║                                                          ║
║   All traffic → WiFi NIC → tshark captures it           ║
║   ML model classifies it → SIEM alerts fire             ║
║                                                          ║
║   Attack types:                                          ║
║   • DDoS     - UDP flood          → CRITICAL             ║
║   • PortScan - TCP SYN sweep      → MEDIUM               ║
║   • SSH Brute- TCP to port 22     → HIGH                 ║
║   • FTP Brute- TCP to port 21     → HIGH                 ║
║   • Bot C&C  - Periodic beaconing → HIGH                 ║
║   • DoS Hulk - HTTP GET flood     → CRITICAL             ║
╚══════════════════════════════════════════════════════════╝
"""


def timestamp():
    return time.strftime("[%H:%M:%S]")


# ── Attack 1: DDoS UDP Flood ──────────────────────────────────────────────────
def attack_ddos(count=800):
    """UDP flood to external IPs — routes through WiFi, detected as DDoS"""
    print(f"{timestamp()} 🌊 DDoS: Sending {count} UDP packets to external IPs...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random.randbytes(512)
    sent = 0
    for _ in range(count):
        ip = random.choice(EXTERNAL_IPS)
        port = random.randint(1024, 65535)
        try:
            s.sendto(payload, (ip, port))
            sent += 1
        except Exception:
            pass
    s.close()
    print(f"{timestamp()} ✅ DDoS complete ({sent} UDP packets sent)")


# ── Attack 2: PortScan ────────────────────────────────────────────────────────
def attack_portscan(target=None, port_count=300):
    """TCP SYN sweep across many ports — detected as PortScan"""
    target = target or random.choice(EXTERNAL_IPS)
    print(f"{timestamp()} 🔍 PortScan: Scanning {port_count} ports on {target}...")
    scanned = 0
    for port in range(1, port_count + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.08)
            s.connect_ex((target, port))
            s.close()
            scanned += 1
        except Exception:
            pass
    print(f"{timestamp()} ✅ PortScan complete ({scanned} ports on {target})")


# ── Attack 3: SSH Brute Force ─────────────────────────────────────────────────
def attack_ssh_brute(attempts=60):
    """Many TCP connections to port 22 — detected as SSH-Patator"""
    print(f"{timestamp()} 🔑 SSH Brute: {attempts} connection attempts to port 22...")
    success = 0
    for i in range(attempts):
        ip = random.choice(EXTERNAL_IPS)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((ip, 22))
            # Send a fake SSH banner to make flow look more realistic
            try:
                s.send(b"SSH-2.0-OpenSSH_8.0\r\n")
            except Exception:
                pass
            time.sleep(0.05)
            s.close()
            success += 1
        except Exception:
            pass
        time.sleep(0.02)
    print(f"{timestamp()} ✅ SSH Brute complete ({success}/{attempts} connections)")


# ── Attack 4: FTP Brute Force ─────────────────────────────────────────────────
def attack_ftp_brute(attempts=60):
    """Many TCP connections to port 21 — detected as FTP-Patator"""
    print(f"{timestamp()} 📂 FTP Brute: {attempts} connection attempts to port 21...")
    success = 0
    for i in range(attempts):
        ip = random.choice(EXTERNAL_IPS)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((ip, 21))
            try:
                s.send(b"USER admin\r\nPASS password\r\n")
            except Exception:
                pass
            time.sleep(0.05)
            s.close()
            success += 1
        except Exception:
            pass
        time.sleep(0.02)
    print(f"{timestamp()} ✅ FTP Brute complete ({success}/{attempts} connections)")


# ── Attack 5: Botnet C&C Beaconing ───────────────────────────────────────────
def attack_bot(beacons=25, interval=1.5):
    """Periodic TCP connections to C2 ports — detected as Bot"""
    c2_ports = [6667, 6668, 6669, 4444, 8080, 9090, 1080]
    print(f"{timestamp()} 🤖 Bot: {beacons} beacons to C&C ports {c2_ports[:3]}...")
    sent = 0
    for i in range(beacons):
        ip = random.choice(EXTERNAL_IPS)
        port = random.choice(c2_ports)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect_ex((ip, port))
            # Send a fake C2 beacon payload
            payload = f"BEACON|{i}|{random.randint(1000,9999)}|CHECKIN\r\n".encode()
            try:
                s.send(payload)
            except Exception:
                pass
            time.sleep(interval)
            s.close()
            sent += 1
        except Exception:
            pass
    print(f"{timestamp()} ✅ Bot complete ({sent} beacons sent)")


# ── Attack 6: DoS HTTP Flood (to gateway) ────────────────────────────────────
def attack_dos_hulk(requests=250):
    """HTTP GET flood sent to the local gateway — detected as DoS Hulk"""
    # Detect gateway IP
    gateway = _get_gateway()
    print(f"{timestamp()} 💥 DoS Hulk: {requests} HTTP GETs to gateway {gateway}:80...")
    success = 0
    for i in range(requests):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            conn = s.connect_ex((gateway, 80))
            path = f"/?id={random.randint(0,999999)}&ref={random.randint(0,999999)}&ts={time.time()}"
            ua = f"Mozilla/5.0 (Windows NT 10.0) Hulk/{random.randint(1,99)}"
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {gateway}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Connection: keep-alive\r\n"
                f"Cache-Control: no-cache\r\n\r\n"
            )
            try:
                s.send(req.encode())
            except Exception:
                pass
            s.close()
            success += 1
        except Exception:
            pass
        time.sleep(0.02)
    print(f"{timestamp()} ✅ DoS Hulk complete ({success} requests to {gateway})")


def _get_gateway():
    """Detect the default gateway IP"""
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=3
        )
        lines = result.stdout.split('\n')
        for line in lines:
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    gw = parts[-1].strip()
                    if gw and gw != '' and '.' in gw:
                        return gw
    except Exception:
        pass
    return "192.168.1.1"   # fallback


# ── MENU ──────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "1": ("DDoS UDP Flood",     lambda: attack_ddos(800)),
    "2": ("PortScan",           lambda: attack_portscan(port_count=300)),
    "3": ("SSH Brute Force",    lambda: attack_ssh_brute(60)),
    "4": ("FTP Brute Force",    lambda: attack_ftp_brute(60)),
    "5": ("Bot C&C Beaconing",  lambda: attack_bot(25, 1.5)),
    "6": ("DoS Hulk",           lambda: attack_dos_hulk(250)),
    "7": ("ALL (sequential)",   None),
    "8": ("ALL (parallel)",     None),
}


def run_all_parallel():
    """Run all attacks simultaneously — maximises detection diversity"""
    print(f"{timestamp()} 🚀 Launching ALL attacks in PARALLEL...\n")
    threads = [
        threading.Thread(target=attack_ddos, args=(800,), name="DDoS"),
        threading.Thread(target=attack_portscan, kwargs={"port_count": 300}, name="PortScan"),
        threading.Thread(target=attack_ssh_brute, args=(60,), name="SSH"),
        threading.Thread(target=attack_ftp_brute, args=(60,), name="FTP"),
        threading.Thread(target=attack_bot, args=(25, 1.5), name="Bot"),
        threading.Thread(target=attack_dos_hulk, args=(250,), name="DoSHulk"),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"\n{timestamp()} ✅ ALL attacks complete!")
    print(f"{timestamp()} 📊 Check dashboard — should see DDoS + PortScan + Bot + DoS alerts")


def run_all_sequential():
    print(f"{timestamp()} 🚀 Running ALL attacks sequentially...")
    attack_ddos(800)
    attack_portscan(port_count=300)
    attack_ssh_brute(60)
    attack_ftp_brute(60)
    attack_bot(20, 1.0)
    attack_dos_hulk(250)
    print(f"\n{timestamp()} ✅ ALL attacks complete!")


if __name__ == "__main__":
    print(BANNER)

    print("Available scenarios:")
    for k, (name, _) in SCENARIOS.items():
        print(f"  {k}. {name}")

    choice = input("\nSelect scenario [8]: ").strip() or "8"

    if choice not in SCENARIOS:
        print("Invalid choice. Running ALL parallel.")
        choice = "8"

    name, fn = SCENARIOS[choice]
    print(f"\n⚠️  Start '{name}' simulation? (yes/no): ", end="")
    confirm = input().strip().lower()
    if confirm not in ("yes", "y"):
        print("Aborted.")
        sys.exit(0)

    print(f"\n⚠️  Starting in 3 seconds...\n")
    time.sleep(3)

    if choice == "7":
        run_all_sequential()
    elif choice == "8":
        run_all_parallel()
    else:
        fn()
