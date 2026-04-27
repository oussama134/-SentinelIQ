#!/usr/bin/env python3
"""
SentinelIQ - Ubuntu Log + Packet Forwarder Agent
-------------------------------------------------
Tails auth.log / nginx / syslog and forwards them to the Windows SIEM.
Also captures live network traffic with tcpdump and POSTs pcap chunks
to /api/pcap/ingest so the Windows ML model can analyse attack flows.

Usage on Ubuntu Victim:
  sudo python3 ubuntu_forwarder.py --siem http://192.168.56.1:8000
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


# ── Syslog noise filter ───────────────────────────────────────────────────────
# /var/log/syslog is extremely noisy (cron, kernel, dhcp, ...).
# Only forward lines that contain security-relevant keywords.
_SYSLOG_SECURITY = re.compile(
    r"(fail|error|denied|invalid|attack|breach|unauthorized|refused|blocked"
    r"|sudo|su\b|sshd|authentication|segfault|oom.killer|firewall|ufw|iptables"
    r"|nmap|scan|brute|exploit|injection|malware|rootkit)",
    re.IGNORECASE,
)

def _syslog_filter(line: str) -> bool:
    return bool(_SYSLOG_SECURITY.search(line))


# ── Log sources ───────────────────────────────────────────────────────────────
LOG_FILES = [
    {"path": "/var/log/auth.log",           "source": "linux-auth"},
    {"path": "/var/log/nginx/access.log",   "source": "nginx"},
    {"path": "/var/log/apache2/access.log", "source": "apache"},
    {"path": "/var/log/syslog",             "source": "syslog",  "filter": _syslog_filter},
]

DEFAULT_SIEM_URL     = "http://192.168.56.1:8000"
FORWARD_TIMEOUT      = 8
CONNECTIVITY_TIMEOUT = 5
FLUSH_INTERVAL       = 1.0
MAX_BATCH_SIZE       = 50
RETRY_DELAY          = 2

# Packet capture settings
PCAP_INTERFACE   = "enp0s8"
PCAP_WINDOW_SEC  = 10
PCAP_SLOT_COUNT  = 5


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_base_url(siem_url):
    return siem_url.rstrip("/")


def check_connectivity(siem_url):
    try:
        with urllib.request.urlopen(
            f"{normalize_base_url(siem_url)}/", timeout=CONNECTIVITY_TIMEOUT
        ) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return resp.status == 200 and "SentinelIQ" in body
    except Exception as e:
        print(f"[!] Initial connectivity check failed: {e}")
        return False


def forward_logs(siem_url, payload):
    url  = f"{normalize_base_url(siem_url)}/api/logs/ingest/bulk"
    data = json.dumps({"logs": payload}).encode("utf-8")
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "SentinelAgent/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=FORWARD_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return True, body
    except Exception as e:
        return False, str(e)


def forward_pcap(siem_url, pcap_path):
    url = f"{normalize_base_url(siem_url)}/api/pcap/ingest"
    try:
        with open(pcap_path, "rb") as f:
            data = f.read()
        if len(data) < 25:
            return False, "empty"
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/octet-stream", "User-Agent": "SentinelAgent/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return True, body
    except Exception as e:
        return False, str(e)


def _detect_interface():
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr"], text=True)
        for line in out.splitlines():
            parts = line.split()
            iface = parts[1]
            addr  = parts[3].split("/")[0]
            if addr.startswith("192.168.56."):
                return iface
    except Exception:
        pass
    return PCAP_INTERFACE


# ── Log tail thread ───────────────────────────────────────────────────────────

def tail_file(siem_url, log_info):
    path       = log_info["path"]
    source     = log_info["source"]
    pre_filter = log_info.get("filter")   # optional callable(line) -> bool

    # Wait until the file exists (e.g. nginx not yet started)
    if not os.path.exists(path):
        print(f"[*] Waiting for {path} to be created...")
        while not os.path.exists(path):
            time.sleep(5)

    # Open and seek to end — we only want new lines from now on
    try:
        fh = open(path, "r", encoding="utf-8", errors="ignore")
    except PermissionError:
        print(f"[!] Permission denied: {path} — run with sudo")
        return
    except Exception as e:
        print(f"[!] Cannot open {path}: {e}")
        return

    fh.seek(0, os.SEEK_END)
    try:
        current_inode = os.stat(path).st_ino
    except Exception:
        current_inode = None

    print(f"[+] Started monitoring {path} as '{source}'...")

    buffer    = []
    last_send = time.time()

    while True:
        line = fh.readline()

        if not line:
            time.sleep(0.3)

            # ── Log rotation detection ────────────────────────────────
            # If the inode changed the file was rotated (logrotate replaced it).
            # Reopen from the beginning of the new file.
            try:
                new_inode = os.stat(path).st_ino
                if current_inode and new_inode != current_inode:
                    fh.close()
                    fh = open(path, "r", encoding="utf-8", errors="ignore")
                    current_inode = new_inode
                    print(f"[~] Log rotated — reopened {path}")
            except FileNotFoundError:
                pass  # file briefly absent during rotation — will reappear
            except Exception:
                pass

        else:
            line = line.strip()
            if not line:
                continue

            # Apply source-specific pre-filter (used for syslog noise reduction)
            if pre_filter and not pre_filter(line):
                continue

            buffer.append({"source": source, "raw": line})

        # ── Flush batch ───────────────────────────────────────────────
        if buffer and (
            time.time() - last_send > FLUSH_INTERVAL
            or len(buffer) >= MAX_BATCH_SIZE
        ):
            batch   = list(buffer[:MAX_BATCH_SIZE])
            success, detail = forward_logs(siem_url, batch)

            if success:
                del buffer[:len(batch)]
                last_send = time.time()
                try:
                    resp = json.loads(detail) if detail else {}
                except Exception:
                    resp = {}
                parsed = resp.get("parsed", "?")
                fired  = resp.get("alerts_fired", "?")
                print(f"[>] {source}: {len(batch)} line(s) forwarded | parsed={parsed} alerts={fired}")
            else:
                print(f"[-] {source}: forward failed ({detail[:80]}) | queued={len(buffer)}")
                time.sleep(RETRY_DELAY)


# ── PCAP capture thread ───────────────────────────────────────────────────────

def pcap_capture_thread(siem_url):
    iface = _detect_interface()
    print(f"[*] PCAP capture started on {iface} → forwarding to {siem_url}/api/pcap/ingest")

    slot    = 0
    tmp_dir = tempfile.gettempdir()

    while True:
        pcap_file = os.path.join(tmp_dir, f"sentineliq_cap_{slot % PCAP_SLOT_COUNT}.pcap")
        slot += 1

        try:
            os.remove(pcap_file)
        except FileNotFoundError:
            pass

        try:
            subprocess.run(
                ["tcpdump", "-i", iface,
                 "-G", str(PCAP_WINDOW_SEC), "-W", "1",
                 "-w", pcap_file, "-q"],
                timeout=PCAP_WINDOW_SEC + 5,
                capture_output=True,
            )
        except FileNotFoundError:
            print("[!] tcpdump not found — install with: sudo apt install tcpdump")
            time.sleep(30)
            continue
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"[!] tcpdump error: {e}")
            time.sleep(5)
            continue

        if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) < 25:
            continue

        size_kb = os.path.getsize(pcap_file) // 1024
        ok, detail = forward_pcap(siem_url, pcap_file)
        if ok:
            try:
                resp    = json.loads(detail)
                flows   = resp.get("flows", "?")
                attacks = resp.get("attacks", {})
                print(f"[PCAP>] {size_kb}KB → {flows} flows | attacks={attacks}")
            except Exception:
                print(f"[PCAP>] {size_kb}KB → {detail[:80]}")
        else:
            print(f"[PCAP!] Forward failed: {detail[:80]}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelIQ Linux Log + Packet Forwarder")
    parser.add_argument("--siem",    type=str, default=DEFAULT_SIEM_URL,
                        help="URL of the SentinelIQ SIEM backend")
    parser.add_argument("--no-pcap", action="store_true",
                        help="Disable packet capture (log forwarding only)")
    args = parser.parse_args()

    print("SentinelIQ Forwarder Starting...")
    print(f"Forwarding to {args.siem}")
    if not args.no_pcap:
        print("Packet capture: ENABLED (needs root / tcpdump)")
    print("Press Ctrl+C to stop.\n")

    if check_connectivity(args.siem):
        print("[+] SIEM connectivity check passed.\n")
    else:
        print("[!]\nSIEM not reachable right now — will keep retrying.\n")

    threads = []

    for log_file in LOG_FILES:
        t = threading.Thread(target=tail_file, args=(args.siem, log_file), daemon=True)
        t.start()
        threads.append(t)

    if not args.no_pcap:
        pt = threading.Thread(target=pcap_capture_thread, args=(args.siem,), daemon=True)
        pt.start()
        threads.append(pt)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping forwarder...")
        sys.exit(0)
