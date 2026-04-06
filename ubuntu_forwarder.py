#!/usr/bin/env python3
"""
SentinelIQ - Ubuntu Log Forwarder Agent
---------------------------------------
Tails /var/log/auth.log and /var/log/apache2/access.log and forwards them in real-time
to the SentinelIQ SIEM backend running on the Windows Host.

Usage on Ubuntu Victim:
  sudo python3 ubuntu_forwarder.py --siem http://192.168.56.1:8000
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error
import threading
import argparse

LOG_FILES = [
    {"path": "/var/log/auth.log", "source": "linux-auth"},
    {"path": "/var/log/apache2/access.log", "source": "apache"}
]

def forward_logs(siem_url, payload):
    url = f"{siem_url}/api/logs/ingest/bulk"
    data = json.dumps({"logs": payload}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'SentinelAgent/1.0'})
    try:
        # Prevent hanging requests with a small timeout
        urllib.request.urlopen(req, timeout=3)
        return True
    except Exception as e:
        print(f"[-] Error forwarding logs: {e}")
        return False

def tail_file(siem_url, log_info):
    path = log_info["path"]
    source = log_info["source"]
    
    if not os.path.exists(path):
        print(f"[*] Waiting for {path} to be created...")
        while not os.path.exists(path):
            time.sleep(5)
    
    print(f"[+] Started monitoring {path} as '{source}'...")
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        # Seek to the end of the file so we only send new logs
        f.seek(0, 2)
        
        buffer = []
        last_send = time.time()
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
            else:
                line = line.strip()
                if line:
                    buffer.append({"source": source, "raw": line})
            
            # Flush buffer every 1 second or if there are 50+ logs waiting
            if buffer and (time.time() - last_send > 1.0 or len(buffer) >= 50):
                success = forward_logs(siem_url, buffer)
                if success:
                    buffer.clear()
                    last_send = time.time()
                else:
                    # In a real environment, you'd keep the buffer to retry later.
                    # Here we clear it to avoid memory leaks if the SIEM is down.
                    buffer.clear()
                    time.sleep(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelIQ Linux Log Forwarder")
    # 192.168.56.1 is usually the VirtualBox Host IP on the Host-Only network
    parser.add_argument("--siem", type=str, default="http://192.168.56.1:8000", help="URL of the SentinelIQ SIEM backend")
    args = parser.parse_args()
    
    print(f"🚀 SentinelIQ Local Forwarder Starting...")
    print(f"📡 Forwarding logs to {args.siem}")
    print("Press Ctrl+C to stop.\n")
    
    threads = []
    for log_file in LOG_FILES:
        t = threading.Thread(target=tail_file, args=(args.siem, log_file), daemon=True)
        t.start()
        threads.append(t)
        
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping forwarder...")
        sys.exit(0)
