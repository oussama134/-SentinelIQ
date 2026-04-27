import time
import random
from scapy.all import IP, TCP, send, Raw

# ── Configuration ───────────────────────────────────────────
TARGET_IP = "8.8.8.8" 

ATTACKS = [
    {
        "name": "DDoS (Spoofed TCP Flood)",
        "fake_src": "10.10.10.99",
        "type": "TCP SYN Flood",
        "proto": "TCP",
        "dport": 80,
        "count": 100
    },
    {
        "name": "PortScan (Spoofed)",
        "fake_src": "172.16.0.50",
        "type": "TCP SYN Sweep",
        "proto": "TCP",
        "dport": range(1, 101),
        "count": 100
    },
    {
        "name": "SSH Brute (Spoofed)",
        "fake_src": "192.168.1.222",
        "type": "TCP Connect to 22",
        "proto": "TCP",
        "dport": 22,
        "count": 40
    }
]

def run_spoofed_attacks():
    print(f"[*] Starting Multi-IP Attack Simulation (Refined for AI)...")
    print("-" * 50)

    for attack in ATTACKS:
        print(f"[!] Launching {attack['name']} from IP: {attack['fake_src']}")
        
        for i in range(attack['count']):
            sport = random.randint(1024, 65535)
            dport = attack['dport']
            if isinstance(dport, range):
                dport = dport[i % len(dport)]

            # Use TCP SYN for all to maintain consistency in detection
            pkt = IP(src=attack['fake_src'], dst=TARGET_IP)/TCP(sport=sport, dport=dport, flags="S")
            
            # Send 8 packets per flow to ensure "sustained" look for AI
            send(pkt, count=8, verbose=False)
            
            # Tiny sleep to ensure flow extractor sees them as individual events
            time.sleep(0.01)
            
        print(f"✅ {attack['name']} complete.\n")
        time.sleep(2) # Pause between different attacks to avoid cross-IP confusion

    print("-" * 50)
    print("[*] Simulation finished. Check your SentinelIQ Dashboard!")

if __name__ == "__main__":
    run_spoofed_attacks()
