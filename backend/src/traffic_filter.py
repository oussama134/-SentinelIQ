"""
Traffic filtering and active defense helpers for SentinelIQ.

This module suppresses routine network noise, post-processes model output,
and exposes helper logic that keeps alerts focused on actionable threats.
"""

# ============================================================================
# WHITELIST CONFIGURATION
# ============================================================================

BENIGN_PORTS = {
    53,           # DNS
    67, 68,       # DHCP
    137, 138, 139,# NetBIOS
    5353,         # mDNS
    123,          # NTP
    1900,         # SSDP
    5355,         # LLMNR
}

BENIGN_IPS = {
    '192.168.1.1',
    '192.168.1.254',
    '192.168.0.1',
    '10.0.0.1',
    '127.0.0.1',
}

MULTICAST_RANGES = ['224.', '239.', 'ff02:']

BROADCAST_IPS = ['255.255.255.255', '192.168.1.255', '0.0.0.0']

# CDN / Cloud providers — these cause DDoS false positives
WHITELIST_IP_PREFIXES = [
    "157.240.",   # Facebook/Meta
    "140.82.",    # GitHub
    "142.251.",   # Google
    "172.217.",   # Google
    "142.250.",   # Google
    "150.171.",   # Microsoft
    "13.107.",    # Microsoft
    "18.97.",     # Amazon AWS
    "104.18.",    # Cloudflare
    "104.20.",    # Cloudflare
    "162.159.",   # Cloudflare
    "172.67.",    # Cloudflare
    "146.75.",    # Fastly
    "151.101.",   # Fastly
    # --- NOISE FILTER ---
    # "192.168.1.", # Real Physical Local Wi-Fi network (Home Router / PC) - DISABLED FOR TESTING
]

DYNAMIC_WHITELIST = set()

# IPs that are benign only when they are the SOURCE (server's own outbound traffic in cloud/VM setups).
# When the same prefix appears as the DESTINATION it is NOT skipped — inbound attacks are still detected.
SRC_ONLY_SKIP_PREFIXES = [
    "10.0.",       # OCI / generic cloud private VNICs — server's own egress connections
    "169.254.",    # Link-local: OCI instance metadata service, APIPA
]

def _ip_matches_entry(ip: str, entry: str) -> bool:
    """Exact-match host IPs; only treat entries as prefixes when explicit."""
    if not ip or not entry:
        return False

    candidate = entry.strip()
    if not candidate:
        return False

    if candidate.endswith('.'):
        return ip.startswith(candidate)

    if '/' in candidate:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            return False

    return ip == candidate

def update_trusted_ips_cache(ips):
    global DYNAMIC_WHITELIST
    DYNAMIC_WHITELIST.clear()
    for ip in ips:
        if ip:
            clean_ip = ip.strip()
            DYNAMIC_WHITELIST.add(clean_ip)
    print(f"[*] Memory Whitelist Synced: {list(DYNAMIC_WHITELIST)}")

# ============================================================================
# ACTIVE DEFENSE: DYNAMIC BAN LIST (IPs & USER-AGENTS)
def is_benign_system_traffic(flow_info: dict) -> bool:
    """
    Returns True if the flow should be SKIPPED (not analyzed).
    Combines CDN whitelist + port-based rules.
    """
    src_ip   = flow_info.get('src_ip', '')
    dst_ip   = flow_info.get('dst_ip', '')
    src_port = flow_info.get('src_port', 0)
    dst_port = flow_info.get('dst_port', 0)
    protocol = flow_info.get('protocol', '').upper()

    # ── 1. Check known CDN/DNS/Service subnets + DYNAMIC DB IPS
    for pfx in WHITELIST_IP_PREFIXES:
        if _ip_matches_entry(src_ip, pfx) or _ip_matches_entry(dst_ip, pfx):
            return True

    for pfx in DYNAMIC_WHITELIST:
        if _ip_matches_entry(src_ip, pfx) or _ip_matches_entry(dst_ip, pfx):
            return True

    # ── 1b. Source-only skip: cloud/VM server outbound traffic
    # Skip when the SERVER's own private IP is the source (normal egress).
    # Do NOT skip when it's the destination — inbound attacks must still fire.
    for pfx in SRC_ONLY_SKIP_PREFIXES:
        if _ip_matches_entry(src_ip, pfx):
            return True

    # ── 2. DNS traffic ───────────────────────────────────────
    if src_port == 53 or dst_port == 53:
        return True

    # ── 3. DHCP ─────────────────────────────────────────────
    if src_port in (67, 68) or dst_port in (67, 68):
        return True

    # ── 4. Other benign ports ────────────────────────────────
    if src_port in BENIGN_PORTS or dst_port in BENIGN_PORTS:
        return True

    # ── 5. Multicast ─────────────────────────────────────────
    for prefix in MULTICAST_RANGES:
        if dst_ip.startswith(prefix):
            return True

    # ── 6. Broadcast ─────────────────────────────────────────
    # Covers 255.255.255.255, any subnet broadcast (*.255), and explicit list
    if dst_ip in BROADCAST_IPS or dst_ip.endswith('.255'):
        return True

    # ── 7. Known benign IPs (routers) ────────────────────────
    if src_ip in BENIGN_IPS or dst_ip in BENIGN_IPS:
        if dst_port not in (80, 443, 8080, 8443):
            return True

    # ── 8. Loopback ──────────────────────────────────────────
    if src_ip == '127.0.0.1' and dst_ip == '127.0.0.1':
        return True

    return False   # ← analyze this flow


# ============================================================================
# POST-PROCESS PREDICTION
# ============================================================================

def post_process_prediction(label, score, flow_info):
    """Apply business rules AFTER prediction to fix obvious errors."""
    protocol    = flow_info.get('protocol', '').upper()
    src_port    = flow_info.get('src_port', 0)
    dst_port    = flow_info.get('dst_port', 0)
    packet_count= flow_info.get('packet_count', 0)
    src_ip      = flow_info.get('src_ip', '')

    # UDP cannot be a slow-HTTP attack
    if protocol == 'UDP' and 'Slowhttp' in label:
        return "BENIGN", 0.05

    # DNS port is never a DoS target
    if (src_port == 53 or dst_port == 53) and ('DoS' in label or 'Slow' in label):
        return "BENIGN", 0.05

    # HTTPS with very few packets is probably not DoS (but keep a low bar)
    if dst_port == 443 and packet_count < 5 and 'DoS' in label:
        if score < 0.85:
            return "BENIGN", score * 0.3

    # Short web-port flows look like DoS/Bot to the ML model but are really
    # directory brute-force (Gobuster, DirBuster, ffuf). Each connection is a
    # tiny HTTP GET (< 15 packets). Real HTTP DoS flows are much longer.
    # The nginx log path (R017 scanner UA, R018 4xx) will fire the correct alert.
    if dst_port in (80, 443, 8080, 8443) and packet_count < 15:
        if 'DoS' in label or 'DDoS' in label or label == 'Bot':
            return "BENIGN", score * 0.15

    # Router IPs need very high confidence for noisy traffic but NOT for DDoS
    # Router IPs need very high confidence for noisy traffic
    if src_ip.endswith('.254') or src_ip.endswith('.1'):
        # For DoS/DDoS from router, we need extreme confidence to avoid false positives from gateway maintenance
        if 'DoS' in label or 'DDoS' in label:
            if score < 0.98:
                return "BENIGN", score * 0.1
        elif score < 0.95:
            return "BENIGN", score * 0.5

    # FTP brute force must target port 21
    if 'FTP-Patator' in label and dst_port != 21:
        return "BENIGN", score * 0.3

    # SSH brute force must target port 22
    if 'SSH-Patator' in label and dst_port != 22:
        return "BENIGN", score * 0.3

    # Web attacks must target web ports
    if 'Web Attack' in label and dst_port not in (80, 443, 8080, 8443):
        return "BENIGN", score * 0.2

    # PortScan needs high confidence
    if 'PortScan' in label and score < 0.90:
        return "BENIGN", score * 0.4

    # Heartbleed must target SSL port
    if 'Heartbleed' in label and dst_port not in (443, 444, 8443):
        return "BENIGN", score * 0.1

    return label, score


def should_generate_alert(label, score, flow_info, min_score=0.85):
    """Returns True if an alert should be generated for this prediction."""
    if label.upper() == "BENIGN":
        return False
    if score < min_score:
        return False
        
    packet_count = flow_info.get('packet_count', 0)
    
    # Require at least 3 packets for heavy attacks to filter single-packet glitches
    if ('DoS' in label or 'DDoS' in label) and packet_count < 3:
        return False
        
    # Require at least 2 packets for PortScan to avoid single SYN spikes
    if 'PortScan' in label and packet_count < 2:
        return False
        
    return True


# ============================================================================
# STATISTICS
# ============================================================================

class TrafficStats:
    def __init__(self):
        self.total_flows = 0
        self.filtered_flows = 0
        self.analyzed_flows = 0
        self.alerts_generated = 0
        self.false_positives_prevented = 0

    def record_flow(self, filtered=False):
        self.total_flows += 1
        if filtered:
            self.filtered_flows += 1
        else:
            self.analyzed_flows += 1

    def record_alert(self):
        self.alerts_generated += 1

    def record_false_positive_prevented(self):
        self.false_positives_prevented += 1

    def get_summary(self):
        return {
            'total_flows': self.total_flows,
            'filtered_flows': self.filtered_flows,
            'analyzed_flows': self.analyzed_flows,
            'alerts_generated': self.alerts_generated,
            'false_positives_prevented': self.false_positives_prevented,
            'filter_rate': f"{(self.filtered_flows / max(self.total_flows, 1)) * 100:.1f}%"
        }

    def reset(self):
        self.__init__()
