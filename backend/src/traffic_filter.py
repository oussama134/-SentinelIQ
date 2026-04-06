# traffic_filter.py - Smart filtering to reduce false positives

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
]

# ============================================================================
# SINGLE is_benign_system_traffic — merged whitelist + port rules
# ============================================================================

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

    # ── 1. CDN / Cloud whitelist ─────────────────────────────
    for prefix in WHITELIST_IP_PREFIXES:
        if src_ip.startswith(prefix) or dst_ip.startswith(prefix):
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
    if dst_ip in BROADCAST_IPS:
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

    # HTTPS with few packets is not DoS
    if dst_port == 443 and packet_count < 20 and 'DoS' in label:
        if score < 0.92:
            return "BENIGN", score * 0.3

    # Router IPs need very high confidence
    if src_ip.endswith('.254') or src_ip.endswith('.1'):
        if score < 0.95:
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


# ============================================================================
# ALERT DECISION
# ============================================================================

def should_generate_alert(label, score, flow_info, min_score=0.85):
    """Returns True if an alert should be generated for this prediction."""
    if label.upper() == "BENIGN":
        return False
    if score < min_score:
        return False
    if ('DoS' in label or 'DDoS' in label) and flow_info.get('packet_count', 0) < 50:
        return False
    if 'PortScan' in label and flow_info.get('packet_count', 0) < 10:
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