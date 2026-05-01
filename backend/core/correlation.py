"""
SentinelIQ — Correlation Engine
This is what separates a SIEM from an IDS.
Rules fire alerts. Multiple alerts become incidents.
"""
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from core.mitre import get_mitre_mapping


# ============================================================
# ALERT THRESHOLDS — per-class confidence minimums
# Fixes your false positive problem on DoS classes
# ============================================================
CLASS_THRESHOLDS: dict[str, float] = {
    "BENIGN":                       0.50,
    "DoS slowloris":                0.72,
    "DoS Slowhttptest":             0.72,
    "DoS Hulk":                     0.70,
    "DoS GoldenEye":                0.70,
    "DDoS":                         0.55,

    "FTP-Patator":                  0.72,
    "SSH-Patator":                  0.72,
    "PortScan":                     0.78,
    "Bot":                          0.75,
    "Heartbleed":                   0.82,
    "Web Attack – Brute Force":     0.72,
    "Web Attack – XSS":             0.72,
    "Web Attack – Sql Injection":   0.80,
    "Infiltration":                 0.80,
}


# ============================================================
# CORRELATION RULES
# Each rule has: what to look for, window, threshold, output
# ============================================================
@dataclass
class Rule:
    rule_id: str
    name: str
    event_type: str               # Match on this event_type from UnifiedLog
    count_threshold: int          # How many events needed
    window_seconds: int           # Time window
    severity: str                 # LOW / MEDIUM / HIGH / CRITICAL
    description: str = ""
    mitre_technique_id: str = ""
    group_by: str = "src_ip"      # What field to group counts by


# Rules that mirror exactly what your attack simulator generates
DEFAULT_RULES: list[Rule] = [
    Rule(
        rule_id="R001",
        name="SSH Brute Force Detected",
        event_type="ssh_brute_force",
        count_threshold=1,
        window_seconds=60,
        severity="HIGH",
        description="SSH brute force flows detected from same IP",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R002",
        name="FTP Brute Force Detected",
        event_type="ftp_brute_force",
        count_threshold=1,
        window_seconds=60,
        severity="HIGH",
        description="FTP brute force flows detected from same IP",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R003",
        name="DoS Attack Detected",
        event_type="dos_hulk",          # Also matches dos_slowloris, dos_goldeneye via prefix
        count_threshold=3,
        window_seconds=60,
        severity="CRITICAL",
        description="DoS flood — 3+ flows in 60 seconds from same source",
        mitre_technique_id="T1499.002",
    ),
    Rule(
        rule_id="R004",
        name="Port Scan Detected",
        event_type="port_scan",
        count_threshold=1,
        window_seconds=60,
        severity="MEDIUM",
        description="Port scan detected — rule-based layer already validated 30+ unique ports",
        mitre_technique_id="T1046",
    ),
    Rule(
        rule_id="R005",
        name="Web Brute Force Detected",
        event_type="web_brute_force",
        count_threshold=8,
        window_seconds=120,
        severity="HIGH",
        description="8+ web login attempts in 2 minutes",
        mitre_technique_id="T1110",
    ),
    Rule(
        rule_id="R006",
        name="SQL Injection Attempt",
        event_type="sql_injection",
        count_threshold=1,             # Alert on first occurrence
        window_seconds=1,
        severity="CRITICAL",
        description="SQL injection pattern detected in HTTP request",
        mitre_technique_id="T1190",
    ),
    Rule(
        rule_id="R007",
        name="XSS Attempt Detected",
        event_type="web_xss",
        count_threshold=1,
        window_seconds=1,
        severity="MEDIUM",
        description="Cross-site scripting payload detected",
        mitre_technique_id="T1189",
    ),
    Rule(
        rule_id="R008",
        name="Botnet Activity Detected",
        event_type="botnet_activity",
        count_threshold=3,
        window_seconds=120,
        severity="HIGH",
        description="Repeated botnet/C2 communication patterns",
        mitre_technique_id="T1071.001",
    ),
    Rule(
        rule_id="R009",
        name="Failed SSH Login Spike",
        event_type="ssh_failed_login",  # auth.log via AuthLogParser
        count_threshold=5,
        window_seconds=60,
        severity="HIGH",
        description="5+ SSH login failures in 60 seconds — possible brute force",
        mitre_technique_id="T1110",
    ),
    Rule(
        rule_id="R010",
        name="Heartbleed Exploit Attempt",
        event_type="heartbleed_exploit",
        count_threshold=1,
        window_seconds=1,
        severity="CRITICAL",
        description="OpenSSL Heartbleed exploit attempt detected",
        mitre_technique_id="T1552.004",
    ),
    Rule(
        rule_id="R011",
        name="DDoS Attack Detected",
        event_type="ddos",
        count_threshold=1,
        window_seconds=60,
        severity="CRITICAL",
        description="DDoS traffic detected by ML model",
        mitre_technique_id="T1498",
    ),

    # ── Rules for log_collector.py event types (auth.log forwarded from Ubuntu) ──

    Rule(
        rule_id="R012",
        name="Root Login Attempt",
        event_type="auth_root_login",
        count_threshold=1,          # Fire immediately on first occurrence
        window_seconds=1,
        severity="CRITICAL",
        description="SSH root login attempt detected in auth.log",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R013",
        name="SSH Brute Force (auth.log)",
        event_type="ssh_failed_login",
        count_threshold=3,          # 3 failures in 60s — low for testing
        window_seconds=60,
        severity="HIGH",
        description="3+ SSH login failures in 60 seconds from auth.log",
        mitre_technique_id="T1110",
    ),
    Rule(
        rule_id="R014",
        name="SSH Invalid User Probe",
        event_type="ssh_invalid_user",
        count_threshold=3,
        window_seconds=60,
        severity="MEDIUM",
        description="3+ SSH invalid-user attempts from same IP",
        mitre_technique_id="T1110.001",
    ),

    # ── Rules for log_collector.py NginxLogParser event types ──

    Rule(
        rule_id="R015",
        name="SQL Injection (Nginx log)",
        event_type="nginx_sql_injection",
        count_threshold=1,
        window_seconds=1,
        severity="CRITICAL",
        description="SQL injection pattern detected in Nginx access log",
        mitre_technique_id="T1190",
    ),
    Rule(
        rule_id="R016",
        name="XSS Attempt (Nginx log)",
        event_type="nginx_xss_attempt",
        count_threshold=1,
        window_seconds=1,
        severity="HIGH",
        description="XSS payload detected in Nginx access log",
        mitre_technique_id="T1189",
    ),
    Rule(
        rule_id="R017",
        name="Web Scanner Detected",
        event_type="nginx_scanner_ua",
        count_threshold=1,
        window_seconds=1,
        severity="HIGH",
        description="Attack tool User-Agent detected (sqlmap, nikto, hydra…)",
        mitre_technique_id="T1046",
    ),
    Rule(
        rule_id="R018",
        name="Web Scanning / Probing",
        event_type="nginx_4xx",
        count_threshold=15,
        window_seconds=30,
        severity="MEDIUM",
        description="15+ HTTP 4xx errors in 30 seconds — directory/path probing",
        mitre_technique_id="T1046",
    ),

    # ── Rules for syslog and new nginx event types ──

    Rule(
        rule_id="R019",
        name="Path Traversal Attempt",
        event_type="nginx_path_traversal",
        count_threshold=1,
        window_seconds=1,
        severity="HIGH",
        description="Directory traversal pattern detected in HTTP request (../etc/passwd, %2e%2e…)",
        mitre_technique_id="T1083",
    ),
    Rule(
        rule_id="R020",
        name="Privilege Escalation via Sudo",
        event_type="sudo_privilege_esc",
        count_threshold=1,
        window_seconds=1,
        severity="HIGH",
        description="Sudo command executed — possible privilege escalation",
        mitre_technique_id="T1548.003",
    ),
    Rule(
        rule_id="R021",
        name="System Security Event (syslog)",
        event_type="syslog_security_event",
        count_threshold=3,
        window_seconds=60,
        severity="MEDIUM",
        description="3+ syslog security events in 60 seconds (UFW blocks, service failures, denied access)",
        mitre_technique_id="T1562",
    ),

    # ── LOW severity — early-warning reconnaissance indicators ──────────────────
    # These fire before thresholds for higher-severity rules are crossed,
    # giving analysts an early signal that an attack chain may be starting.

    Rule(
        rule_id="R025",
        name="First SSH Login Failure",
        event_type="ssh_failed_login",
        count_threshold=1,
        window_seconds=1,
        severity="LOW",
        description="First SSH authentication failure from this IP — possible brute force starting",
        mitre_technique_id="T1110",
    ),
    Rule(
        rule_id="R026",
        name="First Invalid SSH Username",
        event_type="ssh_invalid_user",
        count_threshold=1,
        window_seconds=1,
        severity="LOW",
        description="SSH attempt with non-existent username — possible user enumeration",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R027",
        name="Low-Rate HTTP Probing",
        event_type="nginx_4xx",
        count_threshold=3,
        window_seconds=60,
        severity="LOW",
        description="3–14 HTTP 4xx errors in 60 seconds — low-rate web directory probing",
        mitre_technique_id="T1046",
    ),
    Rule(
        rule_id="R028",
        name="Single FTP Login Failure",
        event_type="ftp_brute_force",
        count_threshold=1,
        window_seconds=1,
        severity="LOW",
        description="Single FTP authentication failure — may indicate credential testing",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R029",
        name="Suspicious Syslog Event",
        event_type="syslog_security_event",
        count_threshold=1,
        window_seconds=1,
        severity="LOW",
        description="Single syslog security event — UFW block, auth denial, or service failure",
        mitre_technique_id="T1562",
    ),

    # ── KILL SWITCH trigger rules ────────────────────────────────────────────────
    # These two rules arm the kill switch. Any alert they generate with
    # severity=CRITICAL will be intercepted in main.py and the kill switch
    # will execute the configured action against the remote victim.

    Rule(
        rule_id="R030",
        name="Ransomware — Shadow Copy / Backup Deletion",
        event_type="ransomware_vss_deletion",
        count_threshold=1,
        window_seconds=1,
        severity="CRITICAL",
        description=(
            "Volume Shadow Copy or backup deletion detected — hallmark pre-encryption step. "
            "KILL SWITCH ARMED (T1490)"
        ),
        mitre_technique_id="T1490",
    ),
    Rule(
        rule_id="R031",
        name="Ransomware — Mass File Encryption",
        event_type="ransomware_mass_encryption",
        count_threshold=1,
        window_seconds=1,
        severity="CRITICAL",
        description=(
            "Mass file encryption activity detected. "
            "KILL SWITCH ARMED (T1486)"
        ),
        mitre_technique_id="T1486",
    ),
]

# Rules that arm the kill switch — checked by main.py
KILL_SWITCH_RULE_IDS = {"R030", "R031"}


# ============================================================
# TRIGGERED ALERT (in-memory, before saving to DB)
# ============================================================
@dataclass
class TriggeredAlert:
    rule: Rule
    src_ip: str
    attack_type: str
    confidence: float
    count: int                     # How many events triggered this
    timestamp: datetime = field(default_factory=datetime.utcnow)
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    extra: dict = field(default_factory=dict)

    @property
    def title(self) -> str:
        return f"{self.rule.name} from {self.src_ip}"

    @property
    def description(self) -> str:
        return (
            f"{self.rule.description} | "
            f"Detected {self.count} events | "
            f"Confidence: {self.confidence:.0%}"
        )


# ============================================================
# ALERT SUPPRESSOR
# Prevents alert storms from the same source
# ============================================================
class AlertSuppressor:
    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown = cooldown_seconds
        self._last_alert: dict[str, float] = {}   # "src_ip:rule_id" → timestamp

    def should_suppress(self, src_ip: str, rule_id: str) -> bool:
        key = f"{src_ip}:{rule_id}"
        last = self._last_alert.get(key, 0)
        if time.time() - last < self.cooldown:
            return True     # Suppress — too soon
        return False

    def mark_alerted(self, src_ip: str, rule_id: str):
        key = f"{src_ip}:{rule_id}"
        self._last_alert[key] = time.time()

    def clear_expired(self):
        """Clean up old entries"""
        now = time.time()
        self._last_alert = {
            k: v for k, v in self._last_alert.items()
            if now - v < self.cooldown * 2
        }


# ============================================================
# CORRELATION ENGINE
# ============================================================
class CorrelationEngine:
    """
    Core engine — processes every normalized log:
    1. Checks ML confidence threshold
    2. Counts events per IP per time window
    3. Fires rule when threshold crossed
    4. Suppresses duplicate alerts
    """

    def __init__(self, rules: list[Rule] = None):
        self.rules = {r.rule_id: r for r in (rules or DEFAULT_RULES)}
        self.suppressor = AlertSuppressor(cooldown_seconds=60)

        # event_type → src_ip → [timestamps]
        self._event_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._call_count: int = 0

    def process_log(self, log) -> list[TriggeredAlert]:
        """
        Main entry point. Pass a UnifiedLog, get back list of alerts.
        UnifiedLog from ingestion.py
        """
        alerts = []

        # Periodic cleanup: remove stale IPs from sliding-window counters
        self._call_count += 1
        if self._call_count % 1000 == 0:
            self._purge_expired()

        # Step 1: Check ML confidence threshold
        if log.predicted_label and log.confidence:
            threshold = CLASS_THRESHOLDS.get(log.predicted_label, 0.60)
            if log.confidence < threshold:
                return []  # Not confident enough → treat as benign

        # Step 2: Determine event type to match rules
        event_type = log.event_type or ""
        if not event_type:
            return []

        # Step 3: Update counters for this event type + source IP
        src_ip = log.src_ip or "unknown"
        now = time.time()
        self._event_counts[event_type][src_ip].append(now)

        # Step 4: Check all matching rules
        for rule in self.rules.values():
            if not self._matches_rule(event_type, rule):
                continue

            # Keep only events within the time window
            window_start = now - rule.window_seconds
            recent = [
                t for t in self._event_counts[event_type][src_ip]
                if t >= window_start
            ]
            self._event_counts[event_type][src_ip] = recent

            # Fire alert if threshold crossed
            if len(recent) >= rule.count_threshold:
                # Check suppression
                if self.suppressor.should_suppress(src_ip, rule.rule_id):
                    continue

                mitre = get_mitre_mapping(log.predicted_label or event_type)

                alert = TriggeredAlert(
                    rule=rule,
                    src_ip=src_ip,
                    attack_type=log.predicted_label or event_type,
                    confidence=log.confidence or 1.0,
                    count=len(recent),
                    mitre_tactic=mitre.tactic,
                    mitre_technique_id=mitre.technique_id,
                    mitre_technique_name=mitre.technique_name,
                    dst_ip=log.dst_ip,
                    dst_port=log.dst_port,
                    extra=log.extra,
                )

                alerts.append(alert)
                self.suppressor.mark_alerted(src_ip, rule.rule_id)

        return alerts

    def _matches_rule(self, event_type: str, rule: Rule) -> bool:
        """Check if the event type matches the rule — supports prefix matching"""
        if event_type == rule.event_type:
            return True
        # Allow rules to match families of events (e.g. "dos_" matches all DoS)
        if rule.event_type.endswith("_") and event_type.startswith(rule.event_type):
            return True
        # DoS rule matches all dos_* events
        if rule.event_type == "dos_hulk" and event_type.startswith("dos_"):
            return True
        return False

    def _purge_expired(self):
        """Remove IPs whose entire timestamp list has aged out of every rule window."""
        if not self.rules:
            return
        max_window = max(r.window_seconds for r in self.rules.values())
        cutoff = time.time() - max_window
        for event_type in list(self._event_counts.keys()):
            ip_dict = self._event_counts[event_type]
            for src_ip in list(ip_dict.keys()):
                ip_dict[src_ip] = [t for t in ip_dict[src_ip] if t >= cutoff]
                if not ip_dict[src_ip]:
                    del ip_dict[src_ip]
            if not ip_dict:
                del self._event_counts[event_type]

    def get_stats(self) -> dict:
        """Return current engine statistics"""
        total_tracked = sum(
            len(ips) for ips in self._event_counts.values()
        )
        return {
            "rules_loaded": len(self.rules),
            "event_types_tracked": len(self._event_counts),
            "source_ips_tracked": total_tracked,
        }


# Global engine instance
engine = CorrelationEngine()
