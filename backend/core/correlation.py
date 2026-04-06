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
    "DoS slowloris":                0.85,   # High threshold = less false positives
    "DoS Slowhttptest":             0.85,
    "DoS Hulk":                     0.82,
    "DoS GoldenEye":                0.82,
    "DDoS":                         0.80,
    "FTP-Patator":                  0.70,
    "SSH-Patator":                  0.70,
    "PortScan":                     0.72,
    "Bot":                          0.75,
    "Heartbleed":                   0.78,
    "Web Attack – Brute Force":     0.68,
    "Web Attack – XSS":             0.68,
    "Web Attack – Sql Injection":   0.75,
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
        count_threshold=5,
        window_seconds=60,
        severity="HIGH",
        description="5+ SSH brute force flows from same IP within 60 seconds",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R002",
        name="FTP Brute Force Detected",
        event_type="ftp_brute_force",
        count_threshold=5,
        window_seconds=60,
        severity="HIGH",
        description="5+ FTP brute force flows from same IP within 60 seconds",
        mitre_technique_id="T1110.001",
    ),
    Rule(
        rule_id="R003",
        name="DoS Attack Detected",
        event_type="dos_hulk",          # Will also match slowloris, goldeneye via prefix
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
        count_threshold=10,
        window_seconds=60,
        severity="MEDIUM",
        description="Port scan — 10+ probe flows in 60 seconds",
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
        event_type="failed_ssh",       # From auth.log
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
        count_threshold=1,              # Alert on first DDoS flow detected
        window_seconds=60,
        severity="CRITICAL",
        description="DDoS traffic detected by ML model",
        mitre_technique_id="T1498",
    ),
]


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
        self.suppressor = AlertSuppressor(cooldown_seconds=30)  # 30s for testing (was 300s)

        # event_type → src_ip → [timestamps]
        self._event_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def process_log(self, log) -> list[TriggeredAlert]:
        """
        Main entry point. Pass a UnifiedLog, get back list of alerts.
        UnifiedLog from ingestion.py
        """
        alerts = []

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