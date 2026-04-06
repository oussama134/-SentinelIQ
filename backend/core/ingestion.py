"""
SentinelIQ — Log Ingestion & Normalization
Transforms raw logs from any source into a unified schema.
All sources → NormalizedLog → stored in PostgreSQL
"""
import re
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ============================================================
# UNIFIED LOG SCHEMA
# This is what every log becomes, regardless of source
# ============================================================
@dataclass
class UnifiedLog:
    source: str                         # "NETWORK", "AUTH", "WEB", "HONEYPOT"
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Network identifiers
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # Event info
    event_type: Optional[str] = None    # "failed_login", "port_scan", "http_request"
    username: Optional[str] = None
    message: Optional[str] = None

    # ML prediction (filled after model inference)
    predicted_label: Optional[str] = None
    confidence: Optional[float] = None

    # Any extra fields
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "event_type": self.event_type,
            "username": self.username,
            "message": self.message,
            "predicted_label": self.predicted_label,
            "confidence": self.confidence,
            "extra": self.extra,
        }


# ============================================================
# AUTH LOG PARSER (/var/log/auth.log)
# ============================================================
class AuthLogParser:
    """
    Parses Linux /var/log/auth.log
    Detects: failed SSH, successful SSH, sudo attempts, new user creation
    """

    PATTERNS = {
        "failed_ssh": re.compile(
            r"(\w+\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
        ),
        "success_ssh": re.compile(
            r"(\w+\s+\d+\s+[\d:]+).*Accepted password for (\S+) from ([\d.]+) port (\d+)"
        ),
        "invalid_user": re.compile(
            r"(\w+\s+\d+\s+[\d:]+).*Invalid user (\S+) from ([\d.]+)"
        ),
        "sudo_attempt": re.compile(
            r"(\w+\s+\d+\s+[\d:]+).*sudo:.*(\S+).*COMMAND=(.*)"
        ),
    }

    def parse_line(self, line: str) -> Optional[UnifiedLog]:
        line = line.strip()
        if not line:
            return None

        for event_type, pattern in self.PATTERNS.items():
            match = pattern.search(line)
            if match:
                return self._build_log(event_type, match, line)

        return None

    def _build_log(self, event_type: str, match, raw_line: str) -> UnifiedLog:
        groups = match.groups()
        log = UnifiedLog(source="AUTH", event_type=event_type, message=raw_line)

        if event_type in ("failed_ssh", "success_ssh"):
            log.username = groups[1] if len(groups) > 1 else None
            log.src_ip = groups[2] if len(groups) > 2 else None
            log.src_port = int(groups[3]) if len(groups) > 3 else None
            log.dst_port = 22
            log.protocol = "TCP"

        elif event_type == "invalid_user":
            log.username = groups[1] if len(groups) > 1 else None
            log.src_ip = groups[2] if len(groups) > 2 else None
            log.dst_port = 22

        elif event_type == "sudo_attempt":
            log.username = groups[1] if len(groups) > 1 else None
            log.extra["command"] = groups[2] if len(groups) > 2 else None

        return log

    def parse_file(self, filepath: str) -> list[UnifiedLog]:
        """Parse entire auth.log file"""
        logs = []
        try:
            with open(filepath, "r", errors="ignore") as f:
                for line in f:
                    parsed = self.parse_line(line)
                    if parsed:
                        logs.append(parsed)
        except FileNotFoundError:
            pass
        return logs


# ============================================================
# WEB LOG PARSER (Apache/Nginx access.log)
# ============================================================
class WebLogParser:
    """
    Parses Apache/Nginx access logs (Combined Log Format)
    Detects: SQL injection patterns, XSS attempts, directory traversal
    """

    # Combined Log Format: IP - user [date] "METHOD /path HTTP/1.1" status bytes
    COMBINED_LOG = re.compile(
        r'([\d.]+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) HTTP[^"]*" (\d+) (\d+|-)(?: "([^"]*)" "([^"]*)")?'
    )

    ATTACK_PATTERNS = {
        "sql_injection": re.compile(
            r"(union\s+select|' or '1'='1|--\s*$|;\s*drop\s+table|1=1|sleep\(|benchmark\()",
            re.IGNORECASE
        ),
        "xss": re.compile(
            r"(<script|onerror=|onload=|javascript:|alert\(|<img.*src=x)",
            re.IGNORECASE
        ),
        "path_traversal": re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%252e)",
            re.IGNORECASE
        ),
        "scanner": re.compile(
            r"(sqlmap|nikto|nmap|masscan|dirb|gobuster|nuclei)",
            re.IGNORECASE
        ),
    }

    def parse_line(self, line: str) -> Optional[UnifiedLog]:
        match = self.COMBINED_LOG.match(line.strip())
        if not match:
            return None

        ip, date_str, method, path, status, size, referer, user_agent = match.groups()

        log = UnifiedLog(
            source="WEB",
            src_ip=ip,
            dst_port=80,
            protocol="TCP",
            message=line.strip(),
        )

        log.extra = {
            "method": method,
            "path": path,
            "status_code": int(status),
            "response_size": int(size) if size != "-" else 0,
            "user_agent": user_agent or "",
        }

        # Detect attack patterns in URL
        full_request = f"{path} {user_agent or ''}"
        for attack_type, pattern in self.ATTACK_PATTERNS.items():
            if pattern.search(full_request):
                log.event_type = attack_type
                log.extra["attack_detected"] = attack_type
                break
        else:
            log.event_type = "http_request"

        return log


# ============================================================
# NETWORK FLOW NORMALIZER
# Wraps your existing LSTM output into the unified schema
# ============================================================
class NetworkFlowNormalizer:
    """
    Takes your LSTM model's prediction and flow features
    and turns them into a UnifiedLog
    """

    def normalize(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        predicted_label: str,
        confidence: float,
        flow_features: dict = None
    ) -> UnifiedLog:

        log = UnifiedLog(
            source="NETWORK",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            predicted_label=predicted_label,
            confidence=confidence,
            event_type=self._label_to_event_type(predicted_label),
            extra=flow_features or {}
        )

        return log

    def _label_to_event_type(self, label: str) -> str:
        """Map CICIDS2017 label to a clean event type string"""
        mapping = {
            "BENIGN": "normal_traffic",
            "FTP-Patator": "ftp_brute_force",
            "SSH-Patator": "ssh_brute_force",
            "DoS slowloris": "dos_slowloris",
            "DoS Slowhttptest": "dos_slowhttptest",
            "DoS Hulk": "dos_hulk",
            "DoS GoldenEye": "dos_goldeneye",
            "Heartbleed": "heartbleed_exploit",
            "Web Attack – Brute Force": "web_brute_force",
            "Web Attack – XSS": "web_xss",
            "Web Attack – Sql Injection": "sql_injection",
            "Infiltration": "infiltration",
            "Bot": "botnet_activity",
            "PortScan": "port_scan",
            "DDoS": "ddos",
        }
        return mapping.get(label, label.lower().replace(" ", "_"))


# ============================================================
# INGESTION PIPELINE — ties everything together
# ============================================================
class IngestionPipeline:
    """
    Central pipeline:
    raw log → parser → UnifiedLog → (saved to DB by caller)
    """

    def __init__(self):
        self.auth_parser = AuthLogParser()
        self.web_parser = WebLogParser()
        self.network_normalizer = NetworkFlowNormalizer()

    def process_auth_line(self, line: str) -> Optional[UnifiedLog]:
        return self.auth_parser.parse_line(line)

    def process_web_line(self, line: str) -> Optional[UnifiedLog]:
        return self.web_parser.parse_line(line)

    def process_network_flow(self, **kwargs) -> UnifiedLog:
        return self.network_normalizer.normalize(**kwargs)

    def process_raw(self, source: str, data: dict) -> UnifiedLog:
        """Generic processor for structured input (e.g. from honeypot JSON)"""
        return UnifiedLog(
            source=source,
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            event_type=data.get("event_type"),
            username=data.get("username"),
            message=data.get("message"),
            extra=data.get("extra", {}),
        )


# Global pipeline instance
pipeline = IngestionPipeline()