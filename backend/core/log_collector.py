"""
SentinelIQ — Log Collection & Parsing Engine
=============================================
Parses raw log lines from multiple source formats into
structured ParsedLogEvent objects that flow through the
SIEM correlation and alerting pipeline.

Supported formats:
  • Linux /var/log/auth.log  (SSH, sudo, su, PAM)
  • Nginx access.log         (Combined Log Format)
  • Generic Syslog           (RFC 3164)
  • Windows Event Log        (JSON from agent)
"""

import re
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class ParsedLogEvent:
    """Normalized log event ready for rule evaluation and DB storage."""
    source_type: str          # "auth" | "nginx" | "syslog" | "windows"
    event_type:  str          # fine-grained type: "ssh_failed_login", etc.
    timestamp:   datetime
    src_ip:      str
    dst_ip:      str
    username:    Optional[str]
    message:     str
    raw:         str
    extra:       dict = field(default_factory=dict)


# ── Linux auth.log ────────────────────────────────────────────────────────────
class AuthLogParser:
    SSH_FAILED   = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    SSH_ACCEPTED = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Accepted \S+ for (\S+) from ([\d.]+) port (\d+)"
    )
    ROOT_LOGIN   = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for root from ([\d.]+)"
    )
    SUDO_CMD     = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo.*?:\s+(\S+)\s+:.*?COMMAND=(.*)"
    )
    INVALID_USER = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Invalid user (\S+) from ([\d.]+)"
    )

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        # Root SSH failure (check before generic SSH — more specific)
        m = self.ROOT_LOGIN.search(line)
        if m:
            ts, ip = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="auth_root_login",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username="root",
                message=f"Root login attempt from {ip}",
                raw=line.strip()
            )

        # Generic SSH failed
        m = self.SSH_FAILED.search(line)
        if m:
            ts, user, ip, port = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="ssh_failed_login",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user,
                message=f"SSH failed: {user}@{ip}:{port}",
                raw=line.strip(), extra={"port": port}
            )

        # Sudo privilege escalation
        m = self.SUDO_CMD.search(line)
        if m:
            ts, user, cmd = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="sudo_privilege_esc",
                timestamp=self._ts(ts), src_ip="127.0.0.1", dst_ip="",
                username=user,
                message=f"Sudo: {user} → {cmd.strip()}",
                raw=line.strip(), extra={"command": cmd.strip()}
            )

        # Invalid user attempt
        m = self.INVALID_USER.search(line)
        if m:
            ts, user, ip = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="ssh_invalid_user",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user,
                message=f"SSH invalid user {user} from {ip}",
                raw=line.strip()
            )
        return None

    def _ts(self, s: str) -> datetime:
        try:
            return datetime.strptime(f"{datetime.now().year} {s.strip()}", "%Y %b %d %H:%M:%S")
        except Exception:
            return datetime.utcnow()


# ── Nginx / Apache access.log ─────────────────────────────────────────────────
class NginxLogParser:
    COMBINED = re.compile(
        r'([\d.]+)\s+\S+\s+\S+\s+\[(.+?)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
    )
    _SQLI = re.compile(
        r"(union\s+select|drop\s+table|insert\s+into|'--|\bor\b\s+1=1"
        r"|xp_cmdshell|exec\s*\(|sleep\s*\(|benchmark\s*\()",
        re.IGNORECASE
    )
    _XSS  = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()", re.IGNORECASE)
    _TRAV = re.compile(r"(\.\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self)", re.IGNORECASE)

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        m = self.COMBINED.match(line)
        if not m:
            return None
        ip, ts, method, path, status, size = m.groups()
        code = int(status)

        if self._SQLI.search(path):
            return ParsedLogEvent(
                source_type="nginx", event_type="nginx_sql_injection",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="", username=None,
                message=f"SQLi: {method} {path[:120]} → {code}",
                raw=line.strip(), extra={"method": method, "path": path, "status": code}
            )
        if self._XSS.search(path):
            return ParsedLogEvent(
                source_type="nginx", event_type="nginx_xss_attempt",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="", username=None,
                message=f"XSS: {method} {path[:120]} → {code}",
                raw=line.strip(), extra={"method": method, "path": path, "status": code}
            )
        if self._TRAV.search(path):
            return ParsedLogEvent(
                source_type="nginx", event_type="nginx_path_traversal",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="", username=None,
                message=f"Path traversal: {path[:120]}",
                raw=line.strip(), extra={"method": method, "path": path, "status": code}
            )
        if 400 <= code < 500:
            return ParsedLogEvent(
                source_type="nginx", event_type="nginx_4xx",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="", username=None,
                message=f"HTTP {code}: {method} {path[:100]}",
                raw=line.strip(), extra={"method": method, "path": path, "status": code}
            )
        if code >= 500:
            return ParsedLogEvent(
                source_type="nginx", event_type="nginx_5xx",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="", username=None,
                message=f"HTTP {code} server error: {method} {path[:100]}",
                raw=line.strip(), extra={"method": method, "path": path, "status": code}
            )
        return None  # 2xx / 3xx benign

    def _ts(self, s: str) -> datetime:
        try:
            return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except Exception:
            return datetime.utcnow()


# ── Windows Event Log (JSON) ──────────────────────────────────────────────────
class WindowsEventParser:
    INTERESTING = {
        4625: ("auth_failed_login",   "Windows login failed"),
        4624: ("auth_success_login",  "Windows login success"),
        4720: ("account_created",     "User account created"),
        4732: ("group_modified",      "Added to privileged group"),
        4648: ("explicit_credential", "Logon with explicit credentials"),
        4688: ("process_created",     "Suspicious process created"),
        7045: ("service_installed",   "New service installed"),
        1102: ("audit_cleared",       "Audit log cleared"),
    }

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        try:
            data = json.loads(line)
        except Exception:
            return None
        eid = data.get("EventID")
        if eid not in self.INTERESTING:
            return None
        ev_type, desc = self.INTERESTING[eid]
        raw_ip = data.get("IpAddress", data.get("SourceAddress", "127.0.0.1"))
        ip = raw_ip if (raw_ip and raw_ip not in ("-", "")) else "127.0.0.1"
        user = data.get("TargetUserName", data.get("SubjectUserName", "unknown"))
        return ParsedLogEvent(
            source_type="windows", event_type=ev_type,
            timestamp=datetime.utcnow(), src_ip=ip, dst_ip="",
            username=user,
            message=f"{desc}: user={user} ip={ip}",
            raw=line.strip(), extra=data
        )


# ── Generic Syslog (RFC 3164) ─────────────────────────────────────────────────
class SyslogParser:
    PATTERN = re.compile(
        r"<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?: (.*)"
    )
    _IP = re.compile(r"([\d]{1,3}(?:\.[\d]{1,3}){3})")

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        m = self.PATTERN.match(line)
        if not m:
            return None
        priority, ts, host, app, msg = m.groups()
        ip_m = self._IP.search(msg)
        ip = ip_m.group(1) if ip_m else "0.0.0.0"
        ev = ("syslog_security_event"
              if re.search(r"(fail|error|denied|invalid|attack|breach)", msg, re.I)
              else "syslog_generic")
        return ParsedLogEvent(
            source_type="syslog", event_type=ev,
            timestamp=self._ts(ts), src_ip=ip, dst_ip="",
            username=None, message=msg.strip(), raw=line.strip(),
            extra={"host": host, "app": app, "priority": int(priority)}
        )

    def _ts(self, s: str) -> datetime:
        try:
            return datetime.strptime(f"{datetime.now().year} {s.strip()}", "%Y %b %d %H:%M:%S")
        except Exception:
            return datetime.utcnow()


# ── Master dispatcher ─────────────────────────────────────────────────────────
class LogParser:
    """
    Auto-detects log format and routes to the correct parser.

    Usage::
        parser = LogParser()
        event = parser.parse(source="linux-auth", raw="Apr 4 ...")
    """

    def __init__(self):
        self._auth    = AuthLogParser()
        self._nginx   = NginxLogParser()
        self._windows = WindowsEventParser()
        self._syslog  = SyslogParser()

        self._map = {
            "linux-auth": self._auth,
            "auth":       self._auth,
            "nginx":      self._nginx,
            "apache":     self._nginx,
            "windows":    self._windows,
            "winevt":     self._windows,
            "syslog":     self._syslog,
        }

    def parse(self, source: str, raw: str) -> Optional[ParsedLogEvent]:
        parser = self._map.get(source.lower().strip())
        if parser:
            return parser.parse(raw)
        return self._auto(raw)

    def _auto(self, raw: str) -> Optional[ParsedLogEvent]:
        if "sshd" in raw or "sudo" in raw or " pam_" in raw.lower():
            return self._auth.parse(raw)
        if raw.lstrip().startswith("{") and "EventID" in raw:
            return self._windows.parse(raw)
        if re.match(r'[\d.]+ \S+ \S+ \[', raw):
            return self._nginx.parse(raw)
        if re.match(r"<\d+>", raw):
            return self._syslog.parse(raw)
        return None
