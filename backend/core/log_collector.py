"""
SentinelIQ — Log Collection & Parsing Engine (v2 with UA Fingerprinting)
=========================================================================
Now extracts User-Agent, Session tokens, and request fingerprints
from Nginx/Apache logs for session-based attack detection.
"""

import re
import json
from urllib.parse import unquote_plus
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedLogEvent:
    source_type: str
    event_type:  str
    timestamp:   datetime
    src_ip:      str
    dst_ip:      str
    username:    Optional[str]
    message:     str
    raw:         str
    user_agent:  Optional[str] = None   # ← NEW: HTTP User-Agent
    session_id:  Optional[str] = None   # ← NEW: Session/Cookie token
    extra:       dict = field(default_factory=dict)


# ── Linux auth.log ────────────────────────────────────────────
class AuthLogParser:
    _TS = r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?))"
    SSH_FAILED   = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    SSH_ACCEPTED = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"Accepted \S+ for (\S+) from ([\d.]+) port (\d+)"
    )
    ROOT_LOGIN   = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for root from ([\d.]+)"
    )
    SUDO_CMD     = re.compile(
        _TS + r"\s+\S+\s+sudo.*?:\s+(\S+)\s+:.*?COMMAND=(.*)"
    )
    INVALID_USER = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"Invalid user (\S+) from ([\d.]+)"
    )
    MAX_AUTH_EXCEEDED = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"error:\s+maximum authentication attempts exceeded for (?:invalid user )?(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)",
        re.IGNORECASE,
    )
    PREAUTH_CLOSED = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"Connection closed by authenticating user (\S+)\s+([\d.]+)\s+port\s+(\d+)\s+\[preauth\]",
        re.IGNORECASE,
    )
    PREAUTH_INVALID = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"Connection closed by invalid user (\S+)\s+([\d.]+)\s+port\s+(\d+)\s+\[preauth\]",
        re.IGNORECASE,
    )
    PAM_AUTH_FAILURE = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+pam_unix\(sshd:auth\): authentication failure;.*?(?:rhost=([\d.]+))(?=.*?(?:user=|user\s+)(\S+))?",
        re.IGNORECASE,
    )
    PAM_MORE_FAILURES = re.compile(
        _TS + r"\s+\S+\s+sshd\[\d+\]:\s+PAM\s+\d+\s+more authentication failures;.*?rhost=([\d.]+).*?user=(\S+)",
        re.IGNORECASE,
    )
    RHOST = re.compile(r"rhost=([\d.]+)")
    USER = re.compile(r"(?:user=|for\s+)(\S+)", re.IGNORECASE)

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        m = self.ROOT_LOGIN.search(line)
        if m:
            ts, ip = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="auth_root_login",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username="root", message=f"Root login attempt from {ip}", raw=line.strip()
            )
        m = self.MAX_AUTH_EXCEEDED.search(line)
        if m:
            ts, user, ip, port = m.groups()
            event_type = "auth_root_login" if user == "root" else "ssh_failed_login"
            message = "Root login attempt" if user == "root" else f"SSH failed: {user}@{ip}:{port}"
            return ParsedLogEvent(
                source_type="auth", event_type=event_type,
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=message,
                raw=line.strip(), extra={"port": port, "reason": "max_auth_exceeded"}
            )
        m = self.PREAUTH_CLOSED.search(line)
        if m:
            ts, user, ip, port = m.groups()
            event_type = "auth_root_login" if user == "root" else "ssh_failed_login"
            message = "Root login attempt" if user == "root" else f"SSH failed: {user}@{ip}:{port}"
            return ParsedLogEvent(
                source_type="auth", event_type=event_type,
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=message,
                raw=line.strip(), extra={"port": port, "reason": "preauth_closed"}
            )
        m = self.PREAUTH_INVALID.search(line)
        if m:
            ts, user, ip, port = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="ssh_invalid_user",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=f"SSH invalid user {user} from {ip}",
                raw=line.strip(), extra={"port": port, "reason": "preauth_closed"}
            )
        m = self.SSH_FAILED.search(line)
        if m:
            ts, user, ip, port = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="ssh_failed_login",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=f"SSH failed: {user}@{ip}:{port}",
                raw=line.strip(), extra={"port": port}
            )
        m = self.SUDO_CMD.search(line)
        if m:
            ts, user, cmd = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="sudo_privilege_esc",
                timestamp=self._ts(ts), src_ip="127.0.0.1", dst_ip="",
                username=user, message=f"Sudo: {user} → {cmd.strip()}",
                raw=line.strip(), extra={"command": cmd.strip()}
            )
        m = self.INVALID_USER.search(line)
        if m:
            ts, user, ip = m.groups()
            return ParsedLogEvent(
                source_type="auth", event_type="ssh_invalid_user",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=f"SSH invalid user {user} from {ip}",
                raw=line.strip()
            )
        m = self.PAM_AUTH_FAILURE.search(line)
        if m:
            ts, ip, user = m.groups()
            if not ip:
                ip_m = self.RHOST.search(line)
                ip = ip_m.group(1) if ip_m else "0.0.0.0"
            if not user:
                user_m = self.USER.search(line)
                user = user_m.group(1) if user_m else "unknown"
            event_type = "auth_root_login" if user == "root" else "ssh_failed_login"
            message = "Root login attempt" if user == "root" else f"SSH failed: {user}@{ip}"
            return ParsedLogEvent(
                source_type="auth", event_type=event_type,
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=message,
                raw=line.strip(), extra={"reason": "pam_auth_failure"}
            )
        m = self.PAM_MORE_FAILURES.search(line)
        if m:
            ts, ip, user = m.groups()
            event_type = "auth_root_login" if user == "root" else "ssh_failed_login"
            message = "Root login attempt" if user == "root" else f"SSH failed: {user}@{ip}"
            return ParsedLogEvent(
                source_type="auth", event_type=event_type,
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=user, message=message,
                raw=line.strip(), extra={"reason": "pam_more_failures"}
            )
        return None

    def _ts(self, s: str) -> datetime:
        try:
            value = s.strip()
            if "T" in value and value[:4].isdigit():
                if value.endswith("Z"):
                    value = value[:-1] + "+00:00"
                return datetime.fromisoformat(value).replace(tzinfo=None)
            return datetime.strptime(f"{datetime.now().year} {value}", "%Y %b %d %H:%M:%S")
        except Exception:
            return datetime.utcnow()


# ── Nginx / Apache access.log ─────────────────────────────────
class NginxLogParser:
    # Combined Log Format WITH User-Agent and Referer
    # IP - user [date] "METHOD /path HTTP/x.x" status bytes "referer" "user-agent"
    COMBINED = re.compile(
        r'([\d.]+)\s+'          # IP
        r'\S+\s+\S+\s+'         # ident, auth
        r'\[(.+?)\]\s+'         # date
        r'"(\w+)\s+'            # method
        r'([^"]+?)\s+'          # path
        r'HTTP/[\d.]+"\s+'      # protocol
        r'(\d+)\s+'             # status
        r'(\d+|-)'              # bytes
        r'(?:\s+"([^"]*)"\s+"([^"]*)")?'  # optional referer + user-agent
    )

    _SQLI = re.compile(
        r"(union\s+select|order\s+by|drop\s+table|insert\s+into|'--|or\s+1=1"
        r"|xp_cmdshell|exec\s*\(|sleep\s*\(|benchmark\s*\(|"
        r"information_schema|load_file|into\s+outfile)",
        re.IGNORECASE
    )
    _XSS = re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|"
        r"document\.cookie|eval\s*\(|fromCharCode)",
        re.IGNORECASE
    )
    _TRAV = re.compile(
        r"(\.\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self|"
        r"\\.\\.\\|%252e)",
        re.IGNORECASE
    )
    _SCANNER_UA = re.compile(
        r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nuclei|"
        r"burpsuite|havij|acunetix|nessus|openvas|hydra|medusa|"
        r"goldenEye|hulk|slowloris|python-requests/\d+|curl/\d+)",
        re.IGNORECASE
    )

    # Session/Cookie extraction from URL params
    _SESSION_PATTERN = re.compile(
        r"(?:session|sess|sid|token|auth|jwt)=([a-zA-Z0-9_\-\.]+)",
        re.IGNORECASE
    )

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        m = self.COMBINED.match(line.strip())
        if not m:
            return None

        ip, ts, method, path, status, size, referer, user_agent = m.groups()
        code = int(status)
        ua = (user_agent or "").strip()
        referer = (referer or "").strip()
        normalized_path = self._normalize_request_target(path)

        # Extract session ID from URL if present
        session_match = self._SESSION_PATTERN.search(normalized_path)
        session_id = session_match.group(1)[:64] if session_match else None

        # Build extra context
        extra = {
            "method": method,
            "path": path[:200],
            "normalized_path": normalized_path[:200],
            "status": code,
            "bytes": size,
            "referer": referer[:100] if referer else "",
            "user_agent": ua[:200],
            "session_id": session_id,
        }

        def _make_event(event_type: str, msg: str) -> ParsedLogEvent:
            return ParsedLogEvent(
                source_type="nginx",
                event_type=event_type,
                timestamp=self._ts(ts),
                src_ip=ip,
                dst_ip="",
                username=None,
                message=msg,
                raw=line.strip(),
                user_agent=ua or None,
                session_id=session_id,
                extra=extra,
            )

        # Priority 4: Scanner User-Agent (regardless of URL)
        scanner_match = self._SCANNER_UA.search(ua) if ua else None
        if scanner_match and not (
            self._SQLI.search(normalized_path)
            or self._XSS.search(normalized_path)
            or self._TRAV.search(normalized_path)
        ):
            extra["detected_tool"] = scanner_match.group(0)
            return _make_event(
                "nginx_scanner_ua",
                f"Attack tool UA detected: {ua[:80]} from {ip}"
            )

        # Priority 1: SQL Injection in URL
        if self._SQLI.search(normalized_path):
            return _make_event(
                "nginx_sql_injection",
                f"SQLi: {method} {path[:120]} → {code} (UA: {ua[:40]})"
            )

        # Priority 2: XSS in URL
        if self._XSS.search(normalized_path):
            return _make_event(
                "nginx_xss_attempt",
                f"XSS: {method} {path[:120]} → {code}"
            )

        # Priority 3: Path Traversal
        if self._TRAV.search(normalized_path):
            return _make_event(
                "nginx_path_traversal",
                f"Path traversal: {path[:120]}"
            )

        # Priority 5: 4xx error (scanning / probing)
        if 400 <= code < 500:
            return _make_event(
                "nginx_4xx",
                f"HTTP {code}: {method} {path[:100]}"
            )

        # Priority 6: 5xx (server error / possible DoS)
        if code >= 500:
            return _make_event(
                "nginx_5xx",
                f"HTTP {code} server error: {method} {path[:100]}"
            )

        return None  # 2xx/3xx benign

    def _normalize_request_target(self, path: str) -> str:
        normalized = path.strip()
        for _ in range(2):
            decoded = unquote_plus(normalized)
            if decoded == normalized:
                break
            normalized = decoded
        return normalized

    def _ts(self, s: str) -> datetime:
        try:
            return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except Exception:
            return datetime.utcnow()


# ── Windows Event Log ─────────────────────────────────────────
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

    # Ransomware hallmarks detectable in process creation (Event 4688)
    _VSS_PATTERN = re.compile(
        r"(vssadmin\s+delete\s+shadows|vssadmin\.exe.*delete|"
        r"wmic\s+shadowcopy\s+delete|wmic\.exe.*shadowcopy.*delete|"
        r"bcdedit\s+/set.*bootstatuspolicy|bcdedit\.exe.*bootstatuspolicy|"
        r"wbadmin\s+delete\s+catalog|cipher\s+/w:|"
        r"schtasks.*delete.*backup)",
        re.IGNORECASE,
    )

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        try:
            data = json.loads(line)
        except Exception:
            return None
        eid = data.get("EventID")
        if eid not in self.INTERESTING:
            return None

        raw_ip = data.get("IpAddress", data.get("SourceAddress", "127.0.0.1"))
        ip = raw_ip if (raw_ip and raw_ip not in ("-", "")) else "127.0.0.1"
        user = data.get("TargetUserName", data.get("SubjectUserName", "unknown"))

        # Special case: ransomware VSS deletion via process creation
        if eid == 4688:
            cmd = (str(data.get("CommandLine") or "") + " " +
                   str(data.get("NewProcessName") or "")).strip()
            if self._VSS_PATTERN.search(cmd):
                return ParsedLogEvent(
                    source_type="windows", event_type="ransomware_vss_deletion",
                    timestamp=datetime.utcnow(), src_ip=ip, dst_ip="",
                    username=user,
                    message=f"Shadow Copy deletion: {cmd[:120]}",
                    raw=line.strip(),
                    extra={**data, "cmd_line": cmd},
                )

        ev_type, desc = self.INTERESTING[eid]
        return ParsedLogEvent(
            source_type="windows", event_type=ev_type,
            timestamp=datetime.utcnow(), src_ip=ip, dst_ip="",
            username=user, message=f"{desc}: user={user} ip={ip}",
            raw=line.strip(), extra=data
        )


# ── Syslog ────────────────────────────────────────────────────
class SyslogParser:
    PATTERN = re.compile(
        r"<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?: (.*)"
    )
    _IP = re.compile(r"([\d]{1,3}(?:\.[\d]{1,3}){3})")

    # Linux ransomware indicators: backup wipe, mass encryption, ransom note drop
    _RANSOM_LINUX = re.compile(
        r"(lvremove\s+-f|vgremove\s+-f|rm\s+-rf\s+/backup|"
        r"openssl\s+enc.*-e.*-aes|gpg\s+--symmetric|"
        r"find\s+/.*-name.*\.(doc|xls|pdf|jpg).*-exec.*rm|"
        r"DECRYPT.*INSTRUCTIONS|YOUR FILES HAVE BEEN ENCRYPTED|"
        r"\.encrypted\b|\.locked\b|\.ransomed\b)",
        re.IGNORECASE,
    )

    def parse(self, line: str) -> Optional[ParsedLogEvent]:
        m = self.PATTERN.match(line)
        if not m:
            return None
        priority, ts, host, app, msg = m.groups()
        ip_m = self._IP.search(msg)
        ip = ip_m.group(1) if ip_m else "0.0.0.0"

        # Ransomware behaviour takes highest priority
        if self._RANSOM_LINUX.search(msg):
            return ParsedLogEvent(
                source_type="syslog", event_type="ransomware_vss_deletion",
                timestamp=self._ts(ts), src_ip=ip, dst_ip="",
                username=None,
                message=f"Ransomware indicator: {msg.strip()[:120]}",
                raw=line.strip(),
                extra={"host": host, "app": app, "priority": int(priority)},
            )

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


# ── Master dispatcher ─────────────────────────────────────────
class LogParser:
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
        if "sshd" in raw or "sudo" in raw:
            return self._auth.parse(raw)
        if raw.lstrip().startswith("{") and "EventID" in raw:
            return self._windows.parse(raw)
        if re.match(r'[\d.]+ \S+ \S+ \[', raw):
            return self._nginx.parse(raw)
        if re.match(r"<\d+>", raw):
            return self._syslog.parse(raw)
        return None
