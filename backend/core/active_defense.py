"""
SentinelIQ active defense engine.

Keeps in-memory bans with TTLs and supports optional callbacks so other
enforcement layers can react to ban/unban events, such as:
- host firewall rules
- remote victim firewall rules
- reverse proxy blocklists
"""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional


@dataclass
class BanEntry:
    identifier: str
    ban_type: str  # "IP" | "USER_AGENT" | "SESSION"
    reason: str
    attack_type: str
    banned_at: float = field(default_factory=time.time)
    ttl_seconds: int = 600
    hit_count: int = 0

    @property
    def expires_at(self) -> float:
        return self.banned_at + self.ttl_seconds

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def time_remaining(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "ban_type": self.ban_type,
            "reason": self.reason,
            "attack_type": self.attack_type,
            "banned_at": datetime.fromtimestamp(self.banned_at).isoformat(),
            "expires_at": datetime.fromtimestamp(self.expires_at).isoformat(),
            "time_remaining_seconds": self.time_remaining,
            "hit_count": self.hit_count,
        }


@dataclass
class RateLimitEntry:
    identifier: str
    timestamps: list = field(default_factory=list)

    def add(self, now: float = None):
        self.timestamps.append(now or time.time())

    def count_in_window(self, window_seconds: int, now: float = None) -> int:
        current = now or time.time()
        cutoff = current - window_seconds
        self.timestamps = [t for t in self.timestamps if t >= cutoff]
        return len(self.timestamps)


class ActiveDefense:
    RATE_LIMITS = {
        "http_requests": {"window": 30, "limit": 150, "ban_ttl": 600},
        "ua_requests": {"window": 60, "limit": 200, "ban_ttl": 600},
        "login_attempts": {"window": 60, "limit": 10, "ban_ttl": 1800},
    }

    SUSPICIOUS_UA_PATTERNS = [
        "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
        "gobuster", "nuclei", "burpsuite", "havij", "acunetix",
        "nessus", "openvas", "metasploit", "hydra", "medusa",
        "goldeneye", "hulk", "slowloris", "python-requests", "python-urllib",
    ]

    def __init__(self, default_ban_ttl: int = 600):
        self._default_ttl = default_ban_ttl
        self._lock = threading.RLock()

        self._ip_bans: dict[str, BanEntry] = {}
        self._ua_bans: dict[str, BanEntry] = {}

        self._ip_rates: dict[str, RateLimitEntry] = defaultdict(lambda: RateLimitEntry(""))
        self._ua_rates: dict[str, RateLimitEntry] = defaultdict(lambda: RateLimitEntry(""))

        self._ip_ban_callbacks: list[Callable[[BanEntry], None]] = []
        self._ip_unban_callbacks: list[Callable[[BanEntry], None]] = []

        self.total_bans_issued = 0
        self.total_requests_blocked = 0

        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def register_ip_ban_callback(self, callback: Callable[[BanEntry], None]):
        with self._lock:
            self._ip_ban_callbacks.append(callback)

    def register_ip_unban_callback(self, callback: Callable[[BanEntry], None]):
        with self._lock:
            self._ip_unban_callbacks.append(callback)

    def _dispatch_callbacks(self, callbacks: list[Callable[[BanEntry], None]], entry: BanEntry):
        for callback in callbacks:
            def _runner(cb=callback, ban_entry=entry):
                try:
                    cb(ban_entry)
                except Exception as e:
                    print(f"[!] Active defense callback failed for {ban_entry.identifier}: {e}")
            threading.Thread(target=_runner, daemon=True).start()

    def ban_ip(self, ip: str, reason: str, attack_type: str, ttl: int = None) -> BanEntry:
        with self._lock:
            entry = BanEntry(
                identifier=ip,
                ban_type="IP",
                reason=reason,
                attack_type=attack_type,
                ttl_seconds=ttl or self._default_ttl,
            )
            self._ip_bans[ip] = entry
            self.total_bans_issued += 1
            callbacks = list(self._ip_ban_callbacks)
        print(f"[ACTIVE DEFENSE] IP BANNED: {ip} | {reason} | TTL={entry.ttl_seconds}s")
        self._dispatch_callbacks(callbacks, entry)
        return entry

    def ban_user_agent(self, ua: str, reason: str, attack_type: str, ttl: int = None) -> BanEntry:
        ua_key = ua.strip().lower()[:200]
        with self._lock:
            entry = BanEntry(
                identifier=ua_key,
                ban_type="USER_AGENT",
                reason=reason,
                attack_type=attack_type,
                ttl_seconds=ttl or self._default_ttl,
            )
            self._ua_bans[ua_key] = entry
            self.total_bans_issued += 1
        print(f"[ACTIVE DEFENSE] UA BANNED: {ua_key[:60]}... | {reason}")
        return entry

    def unban_ip(self, ip: str) -> bool:
        with self._lock:
            entry = self._ip_bans.pop(ip, None)
            callbacks = list(self._ip_unban_callbacks)
        if not entry:
            return False
        print(f"[ACTIVE DEFENSE] IP UNBANNED: {ip}")
        self._dispatch_callbacks(callbacks, entry)
        return True

    def is_ip_banned(self, ip: str) -> Optional[BanEntry]:
        with self._lock:
            entry = self._ip_bans.get(ip)
            if not entry:
                return None
            if entry.is_expired:
                del self._ip_bans[ip]
                callbacks = list(self._ip_unban_callbacks)
            else:
                entry.hit_count += 1
                self.total_requests_blocked += 1
                return entry
        self._dispatch_callbacks(callbacks, entry)
        return None

    def is_ua_banned(self, user_agent: str) -> Optional[BanEntry]:
        if not user_agent:
            return None
        ua_key = user_agent.strip().lower()[:200]
        with self._lock:
            entry = self._ua_bans.get(ua_key)
            if not entry:
                return None
            if entry.is_expired:
                del self._ua_bans[ua_key]
                return None
            entry.hit_count += 1
            self.total_requests_blocked += 1
            return entry

    def is_suspicious_ua(self, user_agent: str) -> bool:
        if not user_agent:
            return False
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in self.SUSPICIOUS_UA_PATTERNS)

    def check_and_block(self, ip: str, user_agent: str = None) -> tuple[bool, str]:
        ip_ban = self.is_ip_banned(ip)
        if ip_ban:
            return True, f"IP banned: {ip_ban.reason} ({ip_ban.time_remaining}s remaining)"

        if user_agent:
            ua_ban = self.is_ua_banned(user_agent)
            if ua_ban:
                return True, f"User-Agent banned: {ua_ban.reason} ({ua_ban.time_remaining}s remaining)"
            if self.is_suspicious_ua(user_agent):
                self.ban_user_agent(
                    user_agent,
                    reason="Suspicious attack tool User-Agent detected",
                    attack_type="Web Scanner",
                    ttl=300,
                )
                return True, f"Suspicious User-Agent auto-banned: {user_agent[:60]}"

        return False, ""

    def record_http_request(self, ip: str, user_agent: str = None) -> Optional[str]:
        now = time.time()
        with self._lock:
            self._ip_rates[ip].add(now)
            ip_count = self._ip_rates[ip].count_in_window(self.RATE_LIMITS["http_requests"]["window"], now)
            if ip_count >= self.RATE_LIMITS["http_requests"]["limit"] and ip not in self._ip_bans:
                self.ban_ip(
                    ip,
                    reason=f"HTTP rate limit: {ip_count} requests in {self.RATE_LIMITS['http_requests']['window']}s",
                    attack_type="DoS",
                    ttl=self.RATE_LIMITS["http_requests"]["ban_ttl"],
                )
                return f"IP {ip} auto-banned: HTTP flood"

            if user_agent:
                ua_key = user_agent.strip().lower()[:200]
                self._ua_rates[ua_key].add(now)
                ua_count = self._ua_rates[ua_key].count_in_window(self.RATE_LIMITS["ua_requests"]["window"], now)
                if ua_count >= self.RATE_LIMITS["ua_requests"]["limit"] and ua_key not in self._ua_bans:
                    self.ban_user_agent(
                        user_agent,
                        reason=f"UA rate limit: {ua_count} req in {self.RATE_LIMITS['ua_requests']['window']}s",
                        attack_type="DoS",
                        ttl=self.RATE_LIMITS["ua_requests"]["ban_ttl"],
                    )
                    return "User-Agent auto-banned: HTTP flood regardless of IP"
        return None

    def record_login_attempt(self, ip: str) -> Optional[str]:
        now = time.time()
        key = f"login:{ip}"
        with self._lock:
            self._ip_rates[key].add(now)
            count = self._ip_rates[key].count_in_window(self.RATE_LIMITS["login_attempts"]["window"], now)
            if count >= self.RATE_LIMITS["login_attempts"]["limit"] and ip not in self._ip_bans:
                self.ban_ip(
                    ip,
                    reason=f"Login brute force: {count} attempts in {self.RATE_LIMITS['login_attempts']['window']}s",
                    attack_type="SSH-Patator",
                    ttl=self.RATE_LIMITS["login_attempts"]["ban_ttl"],
                )
                return f"IP {ip} auto-banned: login brute force"
        return None

    def get_active_bans(self) -> list[dict]:
        with self._lock:
            active = []
            for entry in self._ip_bans.values():
                if not entry.is_expired:
                    active.append(entry.to_dict())
            for entry in self._ua_bans.values():
                if not entry.is_expired:
                    active.append(entry.to_dict())
        return sorted(active, key=lambda x: x["banned_at"], reverse=True)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "active_ip_bans": sum(1 for e in self._ip_bans.values() if not e.is_expired),
                "active_ua_bans": sum(1 for e in self._ua_bans.values() if not e.is_expired),
                "total_bans_issued": self.total_bans_issued,
                "total_requests_blocked": self.total_requests_blocked,
            }

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            with self._lock:
                expired_ips = [(ip, entry) for ip, entry in self._ip_bans.items() if entry.is_expired]
                expired_uas = [ua for ua, entry in self._ua_bans.items() if entry.is_expired]
                ip_unban_callbacks = list(self._ip_unban_callbacks)

                for ip, _ in expired_ips:
                    del self._ip_bans[ip]
                for ua in expired_uas:
                    del self._ua_bans[ua]

                for key in list(self._ip_rates.keys()):
                    self._ip_rates[key].count_in_window(3600)
                    if not self._ip_rates[key].timestamps:
                        del self._ip_rates[key]

            for ip, entry in expired_ips:
                print(f"[ACTIVE DEFENSE] IP ban expired: {ip}")
                self._dispatch_callbacks(ip_unban_callbacks, entry)


active_defense = ActiveDefense(default_ban_ttl=600)
