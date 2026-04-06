"""
SentinelIQ — Threat Intelligence Enrichment
Enriches alerts with data from FREE APIs:
- AbuseIPDB (IP reputation)
- ip-api.com (geolocation, no key needed)
- VirusTotal (free tier)
Results are cached in Redis to avoid repeated API calls
"""
import json
import hashlib
import asyncio
import aiohttp
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional

from config import settings


# ============================================================
# ENRICHMENT RESULT
# ============================================================
@dataclass
class IPEnrichment:
    ip: str
    country_code: str = ""           # "MA", "CN", "RU"
    country_name: str = ""           # "Morocco"
    city: str = ""
    isp: str = ""
    org: str = ""
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False

    # AbuseIPDB
    abuse_score: int = 0             # 0-100 (100 = definitely malicious)
    total_reports: int = 0
    last_reported: Optional[str] = None

    # Flags
    is_known_malicious: bool = False  # abuse_score > 50

    # Meta
    enriched_at: str = ""
    sources: list = None

    def __post_init__(self):
        self.sources = self.sources or []
        self.enriched_at = datetime.utcnow().isoformat()
        self.is_known_malicious = self.abuse_score > 50

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "isp": self.isp,
            "is_vpn": self.is_vpn,
            "is_tor": self.is_tor,
            "abuse_score": self.abuse_score,
            "total_reports": self.total_reports,
            "is_known_malicious": self.is_known_malicious,
            "enriched_at": self.enriched_at,
        }

    def summary(self) -> str:
        """Human-readable summary for dashboard"""
        parts = []
        if self.country_name:
            parts.append(f"📍 {self.city or self.country_name}")
        if self.isp:
            parts.append(f"🌐 {self.isp}")
        if self.abuse_score > 0:
            parts.append(f"⚠️ Abuse score: {self.abuse_score}/100 ({self.total_reports} reports)")
        if self.is_tor:
            parts.append("🧅 TOR exit node")
        if self.is_vpn:
            parts.append("🔒 VPN/Proxy")
        return " | ".join(parts) if parts else "No threat intel available"


# ============================================================
# SIMPLE IN-MEMORY CACHE (replace with Redis in production)
# ============================================================
class SimpleCache:
    def __init__(self, ttl_seconds: int = 3600):
        self._store: dict = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[dict]:
        entry = self._store.get(key)
        if not entry:
            return None
        if datetime.utcnow() > entry["expires"]:
            del self._store[key]
            return None
        return entry["value"]

    def set(self, key: str, value: dict):
        self._store[key] = {
            "value": value,
            "expires": datetime.utcnow() + timedelta(seconds=self._ttl)
        }

    def size(self) -> int:
        return len(self._store)


_cache = SimpleCache(ttl_seconds=3600)   # Cache for 1 hour


# ============================================================
# PRIVATE IP CHECKER
# Don't enrich internal IPs
# ============================================================
def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
        return (
            first == 10 or
            first == 127 or
            (first == 172 and 16 <= second <= 31) or
            (first == 192 and second == 168)
        )
    except ValueError:
        return False


# ============================================================
# THREAT INTEL CLIENT
# ============================================================
class ThreatIntelClient:

    GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,proxy,hosting"
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY

    async def enrich_ip(self, ip: str) -> IPEnrichment:
        """
        Main enrichment function.
        Fetches geolocation (free, no key) + AbuseIPDB (free tier).
        Results cached for 1 hour.
        """
        # Skip private IPs
        if is_private_ip(ip):
            return IPEnrichment(ip=ip, isp="Private/Internal Network")

        # Check cache
        cached = _cache.get(f"ip:{ip}")
        if cached:
            return IPEnrichment(**cached)

        enrichment = IPEnrichment(ip=ip)

        async with aiohttp.ClientSession() as session:
            # Run both requests concurrently
            tasks = [self._fetch_geoip(session, ip, enrichment)]
            if self.abuseipdb_key:
                tasks.append(self._fetch_abuseipdb(session, ip, enrichment))

            await asyncio.gather(*tasks, return_exceptions=True)

        # Cache the result
        _cache.set(f"ip:{ip}", enrichment.to_dict())

        return enrichment

    async def _fetch_geoip(self, session: aiohttp.ClientSession, ip: str, enrichment: IPEnrichment):
        """ip-api.com — free, no key required, 45 requests/minute"""
        try:
            async with session.get(
                self.GEOIP_URL.format(ip=ip),
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        enrichment.country_code = data.get("countryCode", "")
                        enrichment.country_name = data.get("country", "")
                        enrichment.city = data.get("city", "")
                        enrichment.isp = data.get("isp", "")
                        enrichment.org = data.get("org", "")
                        enrichment.is_vpn = data.get("proxy", False)
                        enrichment.is_proxy = data.get("proxy", False)
                        enrichment.sources.append("ip-api.com")
        except Exception:
            pass     # Fail silently — enrichment is optional

    async def _fetch_abuseipdb(self, session: aiohttp.ClientSession, ip: str, enrichment: IPEnrichment):
        """AbuseIPDB — free tier: 1000 checks/day"""
        try:
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

            async with session.get(
                self.ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    enrichment.abuse_score = d.get("abuseConfidenceScore", 0)
                    enrichment.total_reports = d.get("totalReports", 0)
                    enrichment.last_reported = d.get("lastReportedAt")
                    enrichment.is_tor = d.get("isTor", False)
                    enrichment.is_known_malicious = enrichment.abuse_score > 50
                    enrichment.sources.append("abuseipdb")
        except Exception:
            pass


# Global client
threat_intel = ThreatIntelClient()