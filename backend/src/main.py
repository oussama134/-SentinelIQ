"""
SentinelIQ backend application entrypoint.

This FastAPI service ties together log ingestion, PCAP-based ML detection,
correlation, MITRE enrichment, threat intel, alerting, and active response
behind one API used by the dashboard and remote collection agents.
"""

import os
import sys
import socket
import subprocess
import time
import json
import queue
import ipaddress
import ctypes
import pandas as pd
from datetime import datetime, timedelta
from threading import Thread, Lock
from collections import Counter, defaultdict
from core.auth  import verify_token, authenticate_user, create_access_token, decode_token
from fastapi.security import OAuth2PasswordRequestForm
import warnings
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel as PydanticBase

# ── Path setup ───────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))          # backend/src/
BACKEND_DIR = os.path.dirname(os.path.dirname(__file__))  # backend/
sys.path.insert(0, BACKEND_DIR)

# ── Existing IDS imports ─────────────────────────────────────
from flow_extractor import pcap_to_flows_with_metadata
from predictor import Predictor
from traffic_filter import (
    is_benign_system_traffic,
    post_process_prediction,
    should_generate_alert,
    TrafficStats,
)

# ── SIEM imports ─────────────────────────────────────────────
from config import settings
from database import init_db, AsyncSessionLocal, NormalizedLog, Alert, SeverityLevel
from core.ingestion import pipeline as ingestion_pipeline
from core.correlation import engine as correlation_engine
from core.mitre import get_mitre_mapping, EVENT_TYPE_MAPPINGS
from core.threat_intel import threat_intel
from core.active_defense import active_defense
from core.kill_switch import trigger as ks_trigger, get_audit_log as ks_log, lift_isolation
from core.correlation import KILL_SWITCH_RULE_IDS


# ── SMTP / Background ──────────────────────────────────────────
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import BackgroundTasks

_email_last_sent: dict[str, float] = {}   # src_ip → last email timestamp
_EMAIL_COOLDOWN_SECS = 600               # one email per IP per 10 minutes

def send_alert_email(alert_data: Alert, ip_country: str):
    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        return
    ip_key = getattr(alert_data, "src_ip", None) or "unknown"
    now = time.time()
    if now - _email_last_sent.get(ip_key, 0) < _EMAIL_COOLDOWN_SECS:
        return
    _email_last_sent[ip_key] = now
    try:
        dst  = getattr(alert_data, "dst_ip",   None) or "?"
        dev  = getattr(alert_data, "device_id", None) or _SIEM_HOSTNAME
        conf = getattr(alert_data, "confidence", 0) or 0
        sev  = str(getattr(alert_data, "severity", "CRITICAL")).replace("SeverityLevel.", "")

        msg = MIMEMultipart()
        msg['From'] = settings.SMTP_USER
        msg['To']   = settings.SMTP_USER
        # Subject: attack type + direction so the victim machine is visible at a glance
        msg['Subject'] = (
            f"[SentinelIQ] {sev} — {alert_data.attack_type} | "
            f"{alert_data.src_ip} → {dst} | device: {dev}"
        )

        html = f"""
        <html><body style='font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px'>
          <div style='border-left:4px solid #f85149;padding-left:16px;margin-bottom:20px'>
            <h2 style='color:#f85149;margin:0 0 4px'>SentinelIQ — Critical Alert</h2>
            <span style='color:#6e7681;font-size:12px'>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</span>
          </div>

          <table style='border-collapse:collapse;width:100%;max-width:560px'>
            <tr><td style='padding:6px 12px;color:#6e7681;width:160px'>Attack Type</td>
                <td style='padding:6px 12px;color:#f85149;font-weight:bold'>{alert_data.attack_type}</td></tr>
            <tr style='background:#161b22'><td style='padding:6px 12px;color:#6e7681'>Severity</td>
                <td style='padding:6px 12px;color:#f85149'>{sev}</td></tr>
            <tr><td style='padding:6px 12px;color:#6e7681'>Title</td>
                <td style='padding:6px 12px'>{alert_data.title}</td></tr>
            <tr style='background:#161b22'><td style='padding:6px 12px;color:#6e7681'>Source IP</td>
                <td style='padding:6px 12px;color:#58a6ff;font-weight:bold'>{alert_data.src_ip}&nbsp;{ip_country}</td></tr>
            <tr><td style='padding:6px 12px;color:#6e7681'>Destination IP</td>
                <td style='padding:6px 12px;color:#f0883e;font-weight:bold'>{dst}</td></tr>
            <tr style='background:#161b22'><td style='padding:6px 12px;color:#6e7681'>Targeted Device</td>
                <td style='padding:6px 12px;color:#d29922'>{dev}</td></tr>
            <tr><td style='padding:6px 12px;color:#6e7681'>Confidence</td>
                <td style='padding:6px 12px'>{round(conf * 100)}%</td></tr>
            <tr style='background:#161b22'><td style='padding:6px 12px;color:#6e7681'>MITRE Tactic</td>
                <td style='padding:6px 12px'>{getattr(alert_data, "mitre_tactic", "") or "—"}</td></tr>
            <tr><td style='padding:6px 12px;color:#6e7681'>MITRE Technique</td>
                <td style='padding:6px 12px'>{getattr(alert_data, "mitre_technique_id", "") or "—"}</td></tr>
          </table>

          <p style='margin-top:24px;font-size:11px;color:#6e7681'>
            Investigate → <a href='http://localhost:3000' style='color:#58a6ff'>SentinelIQ Dashboard</a>
          </p>
        </body></html>
        """
        msg.attach(MIMEText(html, 'html'))

        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[*] Alert email → {settings.SMTP_USER} | {alert_data.src_ip} → {dst} [{dev}]")
    except Exception as e:
        print(f"[!] Failed to send email: {str(e)}")

# ── Paths ────────────────────────────────────────────────────
_PROJECT_ROOT   = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODELS_DIR      = os.path.join(_PROJECT_ROOT, "backend", "models")
_DATA_DIR       = os.path.join(_PROJECT_ROOT, "data")
PCAP_PATH       = os.path.join(_DATA_DIR, "live_traffic.pcap")
CAPTURE_INTERFACE = os.getenv("SENTINELIQ_CAPTURE_INTERFACE", "7")  # Ethernet 2 = VirtualBox 192.168.56.x
_SIEM_HOSTNAME    = socket.gethostname()  # used as device_id for locally-captured traffic
CAPTURE_DURATION  = 10    # seconds — reduced for faster detection
CAPTURE_COOLDOWN  = 0    # no pause between captures

# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(title="SentinelIQ", version="5.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Authentication middleware ─────────────────────────────────
# Public: login + health check
# Forwarder: X-API-Key header required (forwarder can't do OAuth2)
# Everything else: Bearer JWT required
_PUBLIC_PATHS = frozenset({"/api/auth/login", "/"})
_FORWARDER_PATHS = frozenset({"/api/logs/ingest/bulk", "/api/pcap/ingest"})

class _AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # CORS preflight — browser sends OPTIONS with no auth header, let CORSMiddleware handle it
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if path in _PUBLIC_PATHS:
            return await call_next(request)
        if path in _FORWARDER_PATHS:
            key = request.headers.get("X-Api-Key", "") or request.headers.get("X-API-Key", "")
            if key != settings.FORWARDER_API_KEY:
                return JSONResponse({"detail": "Invalid or missing API key"}, status_code=401,
                                    headers={"WWW-Authenticate": "ApiKey"})
            return await call_next(request)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"detail": "Not authenticated"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        try:
            decode_token(auth_header[7:])
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers=exc.headers or {})
        return await call_next(request)

app.add_middleware(_AuthMiddleware)

import asyncio
main_loop = None
_remote_callbacks_registered = False

@app.on_event("startup")
async def startup_event():
    global main_loop, _remote_callbacks_registered
    main_loop = asyncio.get_running_loop()
    try:
        await init_db()
        print("[OK] PostgreSQL initialisé (async on uvicorn loop)")
    except Exception as _db_err:
        print(f"[!] PostgreSQL unavailable: {_db_err}")
        print("[!] Start the database with:  docker-compose up -d postgres")
    
    if _remote_response_enabled():
        if not _remote_callbacks_registered:
            active_defense.register_ip_ban_callback(_remote_ban_callback)
            active_defense.register_ip_unban_callback(_remote_unban_callback)
            _remote_callbacks_registered = True
        print(
            f"[*] Remote response enabled: "
            f"{settings.REMOTE_RESPONSE_USER}@{settings.REMOTE_RESPONSE_HOST}:"
            f"{settings.REMOTE_RESPONSE_PORT} via {settings.REMOTE_RESPONSE_BACKEND}"
        )

    # Init the whitelist cache from DB immediately
    await _load_trusted_ips_on_startup()

async def _load_trusted_ips_on_startup():
    from sqlalchemy import select
    from database import TrustedIP
    from traffic_filter import update_trusted_ips_cache
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(select(TrustedIP))
            ips = result.scalars().all()
            update_trusted_ips_cache([ip.ip_prefix for ip in ips])
            print(f"[OK] Loaded {len(ips)} trusted IP prefixes into memory cache")
    except Exception as e:
        print(f"[!] Startup Whitelist Load Error: {e}")

def run_async(coro):
    """Submit a coroutine to the uvicorn event loop from any background thread."""
    if main_loop and main_loop.is_running():
        return asyncio.run_coroutine_threadsafe(coro, main_loop)
    else:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(coro)


def _maybe_trigger_kill_switch(rule_id: str, src_ip: str, reason: str):
    """Fire the kill switch when a ransomware rule (R030/R031) fires."""
    if rule_id not in KILL_SWITCH_RULE_IDS:
        return
    if not settings.KILL_SWITCH_ENABLED:
        print(f"[KILL SWITCH] Rule {rule_id} fired — KILL_SWITCH_ENABLED=False, skipping")
        print(f"[KILL SWITCH] Set KILL_SWITCH_ENABLED=True in .env to arm")
        return
    if not settings.REMOTE_RESPONSE_HOST:
        print(f"[KILL SWITCH] Rule {rule_id} fired — no REMOTE_RESPONSE_HOST configured")
        return
    ks_trigger(
        action=settings.KILL_SWITCH_ACTION,
        host=settings.REMOTE_RESPONSE_HOST,
        user=settings.REMOTE_RESPONSE_USER,
        port=settings.REMOTE_RESPONSE_PORT,
        identity_file=settings.REMOTE_RESPONSE_IDENTITY_FILE or None,
        use_sudo=settings.REMOTE_RESPONSE_USE_SUDO,
        reason=f"[{rule_id}] {reason} (attacker: {src_ip})",
    )


# ── Active Defense global on/off toggle ──────────────────────────────────────
_active_defense_on: bool = True

# Per-device defense toggle. Key = device_id, value = True/False.
# Devices not in this dict inherit the global _active_defense_on setting.
_device_defense_enabled: dict[str, bool] = {}


def _is_defense_on(device_id: str = "") -> bool:
    """Return True if active defense should fire for this device."""
    if not _active_defense_on:
        return False
    if device_id and device_id in _device_defense_enabled:
        return _device_defense_enabled[device_id]
    return True


def _ban_ip_safely(ip: str, attack_type: str, reason: str, device_id: str = ""):
    if not _is_defense_on(device_id):
        return
    try:
        active_defense.ban_ip(ip, reason=reason, attack_type=attack_type)
    except Exception as e:
        print(f"[!] Active defense IP ban failed for {ip}: {e}")


def _ban_user_agent_safely(user_agent: str, attack_type: str, reason: str):
    if not user_agent or not _active_defense_on:
        return
    try:
        active_defense.ban_user_agent(user_agent, reason=reason, attack_type=attack_type)
    except Exception as e:
        print(f"[!] Active defense UA ban failed: {e}")


def _is_blockable_ip(ip: str) -> bool:
    if not ip or ip in {"0.0.0.0", "localhost", "multiple"}:
        return False
    if ip.startswith("127.") or ip.startswith("192.168.1."):
        return False  # never ban the SIEM's own local network
    return True


def _firewall_rule_name(ip: str) -> str:
    return f"SentinelIQ Auto Block {ip}"


def _is_running_as_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

_RUNNING_AS_ADMIN: bool = _is_running_as_admin()
if not _RUNNING_AS_ADMIN:
    print("[!] WARNING: SentinelIQ is NOT running as Administrator.")
    print("[!] Windows Firewall auto-blocking (New-NetFirewallRule) will fail with 'Access Denied (System Error 5)'.")
    print("[!] Fix: right-click your terminal → 'Run as administrator', then restart the backend.")


def _apply_windows_firewall_block(ip: str) -> bool:
    """Best-effort host firewall block for the SentinelIQ machine itself."""
    if not _active_defense_on or not _is_blockable_ip(ip):
        return False

    if not _RUNNING_AS_ADMIN:
        print(f"[!] Windows Firewall skip (no admin) for {ip} — restart backend as Administrator to enable")
        return False

    rule_name = _firewall_rule_name(ip)
    cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Inbound -Action Block -RemoteAddress {ip}'
    )
    proc = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
    stderr = (proc.stderr or "").strip().lower()
    if proc.returncode == 0 or "already exists" in stderr or "cannot create a file when that file already exists" in stderr:
        print(f"[*] Windows Firewall block active for {ip}")
        return True

    if "access is denied" in stderr or "system error 5" in stderr:
        print(f"[!] Windows Firewall denied for {ip} — backend must run as Administrator")
    else:
        print(f"[!] Windows Firewall auto-block failed for {ip}: {(proc.stderr or proc.stdout).strip()}")
    return False


async def _upsert_blocked_ip_record(session, ip: str, reason: str, alert_id: int | None = None, ttl_seconds: int = 600):
    """Persist auto-block state so the dashboard can display it."""
    if not _is_blockable_ip(ip):
        return

    from sqlalchemy import select
    from database import BlockedIP

    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    result = await session.execute(select(BlockedIP).where(BlockedIP.ip_address == ip))
    row = result.scalar_one_or_none()

    if row:
        row.reason = reason[:200]
        row.blocked_by = "AUTO"
        row.is_active = True
        row.expires_at = expires_at
        if alert_id:
            row.alert_id = alert_id
        return

    session.add(BlockedIP(
        ip_address=ip,
        reason=reason[:200],
        blocked_by="AUTO",
        alert_id=alert_id,
        is_active=True,
        expires_at=expires_at,
    ))


def _remote_response_enabled() -> bool:
    return bool(
        settings.REMOTE_RESPONSE_ENABLED
        and settings.REMOTE_RESPONSE_HOST
        and settings.REMOTE_RESPONSE_USER
    )


def _build_remote_ubuntu_command(ip: str, action: str) -> str:
    safe_ip = str(ipaddress.ip_address(ip))
    sudo_prefix = "sudo -n " if settings.REMOTE_RESPONSE_USE_SUDO else ""
    backend = (settings.REMOTE_RESPONSE_BACKEND or "iptables").strip().lower()

    if backend == "ufw":
        if action == "ban":
            return (
                f"{sudo_prefix}bash -lc "
                f"\"ufw status | grep -F 'DENY IN    {safe_ip}' >/dev/null "
                f"|| ufw insert 1 deny from {safe_ip}\""
            )
        return (
            f"{sudo_prefix}bash -lc "
            f"\"yes | ufw delete deny from {safe_ip} >/dev/null 2>&1 || true\""
        )

    if action == "ban":
        return (
            f"{sudo_prefix}bash -lc "
            f"\"iptables -C INPUT -s {safe_ip} -j DROP 2>/dev/null "
            f"|| iptables -I INPUT -s {safe_ip} -j DROP\""
        )
    return (
        f"{sudo_prefix}bash -lc "
        f"\"iptables -D INPUT -s {safe_ip} -j DROP 2>/dev/null || true\""
    )


# ── SSH circuit breaker ───────────────────────────────────────
# Opens after 3 consecutive failures; auto-resets after 2 minutes.
_ssh_consec_fails: int = 0
_ssh_quiet_until:  float = 0.0
_SSH_OPEN_AFTER   = 3
_SSH_COOLDOWN     = 120   # seconds before next retry burst

def _ssh_circuit_open() -> bool:
    return _ssh_consec_fails >= _SSH_OPEN_AFTER and time.time() < _ssh_quiet_until

def _ssh_on_success():
    global _ssh_consec_fails, _ssh_quiet_until
    _ssh_consec_fails = 0
    _ssh_quiet_until  = 0.0

def _ssh_on_failure():
    global _ssh_consec_fails, _ssh_quiet_until
    _ssh_consec_fails += 1
    if _ssh_consec_fails >= _SSH_OPEN_AFTER:
        _ssh_quiet_until = time.time() + _SSH_COOLDOWN
        print(f"[SSH] Circuit breaker OPEN — remote response paused {_SSH_COOLDOWN}s "
              f"(Ubuntu VM unreachable?). Will retry automatically.")

def _build_ssh_base() -> list:
    """Return the common SSH flags used by all remote calls."""
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=5",   # fail fast if host is unreachable
        "-p", str(settings.REMOTE_RESPONSE_PORT),
    ]
    if settings.REMOTE_RESPONSE_IDENTITY_FILE:
        cmd.extend(["-i", settings.REMOTE_RESPONSE_IDENTITY_FILE])
    cmd.append(f"{settings.REMOTE_RESPONSE_USER}@{settings.REMOTE_RESPONSE_HOST}")
    return cmd


def _run_remote_ubuntu_flush() -> bool:
    """Flush the INPUT chain on Ubuntu — removes all SentinelIQ blocks at once."""
    if not _remote_response_enabled():
        return False
    if _ssh_circuit_open():
        print("[SSH] Circuit breaker open — flush skipped")
        return False
    sudo_prefix = "sudo -n " if settings.REMOTE_RESPONSE_USE_SUDO else ""
    backend = (settings.REMOTE_RESPONSE_BACKEND or "iptables").strip().lower()
    if backend == "ufw":
        cmd = f"{sudo_prefix}bash -lc \"yes | ufw reset && ufw --force enable\""
    else:
        cmd = f"{sudo_prefix}bash -lc \"iptables -F INPUT\""
    ssh_cmd = _build_ssh_base() + [cmd]
    try:
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=8)
        if proc.returncode == 0:
            _ssh_on_success()
            return True
        _ssh_on_failure()
        return False
    except subprocess.TimeoutExpired:
        _ssh_on_failure()
        print("[SSH] Flush timed out")
        return False


def _run_remote_ubuntu_firewall_action(ip: str, action: str):
    if not _active_defense_on or not _remote_response_enabled() or not _is_blockable_ip(ip):
        return
    if _ssh_circuit_open():
        return   # silently skip — circuit is open, logged when it opened

    safe_ip = str(ipaddress.ip_address(ip))
    ssh_cmd = _build_ssh_base() + [_build_remote_ubuntu_command(safe_ip, action)]

    try:
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=8)
        if proc.returncode == 0:
            _ssh_on_success()
            print(f"[*] Remote Ubuntu firewall {action} applied for {safe_ip}")
            return
        detail = (proc.stderr or proc.stdout or "").strip()
        _ssh_on_failure()
        print(f"[!] Remote Ubuntu firewall {action} failed for {safe_ip}: {detail}")
    except subprocess.TimeoutExpired:
        _ssh_on_failure()
        print(f"[!] Remote Ubuntu SSH timed out for {safe_ip}")


def _remote_ban_callback(entry):
    _run_remote_ubuntu_firewall_action(entry.identifier, "ban")


def _remote_unban_callback(entry):
    _run_remote_ubuntu_firewall_action(entry.identifier, "unban")

# ── Predictor ─────────────────────────────────────────────────
print("\n[*] SentinelIQ Startup Sequence Initiated...")
print("[*] Loading Machine Learning Model into memory (this may take 15-30 seconds). Please wait...\n")
pred = Predictor(MODELS_DIR, confidence_threshold=0.65)

# ── Global state ──────────────────────────────────────────────
history_lock    = Lock()
sequence_counter = 0
traffic_stats   = TrafficStats()
session_stats   = {
    "session_start": datetime.now().isoformat(),
    "captures": 0,
    "flows_processed": 0,
}

from core.log_collector import LogParser as _LogParser
_log_parser = _LogParser()
_log_source_stats = defaultdict(lambda: {"received": 0, "alerts_fired": 0, "last_seen": None})

# ── Parallel capture queue ────────────────────────────────────
_pcap_queue = queue.Queue(maxsize=2)


# =============================================================================
# CAPTURE & PROCESS
# =============================================================================

def capture_thread():
    """Thread 1 — capture continuously into rotating pcap files."""
    counter = 0
    print(f"[*] Capture thread started — interface {CAPTURE_INTERFACE}, {CAPTURE_DURATION}s windows")
    while True:
        try:
            counter += 1
            pcap_file = os.path.join(_DATA_DIR, f"cap_{counter % 5}.pcap")
            subprocess.run([
                r"C:\Program Files\Wireshark\tshark.exe",
                "-i", CAPTURE_INTERFACE,
                "-a", f"duration:{CAPTURE_DURATION}",
                "-F", "pcap",
                "-w", pcap_file
            ], check=True, timeout=CAPTURE_DURATION + 5, capture_output=True)

            if not _pcap_queue.full():
                _pcap_queue.put(pcap_file)
            else:
                print(f"[!] Capture queue full — dropping {pcap_file} (processing too slow)")
        except Exception as e:
            print(f"[!] Capture error: {e}")
            time.sleep(2)


def process_thread():
    """Thread 2 — process pcap files as soon as they are ready."""
    print("[*] Process thread started")
    while True:
        try:
            pcap_file = _pcap_queue.get(timeout=30)
            _process_pcap(pcap_file)
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[!] Process error: {e}")


# ── Pydantic models for log ingestion ────────────────────────


# =============================================================================
# ASYNC DB SAVE
# =============================================================================

async def _save_alerts_to_postgres(triggered_alerts, unified_log, device_id: str = ""):
    # Commit the normalized log first in its own transaction so its ID is
    # stable before we reference it as a FK in the alert rows.
    async with AsyncSessionLocal() as db_session:
        db_log = NormalizedLog(
            source="NETWORK",
            src_ip=unified_log.src_ip,
            dst_ip=unified_log.dst_ip,
            src_port=unified_log.src_port,
            dst_port=unified_log.dst_port,
            protocol=unified_log.protocol,
            predicted_label=unified_log.predicted_label,
            confidence=unified_log.confidence,
            event_type=unified_log.event_type,
            extra=unified_log.extra or {},
        )
        db_session.add(db_log)
        await db_session.commit()
        log_id = db_log.id

    async with AsyncSessionLocal() as db_session:
        for alert_data in triggered_alerts:
            enrichment = await threat_intel.enrich_ip(alert_data.src_ip)
            db_alert = Alert(
                title=alert_data.title,
                description=alert_data.description,
                severity=SeverityLevel(alert_data.rule.severity),
                src_ip=alert_data.src_ip,
                dst_ip=alert_data.dst_ip,
                attack_type=alert_data.attack_type,
                confidence=alert_data.confidence,
                rule_id=alert_data.rule.rule_id,
                mitre_tactic=alert_data.mitre_tactic,
                mitre_technique_id=alert_data.mitre_technique_id,
                mitre_technique_name=alert_data.mitre_technique_name,
                ip_country=enrichment.country_code or None,
                ip_isp=enrichment.isp,
                ip_abuse_score=enrichment.abuse_score,
                is_known_malicious=enrichment.is_known_malicious,
                raw_log_id=log_id,
                device_id=device_id or _SIEM_HOSTNAME,
            )
            db_session.add(db_alert)
            await db_session.flush()

            # Email for CRITICAL; active defense for CRITICAL + HIGH
            if db_alert.severity == SeverityLevel.CRITICAL:
                Thread(target=send_alert_email, args=(db_alert, enrichment.country_code or ''), daemon=True).start()
                _maybe_trigger_kill_switch(
                    db_alert.rule_id, db_alert.src_ip, db_alert.title
                )

            if db_alert.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                _ban_ip_safely(
                    db_alert.src_ip,
                    attack_type=db_alert.attack_type,
                    reason=f"{db_alert.severity} alert auto-ban: {db_alert.title}",
                    device_id=device_id,
                )
                firewall_reason = f"{db_alert.severity} auto-block: {db_alert.title}"
                firewall_applied = _apply_windows_firewall_block(db_alert.src_ip)
                if firewall_applied:
                    await _upsert_blocked_ip_record(
                        db_session,
                        db_alert.src_ip,
                        reason=firewall_reason,
                        alert_id=db_alert.id,
                    )
                if alert_data.extra and 'user_agent' in alert_data.extra:
                    _ban_user_agent_safely(
                        alert_data.extra['user_agent'],
                        attack_type=db_alert.attack_type,
                        reason=f"{db_alert.severity} alert auto-ban: {db_alert.title}",
                    )

        await db_session.commit()


async def _evaluate_and_save_log_event(event, device_id: str = "", forwarder_ip: str = "") -> bool:
    """Run a ParsedLogEvent through the correlation engine and persist to DB."""
    try:
        _src_map = {
            "auth": "AUTH", "linux-auth": "AUTH",
            "nginx": "WEB", "apache": "WEB",
            "syslog": "SYSLOG",
        }
        source = _src_map.get((event.source_type or "").lower(), "NETWORK")

        # For log-based sources (auth.log, syslog), dst_ip is never in the log line.
        # Use the HTTP client IP (the forwarder machine) as the destination instead.
        effective_dst = event.dst_ip or forwarder_ip or ""

        unified_log = ingestion_pipeline.process_raw(source, {
            "src_ip":      event.src_ip,
            "dst_ip":      effective_dst,
            "event_type":  event.event_type,
            "username":    event.username,
            "message":     event.message,
            "extra":       event.extra or {},
        })

        triggered = correlation_engine.process_log(unified_log)
        if not triggered:
            return False

        async with AsyncSessionLocal() as db_session:
            db_log = NormalizedLog(
                source=source,
                src_ip=event.src_ip,
                dst_ip=effective_dst,
                event_type=event.event_type,
                username=event.username,
                message=event.message,
                extra=event.extra or {},
            )
            db_session.add(db_log)
            await db_session.commit()
            log_id = db_log.id

        async with AsyncSessionLocal() as db_session:
            for alert_data in triggered:
                enrichment = await threat_intel.enrich_ip(alert_data.src_ip)
                attack_type = EVENT_TYPE_MAPPINGS.get(alert_data.attack_type, alert_data.attack_type)
                title       = alert_data.title
                sev_str     = alert_data.rule.severity

                row = Alert(
                    title=title,
                    description=alert_data.description,
                    severity=SeverityLevel(sev_str),
                    src_ip=alert_data.src_ip,
                    dst_ip=alert_data.dst_ip,
                    attack_type=attack_type,
                    confidence=alert_data.confidence,
                    rule_id=alert_data.rule.rule_id,
                    mitre_tactic=alert_data.mitre_tactic,
                    mitre_technique_id=alert_data.mitre_technique_id,
                    mitre_technique_name=alert_data.mitre_technique_name,
                    ip_country=enrichment.country_code or None,
                    ip_isp=enrichment.isp,
                    ip_abuse_score=enrichment.abuse_score,
                    is_known_malicious=enrichment.is_known_malicious,
                    raw_log_id=log_id,
                    device_id=device_id or _SIEM_HOSTNAME,
                )
                db_session.add(row)
                await db_session.flush()

                print(f"[{datetime.now().strftime('%H:%M:%S')}] [LOG] LOG ALERT: {title} | {sev_str}")

                if row.severity == SeverityLevel.CRITICAL:
                    Thread(target=send_alert_email, args=(row, enrichment.country_code or ''), daemon=True).start()
                    _maybe_trigger_kill_switch(row.rule_id, row.src_ip, row.title)

                if row.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                    _ban_ip_safely(event.src_ip, attack_type=attack_type,
                                   reason=f"{row.severity} log alert auto-ban: {title}",
                                   device_id=device_id)
                    fw_ok = _apply_windows_firewall_block(event.src_ip)
                    if fw_ok:
                        await _upsert_blocked_ip_record(
                            db_session, event.src_ip,
                            reason=f"{row.severity} log auto-block: {title}",
                            alert_id=row.id,
                        )
                    if hasattr(event, 'extra') and event.extra and 'user_agent' in event.extra:
                        _ban_user_agent_safely(event.extra['user_agent'], attack_type=attack_type,
                                               reason=f"{row.severity} log alert auto-ban: {title}")

            await db_session.commit()

        traffic_stats.record_alert()
        _log_source_stats[event.source_type]["alerts_fired"] += 1
        return True

    except Exception as e:
        print(f"[!] Log alert save error: {e}")
        return False


# =============================================================================
# RULE-BASED DETECTION LAYER
# =============================================================================

from collections import defaultdict as _dd

_rb_state = {
    "dst_ports_per_src": _dd(set),
    "ssh_attempts":      _dd(int),
    "ftp_attempts":      _dd(int),
    "bot_ports":         _dd(int),
    "http_reqs":         _dd(int),   # persistent HTTP flood counter (DoS Hulk)
    "ua_reqs":           _dd(int),
    "last_alert":        _dd(float),
}
_RB_COOLDOWN = 30


def _rb_can_alert(key: str) -> bool:
    now = time.time()
    if now - _rb_state["last_alert"][key] > _RB_COOLDOWN:
        _rb_state["last_alert"][key] = now
        return True
    return False


def _rule_based_detect(flow_metadata: list, ts: str, device_id: str = ""):
    C2_PORTS = {6667, 6668, 6669, 4444, 8080, 9090, 1080, 5555, 31337}
    FLOOD_PKT_THRESHOLD = 200   # packets from one source in a 10s window → flood

    local_ports  = _dd(set)
    ssh_hits     = _dd(int)
    ftp_hits     = _dd(int)
    bot_hits     = _dd(int)
    http_hits    = _dd(int)
    flood_pkts   = _dd(int)   # packet volume per source in this capture window
    dst_per_src  = _dd(str)   # most recent non-zero dst_ip seen per attacker src

    for fl in flow_metadata:
        if is_benign_system_traffic(fl):
            src = fl.get("src_ip", "")
            if src:
                _rb_state["dst_ports_per_src"][src].clear()
                _rb_state["ssh_attempts"][src] = 0
                _rb_state["ftp_attempts"][src] = 0
                _rb_state["bot_ports"][src] = 0
            continue

        src   = fl.get("src_ip", "")
        dst   = fl.get("dst_ip", "")
        dport = int(fl.get("dst_port", 0))

        if dst and dst != "0.0.0.0":
            dst_per_src[src] = dst
        proto = fl.get("protocol", "TCP")
        pkt_n = int(fl.get("packet_count", 1))

        if proto == "TCP":
            local_ports[src].add(dport)

        if dport == 22:           ssh_hits[src] += 1
        if dport == 21:           ftp_hits[src] += 1
        if dport in C2_PORTS:     bot_hits[src] += 1
        if dport == 80 and proto == "TCP":
            http_hits[dst] += 1
            ua = fl.get('extra', {}).get('user_agent', '') if 'extra' in fl else fl.get('user_agent', '')
            if ua and len(ua) > 5:
                _rb_state["ua_reqs"][ua] += 1

        flood_pkts[src] += pkt_n   # count raw packet volume per source

    # ── Merge into persistent state ──────────────────────────────
    for src, ports in local_ports.items():
        _rb_state["dst_ports_per_src"][src] |= ports
    for src, n in ssh_hits.items():  _rb_state["ssh_attempts"][src] += n
    for src, n in ftp_hits.items():  _rb_state["ftp_attempts"][src] += n
    for src, n in bot_hits.items():  _rb_state["bot_ports"][src]    += n

    # ── Memory guard: prune oldest 250 IPs when dict exceeds 500 ────
    if len(_rb_state["dst_ports_per_src"]) > 500:
        for stale in list(_rb_state["dst_ports_per_src"])[:250]:
            del _rb_state["dst_ports_per_src"][stale]
            _rb_state["ssh_attempts"].pop(stale, None)
            _rb_state["ftp_attempts"].pop(stale, None)
            _rb_state["bot_ports"].pop(stale, None)

    # ── Alert-firing helper ───────────────────────────────────────
    def _rb_fire(src_ip, label, event_type, conf, reason, dst_ip=None):
        try:
            resolved_dst = dst_ip or dst_per_src.get(src_ip, "0.0.0.0")
            log = ingestion_pipeline.process_network_flow(
                src_ip=src_ip, dst_ip=resolved_dst,
                src_port=0, dst_port=0, protocol="TCP",
                predicted_label=label, confidence=conf,
                flow_features={"rule_based": True, "reason": reason},
            )
            triggered = correlation_engine.process_log(log)
            if triggered:
                run_async(_save_alerts_to_postgres(triggered, log, device_id))
                for a in triggered:
                    traffic_stats.record_alert()
                    print(f"[{ts}] [ALERT] RB-{event_type}: {a.title} | {a.rule.severity}")
        except Exception as e:
            print(f"[!] Rule-based alert error ({event_type}): {e}")

    # ── Packet flood / SYN flood (catches hping3 and similar) ────
    for src, n in flood_pkts.items():
        if n >= FLOOD_PKT_THRESHOLD and _rb_can_alert(f"flood:{src}"):
            print(f"[{ts}] [ALERT] Packet flood: {src} sent {n} pkts in window")
            _rb_fire(src, "DDoS", "ddos", 0.88, f"pkt_flood:{n}")

    # ── HTTP flood (DoS Hulk) — separate key so DDoS doesn't crowd it out ─────
    for src, n in http_hits.items():
        _rb_state["http_reqs"][src] += n
    for src, n in list(_rb_state["http_reqs"].items()):
        if n >= 80 and _rb_can_alert(f"http_flood:{src}"):
            print(f"[{ts}] [ALERT] HTTP flood: {src} → {n} GET reqs in window")
            _rb_fire(src, "DoS Hulk", "dos_hulk", 0.87, f"http_flood:{n}")
            _rb_state["http_reqs"][src] = 0

    # ── Port scan ─────────────────────────────────────────────────
    for src, ports in list(_rb_state["dst_ports_per_src"].items()):
        if len(ports) >= 30 and _rb_can_alert(f"scan:{src}"):
            print(f"[{ts}] [ALERT] Port scan: {src} → {len(ports)} ports")
            _rb_fire(src, "PortScan", "port_scan", 0.85, f"portscan:{len(ports)}")
            _rb_state["dst_ports_per_src"][src].clear()

    # ── SSH brute force ───────────────────────────────────────────
    for src, n in list(_rb_state["ssh_attempts"].items()):
        if n >= 5 and _rb_can_alert(f"ssh:{src}"):
            print(f"[{ts}] [ALERT] SSH brute force: {src} → {n} attempts")
            _rb_fire(src, "SSH-Patator", "ssh_brute_force", 0.85, f"ssh_bf:{n}")
            _rb_state["ssh_attempts"][src] = 0

    # ── FTP brute force ───────────────────────────────────────────
    for src, n in list(_rb_state["ftp_attempts"].items()):
        if n >= 5 and _rb_can_alert(f"ftp:{src}"):
            print(f"[{ts}] [ALERT] FTP brute force: {src} → {n} attempts")
            _rb_fire(src, "FTP-Patator", "ftp_brute_force", 0.85, f"ftp_bf:{n}")
            _rb_state["ftp_attempts"][src] = 0

    # ── C2 / Botnet beaconing ─────────────────────────────────────
    for src, n in list(_rb_state["bot_ports"].items()):
        if n >= 5 and _rb_can_alert(f"bot:{src}"):
            print(f"[{ts}] [ALERT] C2 beaconing: {src} → {n} C2-port connections")
            _rb_fire(src, "Bot", "botnet_activity", 0.82, f"c2_beacon:{n}")
            _rb_state["bot_ports"][src] = 0


def _process_pcap(pcap_file: str):
    """Process ONE pcap file independently. No global accumulation."""
    global sequence_counter
    timestamp = datetime.now().strftime("%H:%M:%S")

    if not os.path.exists(pcap_file):
        return
    pcap_size = os.path.getsize(pcap_file)
    if pcap_size == 0:
        print(f"[{timestamp}] [*] Pcap empty (0 bytes): {pcap_file}")
        return

    try:
        # Quick raw packet count diagnostic using scapy
        from scapy.all import rdpcap, IP
        _raw = rdpcap(pcap_file)
        _ip_count = sum(1 for p in _raw if IP in p)
        print(f"[{timestamp}] [PCAP] {os.path.basename(pcap_file)} — "
              f"{len(_raw)} pkts total, {_ip_count} IP pkts, {pcap_size//1024}KB  "
              f"(interface={CAPTURE_INTERFACE})")

        if _ip_count == 0:
            print(f"[{timestamp}] [!] No IP packets — check CAPTURE_INTERFACE (run: tshark -D)")
            _rule_based_detect([], timestamp)
            return

        df, flow_metadata = pcap_to_flows_with_metadata(pcap_file)

        if df.empty:
            print(f"[{timestamp}] [*] No flows extracted (all filtered by whitelist/multicast)")
            _rule_based_detect(flow_metadata, timestamp)
            return

        # Safety check — skip if too many flows (pcap too large)
        if len(df) > 5000:
            print(f"[{timestamp}] [WARN]  Too many flows ({len(df)}) — skipping to avoid lag")
            _rule_based_detect(flow_metadata, timestamp)
            return

        print(f"[{timestamp}] [SCAN] Extracted {len(df)} flows — running ML...")

        results = pred.predict_df_with_scores(df)
        if not results:
            _rule_based_detect(flow_metadata, timestamp)
            return

        prediction_counts = Counter()

        with history_lock:
            for flow_info in flow_metadata:
                if is_benign_system_traffic(flow_info):
                    traffic_stats.record_flow(filtered=True)
                else:
                    traffic_stats.record_flow(filtered=False)

            for idx, (label, score) in enumerate(results):
                sequence_counter += 1

                flow_idx = idx + 4
                if flow_idx >= len(flow_metadata):
                    continue
                flow_info = flow_metadata[flow_idx]

                if is_benign_system_traffic(flow_info):
                    continue

                label, score = post_process_prediction(label, score, flow_info)
                prediction_counts[label] += 1

                # ── ML path -> SIEM correlation ───────────────
                try:
                    unified_log = ingestion_pipeline.process_network_flow(
                        src_ip=flow_info.get("src_ip", "0.0.0.0"),
                        dst_ip=flow_info.get("dst_ip", "0.0.0.0"),
                        src_port=int(flow_info.get("src_port", 0)),
                        dst_port=int(flow_info.get("dst_port", 0)),
                        protocol=flow_info.get("protocol", "TCP"),
                        predicted_label=label,
                        confidence=float(score),
                        flow_features=flow_info,
                    )
                    triggered = correlation_engine.process_log(unified_log)

                    if triggered:
                        run_async(_save_alerts_to_postgres(triggered, unified_log, _SIEM_HOSTNAME))
                        for a in triggered:
                            traffic_stats.record_alert()
                            print(f"[{timestamp}] [ALERT] SIEM: {a.title} | {a.mitre_technique_id} | {a.rule.severity}")
                    elif label.upper() != "BENIGN":
                        traffic_stats.record_false_positive_prevented()

                except Exception as siem_err:
                    print(f"[!] SIEM error (non-fatal): {siem_err}")
                    if should_generate_alert(label, score, flow_info):
                        traffic_stats.record_alert()

            session_stats["captures"] += 1
            session_stats["flows_processed"] += len(df)

        if prediction_counts:
            non_benign = {k: v for k, v in prediction_counts.items() if k != "BENIGN"}
            if non_benign:
                print(f"[{timestamp}] [RED] ATTACKS: {non_benign}")
            else:
                print(f"[{timestamp}] [OK] {len(results)} flows -> BENIGN")

        # ── Rule-based layer (catches what ML misses) ────────
        _rule_based_detect(flow_metadata, timestamp)

    except Exception as e:
        print(f"[{timestamp}] [ERR] Processing error: {e}")
        import traceback; traceback.print_exc()


# ── Pydantic models for log ingestion ────────────────────────

class LogEntry(PydanticBase):
    source: str
    raw: str
    device_id: str = ""

class BulkLogRequest(PydanticBase):
    logs: list[LogEntry]
    device_id: str = ""   # device that sent this batch; overrides per-entry if set



@app.post("/api/logs/ingest/bulk")
async def ingest_bulk(payload: BulkLogRequest, request: Request):
    """Ingest multiple log lines at once."""
    if len(payload.logs) > 500:
        raise HTTPException(status_code=413, detail=f"Batch too large: {len(payload.logs)} logs (max 500)")
    results = {"received": len(payload.logs), "parsed": 0, "alerts_fired": 0, "skipped": 0}

    if _log_parser is None:
        return {"status": "error", "reason": "log_parser not available"}

    client_ip = request.client.host if request.client else ""

    # Parse all lines
    parsed_events = []
    for entry in payload.logs:
        source = entry.source
        raw    = entry.raw.strip()
        if not raw:
            results["skipped"] += 1
            continue
        _log_source_stats[source]["received"] += 1
        _log_source_stats[source]["last_seen"] = datetime.utcnow().isoformat()
        event = _log_parser.parse(source=source, raw=raw)
        if not event:
            results["skipped"] += 1
            continue
        results["parsed"] += 1
        parsed_events.append(event)

    # Process every event individually so the correlation engine counts
    # each occurrence — the AlertSuppressor prevents alert storms.
    bulk_device_id = payload.device_id
    for ev in parsed_events:
        if await _evaluate_and_save_log_event(ev, bulk_device_id, client_ip):
            results["alerts_fired"] += 1

    return {"status": "ok", **results}



# =============================================================================
# API ENDPOINTS
# =============================================================================

from datetime import datetime, timedelta

@app.get("/api/siem/alerts")
async def siem_alerts(
    limit: int = Query(100, le=500),
    attack_type: str = Query(None),
    src_ip: str = Query(None),
    device_id: str = Query(None),
    minutes: int = Query(None, ge=1, le=1440)
):
    from sqlalchemy import select, desc
    from database import Alert as SiemAlert, BlockedIP

    try:
        async with AsyncSessionLocal() as s:
            stmt = select(SiemAlert)

            # [OK] NEW: time filter
            if minutes:
                since = datetime.utcnow() - timedelta(minutes=minutes)
                stmt = stmt.where(SiemAlert.created_at >= since)

            stmt = stmt.order_by(desc(SiemAlert.created_at))  # [OK] FIX (better than id)

            if attack_type:
                stmt = stmt.where(SiemAlert.attack_type.ilike(f"%{attack_type}%"))
            if src_ip:
                stmt = stmt.where(SiemAlert.src_ip.ilike(f"%{src_ip}%"))
            if device_id:
                stmt = stmt.where(SiemAlert.device_id == device_id)

            result = await s.execute(stmt.limit(limit))
            alerts = result.scalars().all()

            blocked_r = await s.execute(select(BlockedIP.ip_address))
            blocked_set = {row[0] for row in blocked_r.all()}

        return {
            "alerts": [{
                "id": a.id,
                "title": a.title,
                "severity": str(a.severity),
                "src_ip": a.src_ip,
                "attack_type": a.attack_type,
                "confidence": a.confidence,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_technique_name": a.mitre_technique_name,
                "is_known_malicious": a.is_known_malicious,
                "dst_ip": a.dst_ip,
                "is_blocked": a.src_ip in blocked_set,
                "ip_country": a.ip_country,
                "ip_isp": a.ip_isp,
                "ip_abuse_score": a.ip_abuse_score,
                "device_id": a.device_id or _SIEM_HOSTNAME,

                # [OK] FIX: always UTC ISO
                "created_at": a.created_at.replace(tzinfo=None).isoformat() + "Z"
                if a.created_at else None,
            } for a in alerts],
            "total": len(alerts),
        }

    except Exception as e:
        return {"error": str(e), "alerts": []}

@app.get("/api/siem/trusted-ips")
async def get_trusted_ips():
    from sqlalchemy import select
    from database import TrustedIP
    async with AsyncSessionLocal() as s:
        result = await s.execute(select(TrustedIP))
        ips = result.scalars().all()
        # Update traffic_filter caching as a side-effect to ensure it's loaded
        from traffic_filter import update_trusted_ips_cache
        update_trusted_ips_cache([ip.ip_prefix for ip in ips])
        return [{"id": ip.id, "ip_prefix": ip.ip_prefix, "description": ip.description, "added_at": ip.added_at.isoformat()} for ip in ips]

class TrustedIPCreate(PydanticBase):
    ip_prefix: str
    description: str

@app.post("/api/siem/trusted-ips")
async def add_trusted_ip(data: TrustedIPCreate):
    from database import TrustedIP
    from sqlalchemy.exc import IntegrityError
    try:
        async with AsyncSessionLocal() as s:
            # Truncate description to 200 chars max to prevent StringDataRightTruncationError in PG
            desc = data.description[:199] if data.description else ""
            new_ip = TrustedIP(ip_prefix=data.ip_prefix, description=desc)
            s.add(new_ip)
            await s.commit()
            
        # Refresh the in-memory cache immediately
        await _load_trusted_ips_on_startup()
        return {"success": True}
    except IntegrityError:
        # IP already exists, safe to ignore
        return {"success": True, "message": "IP already trusted"}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/siem/trusted-ips/{ip_id}")
async def delete_trusted_ip(ip_id: int):
    from sqlalchemy import delete
    from database import TrustedIP
    async with AsyncSessionLocal() as s:
        await s.execute(delete(TrustedIP).where(TrustedIP.id == ip_id))
        await s.commit()
        
    # Refresh the in-memory cache immediately
    await _load_trusted_ips_on_startup()
    return {"success": True}


@app.get("/api/siem/dashboard")
async def siem_dashboard():
    from sqlalchemy import select, func, desc
    from datetime import timedelta
    from database import Alert as SiemAlert
    try:
        async with AsyncSessionLocal() as s:
            total_r      = await s.execute(select(func.count(SiemAlert.id)))
            severity_r   = await s.execute(select(SiemAlert.severity, func.count(SiemAlert.id)).group_by(SiemAlert.severity))
            tactic_r     = await s.execute(select(SiemAlert.mitre_tactic, func.count(SiemAlert.id)).group_by(SiemAlert.mitre_tactic).order_by(desc(func.count(SiemAlert.id))))
            top_ips_r    = await s.execute(select(SiemAlert.src_ip, func.count(SiemAlert.id)).group_by(SiemAlert.src_ip).order_by(desc(func.count(SiemAlert.id))).limit(10))
        return {
            "total_alerts":     total_r.scalar(),
            "by_severity":      {str(r[0]): r[1] for r in severity_r},
            "by_mitre_tactic":  [{"tactic": r[0], "count": r[1]} for r in tactic_r],
            "top_source_ips":   [{"ip": r[0], "count": r[1]} for r in top_ips_r],
            "correlation_engine": correlation_engine.get_stats(),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/alerts")
async def get_alerts(limit: int = Query(50, ge=1, le=1000)):
    from sqlalchemy import select, desc
    from database import Alert as SiemAlert
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(select(SiemAlert).order_by(desc(SiemAlert.id)).limit(limit))
            alerts = result.scalars().all()
        return {
            "alerts": [{"id": a.id, "title": a.title, "severity": str(a.severity),
                        "src_ip": a.src_ip, "attack_type": a.attack_type,
                        "confidence": a.confidence, "mitre_technique_id": a.mitre_technique_id,
                        "created_at": a.created_at.isoformat() + "Z" if a.created_at else None}
                       for a in alerts],
            "total": len(alerts),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/debug/pipeline")
async def debug_pipeline():
    """
    Live pipeline health-check.
    Hit this while an attack is running to see exactly where flows are going.
    """
    from core.correlation import CLASS_THRESHOLDS, DEFAULT_RULES
    rules_summary = {r.rule_id: {"name": r.name, "threshold": r.count_threshold, "window": r.window_seconds} for r in DEFAULT_RULES}
    engine_stats = correlation_engine.get_stats()
    sup = correlation_engine.suppressor._last_alert

    # Current event counters inside the sliding-window engine
    event_counts = {}
    for etype, ips in correlation_engine._event_counts.items():
        event_counts[etype] = {ip: len(ts) for ip, ts in ips.items() if ts}

    return {
        "predictor_threshold":  pred.confidence_threshold,
        "class_thresholds":     CLASS_THRESHOLDS,
        "traffic_stats":        traffic_stats.get_summary(),
        "engine_stats":         engine_stats,
        "active_event_counts":  event_counts,
        "suppressor_keys":      list(sup.keys()),
        "capture_interface":    CAPTURE_INTERFACE,
        "capture_duration_s":   CAPTURE_DURATION,
    }


@app.post("/api/pcap/ingest")
async def ingest_pcap_from_ubuntu(request: Request):
    """
    Receive a raw pcap file POSTed by ubuntu_forwarder.py.
    Writes to a temp file then feeds it through the same ML pipeline
    that processes local captures.
    """
    data = await request.body()
    if len(data) < 25:
        return {"status": "skipped", "reason": "payload too small"}

    pcap_device_id = request.headers.get("X-Device-ID", "")

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False, dir=_DATA_DIR) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    ts = datetime.now().strftime("%H:%M:%S")
    device_tag = f" [{pcap_device_id}]" if pcap_device_id else ""
    print(f"[{ts}] [REMOTE PCAP]{device_tag} Received {len(data)//1024}KB from Ubuntu forwarder")

    attack_counts: dict = {}
    flow_metadata = []
    df = None
    try:
        from flow_extractor import pcap_to_flows_with_metadata
        from traffic_filter import is_benign_system_traffic, post_process_prediction
        df, flow_metadata = pcap_to_flows_with_metadata(tmp_path)

        if df.empty:
            # No flows extracted — still run rule-based on raw metadata
            _rule_based_detect(flow_metadata, ts, pcap_device_id)
            return {"status": "ok", "flows": 0, "attacks": {}}

        # ── Flood fast-path ────────────────────────────────────────────
        # hping3 / SYN floods create 1 huge flow (same 5-tuple, 10K+ packets).
        # ML needs ≥5 flows — it will be skipped. Detect the flood directly
        # from the metadata before trying the ML path.
        with history_lock:
            for meta in flow_metadata:
                if is_benign_system_traffic(meta):
                    continue
                pkt_count = meta.get("packet_count", 0)
                src = meta.get("src_ip", "unknown")
                if pkt_count >= 500:
                    print(f"[{ts}] [FLOOD] {src} → {pkt_count} pkts in one flow — fast-path DDoS")
                    attack_counts["DDoS"] = attack_counts.get("DDoS", 0) + 1
                    try:
                        log = ingestion_pipeline.process_network_flow(
                            src_ip=src,
                            dst_ip=meta.get("dst_ip", "0.0.0.0"),
                            src_port=int(meta.get("src_port", 0)),
                            dst_port=int(meta.get("dst_port", 0)),
                            protocol=meta.get("protocol", "TCP"),
                            predicted_label="DDoS",
                            confidence=0.92,
                            flow_features={"flood_packets": pkt_count, "fast_path": True},
                        )
                        triggered = correlation_engine.process_log(log)
                        if triggered:
                            run_async(_save_alerts_to_postgres(triggered, log, pcap_device_id))
                            for a in triggered:
                                traffic_stats.record_alert()
                                print(f"[{ts}] [ALERT] FLOOD: {a.title} | {a.rule.severity}")
                    except Exception as fe:
                        print(f"[!] Flood fast-path error: {fe}")

        # ── Normal ML path ─────────────────────────────────────────────
        results = pred.predict_df_with_scores(df)
        flows_processed = 0

        with history_lock:
            for idx, (label, score) in enumerate(results):
                flow_idx = idx + 4
                if flow_idx >= len(flow_metadata):
                    continue
                flow_info = flow_metadata[flow_idx]

                if is_benign_system_traffic(flow_info):
                    continue

                label, score = post_process_prediction(label, score, flow_info)
                flows_processed += 1

                if label.upper() != "BENIGN":
                    attack_counts[label] = attack_counts.get(label, 0) + 1

                try:
                    unified_log = ingestion_pipeline.process_network_flow(
                        src_ip=flow_info.get("src_ip", "0.0.0.0"),
                        dst_ip=flow_info.get("dst_ip", "0.0.0.0"),
                        src_port=int(flow_info.get("src_port", 0)),
                        dst_port=int(flow_info.get("dst_port", 0)),
                        protocol=flow_info.get("protocol", "TCP"),
                        predicted_label=label,
                        confidence=float(score),
                        flow_features=flow_info,
                    )
                    triggered = correlation_engine.process_log(unified_log)
                    if triggered:
                        run_async(_save_alerts_to_postgres(triggered, unified_log, pcap_device_id))
                        for a in triggered:
                            traffic_stats.record_alert()
                            print(f"[{ts}] [ALERT] REMOTE: {a.title} | {a.rule.severity}")
                except Exception as siem_err:
                    print(f"[!] SIEM error (remote pcap): {siem_err}")

        session_stats["captures"] += 1
        session_stats["flows_processed"] += flows_processed

        if attack_counts:
            print(f"[{ts}] [REMOTE RED] ATTACKS: {attack_counts}")

        # ── Rule-based layer (catches what ML misses) ──────────────────
        _rule_based_detect(flow_metadata, ts, pcap_device_id)

    except Exception as e:
        print(f"[{ts}] [!] Remote pcap processing error: {e}")
        import traceback; traceback.print_exc()
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    return {"status": "ok", "flows": len(df) if df is not None else 0, "attacks": attack_counts}



@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    auth = authenticate_user(form_data.username, form_data.password)
    if not auth:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(form_data.username)
    return {"access_token": access_token, "token_type": "bearer"}



@app.get("/api/stats")
async def get_stats(days: int = Query(7, ge=1, le=30)):
    from sqlalchemy import select, func
    from datetime import timedelta
    from database import Alert as SiemAlert
    try:
        since = datetime.utcnow() - timedelta(days=days)
        async with AsyncSessionLocal() as s:
            total_r  = await s.execute(select(func.count(SiemAlert.id)).where(SiemAlert.created_at >= since))
            type_r   = await s.execute(select(SiemAlert.attack_type, func.count(SiemAlert.id)).where(SiemAlert.created_at >= since).group_by(SiemAlert.attack_type))
        return {"days": days, "total_alerts": total_r.scalar(),
                "by_attack_type": {r[0]: r[1] for r in type_r}}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    from sqlalchemy import select
    from database import Alert as SiemAlert, AlertStatus
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(select(SiemAlert).where(SiemAlert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            alert.status = AlertStatus.INVESTIGATING
            await s.commit()
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/siem/alerts/{alert_id}/block")
async def block_ip_from_alert(alert_id: int):
    from sqlalchemy import select
    from database import Alert as SiemAlert, BlockedIP, AlertStatus
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(select(SiemAlert).where(SiemAlert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            ip = alert.src_ip
            if ip in ("127.0.0.1", "localhost", "0.0.0.0", "multiple", ""):
                raise HTTPException(status_code=400, detail="Cannot block internal/invalid IP")
                
            # Handle duplicate key if already blocked
            existing_block = await s.execute(select(BlockedIP).where(BlockedIP.ip_address == ip))
            if existing_block.scalar_one_or_none():
                return {"success": True, "blocked_ip": ip, "firewall_status": "Already Blocked"}
                
            # Execute Windows Firewall block via reusable helper (admin-aware)
            firewall_ok = _apply_windows_firewall_block(ip)
            firewall_status = "OK" if firewall_ok else (
                "Skipped — restart backend as Administrator to enable Windows Firewall blocking"
                if not _RUNNING_AS_ADMIN else "Failed"
            )

            # Log the action
            block_log = BlockedIP(
                ip_address=ip,
                reason=f"Blocked via Dashboard for Alert #{alert_id} ({alert.attack_type})",
                blocked_by="Analyst",
                alert_id=alert_id
            )
            s.add(block_log)
            alert.status = AlertStatus.INVESTIGATING
            await s.commit()

        return {"success": True, "blocked_ip": ip, "firewall_status": firewall_status}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/siem/alerts/{alert_id}/unblock")
async def unblock_ip_from_alert(alert_id: int):
    from sqlalchemy import select, delete
    from database import Alert as SiemAlert, BlockedIP, AlertStatus
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(select(SiemAlert).where(SiemAlert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            ip = alert.src_ip

            # Execute Windows Firewall unblock (admin-aware)
            if _RUNNING_AS_ADMIN:
                rule_name = _firewall_rule_name(ip)
                cmd = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
                proc = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                print(f"[*] Firewall unblock for {ip}: rc={proc.returncode}")
            else:
                print(f"[!] Firewall unblock skipped (no admin) for {ip}")

            # Remove from BlockedIP table
            await s.execute(delete(BlockedIP).where(BlockedIP.ip_address == ip))
            await s.commit()
            
        return {"success": True, "unblocked_ip": ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/set-threshold")
def set_threshold(threshold: float = Query(..., ge=0.5, le=0.95)):
    try:
        pred.set_confidence_threshold(threshold)
        return {"status": "success", "threshold": threshold}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/set-interface")
def set_interface(interface: str = Query(...)):
    global CAPTURE_INTERFACE
    CAPTURE_INTERFACE = interface.strip()
    print(f"[CONFIG] Capture interface updated to: {CAPTURE_INTERFACE}")
    return {"status": "success", "interface": CAPTURE_INTERFACE}


@app.get("/api/diagnostic")
async def diagnostic():
    from sqlalchemy import select, func
    from database import Alert as SiemAlert
    try:
        n_features  = pred.scaler.n_features_in_
        n_classes   = len(pred.label_encoder.classes_)
        threshold   = pred.confidence_threshold
        async with AsyncSessionLocal() as s:
            count_r = await s.execute(select(func.count(SiemAlert.id)))
            alert_count = count_r.scalar()
        tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        model_info = {
            "expected_features": n_features,
            "num_classes":       n_classes,
            "threshold":         threshold,
        }
        return {
            "status": "operational",
            "model": {"features": n_features, "classes": n_classes, "threshold": threshold},
            "model_info": model_info,
            "model_files": {
                "model":         os.path.exists(os.path.join(MODELS_DIR, "lstm_cicids.pth")),
                "scaler":        os.path.exists(os.path.join(MODELS_DIR, "scaler.pkl")),
                "label_encoder": os.path.exists(os.path.join(MODELS_DIR, "label_encoder.pkl")),
            },
            "tshark_available": os.path.exists(tshark_path),
            "capture_stats": {
                "total_captures":    session_stats.get("captures", 0),
                "total_flows":       session_stats.get("flows_processed", 0),
                "total_predictions": session_stats.get("flows_processed", 0),
                "detection_rate":    {"malicious": int(alert_count)},
            },
            "database": {"total_alerts": alert_count},
            "session": session_stats,
            "interface": CAPTURE_INTERFACE,
            "remote_response": {
                "enabled": _remote_response_enabled(),
                "host": settings.REMOTE_RESPONSE_HOST if settings.REMOTE_RESPONSE_ENABLED else "",
                "user": settings.REMOTE_RESPONSE_USER if settings.REMOTE_RESPONSE_ENABLED else "",
                "backend": settings.REMOTE_RESPONSE_BACKEND if settings.REMOTE_RESPONSE_ENABLED else "",
            },
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/logs")
async def get_logs(
    src_ip: str = Query(None),
    source: str = Query(None),
    event_type: str = Query(None),
    limit: int = Query(200, le=500),
    offset: int = Query(0, ge=0),
    minutes: int = Query(60, ge=1, le=1440),
):
    from sqlalchemy import select, desc
    from database import NormalizedLog
    try:
        async with AsyncSessionLocal() as s:
            stmt = select(NormalizedLog)
            since = datetime.utcnow() - timedelta(minutes=minutes)
            stmt = stmt.where(NormalizedLog.timestamp >= since)
            if src_ip:
                stmt = stmt.where(NormalizedLog.src_ip.ilike(f"%{src_ip}%"))
            if source:
                stmt = stmt.where(NormalizedLog.source == source)
            if event_type:
                stmt = stmt.where(NormalizedLog.event_type.ilike(f"%{event_type}%"))
            stmt = stmt.order_by(desc(NormalizedLog.timestamp)).offset(offset).limit(limit)
            result = await s.execute(stmt)
            logs = result.scalars().all()
        return {
            "logs": [{
                "id": l.id,
                "timestamp": l.timestamp.isoformat() + "Z" if l.timestamp else None,
                "source": str(l.source),
                "src_ip": l.src_ip,
                "dst_ip": l.dst_ip,
                "src_port": l.src_port,
                "dst_port": l.dst_port,
                "protocol": l.protocol,
                "event_type": l.event_type,
                "predicted_label": l.predicted_label,
                "confidence": l.confidence,
                "message": l.message,
                "extra": l.extra or {},
            } for l in logs],
            "total": len(logs),
        }
    except Exception as e:
        return {"error": str(e), "logs": []}


@app.get("/api/siem/alerts/{alert_id}/context")
async def alert_context(alert_id: int):
    """Return related alerts + raw logs from same source IP for investigation."""
    from sqlalchemy import select, desc
    from database import Alert as SiemAlert, NormalizedLog
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(select(SiemAlert).where(SiemAlert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            src_ip = alert.src_ip
            rel_alerts_r = await s.execute(
                select(SiemAlert)
                .where(SiemAlert.src_ip == src_ip)
                .order_by(SiemAlert.created_at)
                .limit(50)
            )
            related_alerts = rel_alerts_r.scalars().all()
            rel_logs_r = await s.execute(
                select(NormalizedLog)
                .where(NormalizedLog.src_ip == src_ip)
                .order_by(desc(NormalizedLog.timestamp))
                .limit(100)
            )
            related_logs = rel_logs_r.scalars().all()
        return {
            "alert_id": alert_id,
            "src_ip": src_ip,
            "related_alerts": [{
                "id": a.id,
                "title": a.title,
                "severity": str(a.severity),
                "attack_type": a.attack_type,
                "confidence": a.confidence,
                "mitre_technique_id": a.mitre_technique_id,
                "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
            } for a in related_alerts],
            "related_logs": [{
                "id": l.id,
                "timestamp": l.timestamp.isoformat() + "Z" if l.timestamp else None,
                "source": str(l.source),
                "src_ip": l.src_ip,
                "dst_ip": l.dst_ip,
                "src_port": l.src_port,
                "dst_port": l.dst_port,
                "protocol": l.protocol,
                "event_type": l.event_type,
                "predicted_label": l.predicted_label,
                "confidence": l.confidence,
                "message": l.message,
            } for l in related_logs],
        }
    except HTTPException:
        raise
    except Exception as e:
        return {"error": str(e), "related_alerts": [], "related_logs": []}



@app.post("/api/active-defense/flush-all")
async def flush_all_blocks():
    """
    Remove every active ban: memory, DB, Windows Firewall, Ubuntu iptables.
    Equivalent to 'iptables -F INPUT' on Ubuntu + clearing all local state.
    """
    from sqlalchemy import delete as sa_delete
    from database import BlockedIP

    # 1. Clear in-memory bans (both IP and UA)
    with active_defense._lock:
        banned_ips = list(active_defense._ip_bans.keys())
        active_defense._ip_bans.clear()
        active_defense._ua_bans.clear()

    # 2. Trigger unban callbacks so Ubuntu iptables rules are removed individually
    for ip in banned_ips:
        try:
            _run_remote_ubuntu_firewall_action(ip, "unban")
        except Exception:
            pass

    # 3. Flush entire INPUT chain on Ubuntu (catch anything we missed)
    ubuntu_flushed = False
    try:
        ubuntu_flushed = _run_remote_ubuntu_flush()
    except Exception as e:
        print(f"[!] Remote flush failed: {e}")

    # 4. Remove all Windows Firewall rules created by SentinelIQ
    win_cleared = False
    if _RUNNING_AS_ADMIN:
        try:
            cmd = 'Get-NetFirewallRule -DisplayName "SentinelIQ Auto Block*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue'
            subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, timeout=15)
            win_cleared = True
        except Exception as e:
            print(f"[!] Windows firewall flush failed: {e}")

    # 5. Clear BlockedIP table in DB
    async with AsyncSessionLocal() as s:
        await s.execute(sa_delete(BlockedIP))
        await s.commit()

    print(f"[ACTIVE DEFENSE] FLUSH ALL — {len(banned_ips)} bans cleared | ubuntu={ubuntu_flushed} | win={win_cleared}")
    return {
        "success": True,
        "bans_cleared": len(banned_ips),
        "ubuntu_iptables_flushed": ubuntu_flushed,
        "windows_firewall_cleared": win_cleared,
    }


@app.post("/api/active-defense/flush-device")
async def flush_device_blocks(device_id: str = Query(...)):
    """
    Flush active bans for a specific device.
    device_id="__all__"     → same as flush-all
    device_id="__windows__" → Windows Firewall only (no Ubuntu SSH)
    device_id="<name>"      → remove bans that belong to that device's alerts
                              + remote iptables flush if SSH is configured for it
    """
    from sqlalchemy import select as sa_select, delete as sa_delete
    from database import BlockedIP, Alert as SiemAlert

    if device_id == "__all__":
        return await flush_all_blocks()

    # Collect IPs that fired alerts on this device
    async with AsyncSessionLocal() as s:
        if device_id == "__windows__":
            # All currently banned IPs (we only touch Windows Firewall)
            result = await s.execute(sa_select(BlockedIP.ip_address))
            target_ips = [r[0] for r in result.all()]
        else:
            result = await s.execute(
                sa_select(SiemAlert.src_ip)
                .where(SiemAlert.device_id == device_id)
                .distinct()
            )
            target_ips = [r[0] for r in result.all() if r[0]]

    cleared_win = 0
    cleared_ubuntu = 0

    for ip in target_ips:
        # Remove from in-memory ban cache
        active_defense.unban_ip(ip)

        # Remove Windows Firewall rule (must use same name pattern as _apply_windows_firewall_block)
        if _RUNNING_AS_ADMIN:
            try:
                rule_name = _firewall_rule_name(ip)
                subprocess.run(
                    ["powershell", "-Command",
                     f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'],
                    capture_output=True, text=True, timeout=10
                )
                cleared_win += 1
            except Exception:
                pass

        # Remote iptables unban — only when this device matches the configured SSH host
        if device_id != "__windows__" and _remote_response_enabled():
            try:
                _run_remote_ubuntu_firewall_action(ip, "unban")
                cleared_ubuntu += 1
            except Exception:
                pass

    # Remove from BlockedIP table
    async with AsyncSessionLocal() as s:
        if device_id == "__windows__":
            await s.execute(sa_delete(BlockedIP))
        else:
            from sqlalchemy import and_
            await s.execute(
                sa_delete(BlockedIP).where(BlockedIP.ip_address.in_(target_ips))
            )
        await s.commit()

    print(f"[ACTIVE DEFENSE] FLUSH [{device_id}] — {len(target_ips)} IPs | win={cleared_win} | ubuntu={cleared_ubuntu}")
    return {
        "success": True,
        "device_id": device_id,
        "ips_cleared": len(target_ips),
        "windows_firewall_cleared": cleared_win,
        "ubuntu_iptables_cleared": cleared_ubuntu,
    }


@app.get("/api/active-defense/device-states")
async def get_device_defense_states():
    """Return global + per-device active defense toggle states."""
    from sqlalchemy import select as sa_select
    from database import Alert as SiemAlert

    # Collect distinct device_ids that have ever sent alerts
    async with AsyncSessionLocal() as s:
        result = await s.execute(
            sa_select(SiemAlert.device_id).distinct()
        )
        db_devices = [r[0] for r in result.all() if r[0]]

    # Merge with in-memory overrides
    all_devices = sorted(set(db_devices) | set(_device_defense_enabled.keys()))
    return {
        "global": _active_defense_on,
        "devices": [
            {
                "device_id": d,
                "enabled": _device_defense_enabled.get(d, True),
                "inherits_global": d not in _device_defense_enabled,
            }
            for d in all_devices
        ],
    }


@app.post("/api/active-defense/toggle-device")
async def toggle_device_defense(device_id: str = Query(...), enabled: bool = Query(...)):
    """Enable or disable active defense for a specific device."""
    global _device_defense_enabled
    if device_id == "__global__":
        global _active_defense_on
        _active_defense_on = enabled
        print(f"[ACTIVE DEFENSE] GLOBAL → {'ENABLED' if enabled else 'DISABLED'}")
        return {"device_id": "__global__", "enabled": _active_defense_on}

    _device_defense_enabled[device_id] = enabled
    print(f"[ACTIVE DEFENSE] [{device_id}] → {'ENABLED' if enabled else 'DISABLED'}")
    return {"device_id": device_id, "enabled": enabled}



@app.get("/api/active-defense/bans")
async def active_defense_bans():
    """List all currently active bans."""
    return {"bans": active_defense.get_active_bans()}



@app.get("/api/kill-switch/status")
async def kill_switch_status():
    """Current kill switch configuration and audit trail."""
    return {
        "enabled": settings.KILL_SWITCH_ENABLED,
        "action":  settings.KILL_SWITCH_ACTION,
        "target":  settings.REMOTE_RESPONSE_HOST or None,
        "armed_for_rules": list(KILL_SWITCH_RULE_IDS),
        "audit_log": ks_log(),
    }


@app.post("/api/kill-switch/test")
async def kill_switch_test(
    action: str = Query("isolate", regex="^(isolate|shutdown)$"),
):
    """
    Manually trigger the kill switch for demo/testing purposes.
    Requires KILL_SWITCH_ENABLED=True and REMOTE_RESPONSE_HOST configured.
    """
    if not settings.KILL_SWITCH_ENABLED:
        raise HTTPException(status_code=403,
                            detail="Kill switch is disabled. Set KILL_SWITCH_ENABLED=True in .env")
    if not settings.REMOTE_RESPONSE_HOST:
        raise HTTPException(status_code=400,
                            detail="No target configured. Set REMOTE_RESPONSE_HOST in .env")
    ks_trigger(
        action=action,
        host=settings.REMOTE_RESPONSE_HOST,
        user=settings.REMOTE_RESPONSE_USER,
        port=settings.REMOTE_RESPONSE_PORT,
        identity_file=settings.REMOTE_RESPONSE_IDENTITY_FILE or None,
        use_sudo=settings.REMOTE_RESPONSE_USE_SUDO,
        reason="Manual test via API",
    )
    return {"status": "dispatched", "action": action, "target": settings.REMOTE_RESPONSE_HOST}


@app.post("/api/kill-switch/lift")
async def kill_switch_lift():
    """Restore normal iptables policies after an isolation (analyst override)."""
    if not settings.REMOTE_RESPONSE_HOST:
        raise HTTPException(status_code=400, detail="No target configured")
    ok = lift_isolation(
        host=settings.REMOTE_RESPONSE_HOST,
        user=settings.REMOTE_RESPONSE_USER,
        port=settings.REMOTE_RESPONSE_PORT,
        identity_file=settings.REMOTE_RESPONSE_IDENTITY_FILE or None,
        use_sudo=settings.REMOTE_RESPONSE_USE_SUDO,
    )
    return {"success": ok, "target": settings.REMOTE_RESPONSE_HOST}


@app.post("/api/kill-switch/simulate")
async def kill_switch_simulate():
    """
    Inject a fake ransomware log to trigger the full detection pipeline
    without a real attack — useful for demo/PFE presentations.
    """
    import json as _json
    fake_log = _json.dumps({
        "EventID": 4688,
        "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
        "CommandLine": "vssadmin delete shadows /all /quiet",
        "SubjectUserName": "SYSTEM",
        "IpAddress": "127.0.0.1",
    })
    from core.log_collector import LogParser as _LP
    ev = _LP().parse("windows", fake_log)
    if not ev:
        raise HTTPException(status_code=500, detail="Simulation log parse failed")
    fired = await _evaluate_and_save_log_event(ev)
    return {
        "status": "simulated",
        "event_type": ev.event_type,
        "alert_fired": fired,
        "kill_switch_would_fire": settings.KILL_SWITCH_ENABLED,
    }


@app.get("/")
def root():
    return {"name": "SentinelIQ", "version": "5.0", "status": "running"}


# =============================================================================
# START BACKGROUND THREADS
# =============================================================================

if settings.CAPTURE_ENABLED:
    Thread(target=capture_thread, daemon=True).start()
    Thread(target=process_thread,  daemon=True).start()
else:
    print("[*] Local PCAP capture DISABLED (CAPTURE_ENABLED=False) — using remote forwarder only")

print(f"[*] Dashboard: http://localhost:3000")
print("-" * 60)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
