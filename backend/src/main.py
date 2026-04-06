# main.py - SentinelIQ SIEM Backend
import os
import sys
import subprocess
import time
import json
import queue
from datetime import datetime
from threading import Thread, Lock
from collections import Counter, defaultdict

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
from core.mitre import get_mitre_mapping

# ── Paths ────────────────────────────────────────────────────
_PROJECT_ROOT   = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODELS_DIR      = os.path.join(_PROJECT_ROOT, "backend", "models")
_DATA_DIR       = os.path.join(_PROJECT_ROOT, "data")
PCAP_PATH       = os.path.join(_DATA_DIR, "live_traffic.pcap")
CAPTURE_INTERFACE = os.getenv("NETWORK_INTERFACE", "2")
CAPTURE_DURATION  = 5    # seconds — reduced for faster detection
CAPTURE_COOLDOWN  = 0    # no pause between captures

# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(title="SentinelIQ", version="5.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

import asyncio
main_loop = None

@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()
    await init_db()
    print("✅ PostgreSQL initialisé (async on uvicorn loop)")

def run_async(coro):
    """Submit a coroutine to the uvicorn event loop from any background thread."""
    if main_loop and main_loop.is_running():
        return asyncio.run_coroutine_threadsafe(coro, main_loop)
    else:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(coro)

# ── Predictor ─────────────────────────────────────────────────
pred = Predictor(MODELS_DIR, confidence_threshold=0.85)

# ── Global state ──────────────────────────────────────────────
history_lock    = Lock()
sequence_counter = 0
traffic_stats   = TrafficStats()
session_stats   = {
    "session_start": datetime.now().isoformat(),
    "captures": 0,
    "flows_processed": 0,
}

# ── Parallel capture queue ────────────────────────────────────
_pcap_queue = queue.Queue(maxsize=3)


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
                "-w", pcap_file,
            ], check=True, timeout=CAPTURE_DURATION + 5, capture_output=True)

            if not _pcap_queue.full():
                _pcap_queue.put(pcap_file)
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


def _process_pcap(pcap_file: str):
    """Core processing: extract flows → predict → correlate → save."""
    global sequence_counter
    timestamp = datetime.now().strftime("%H:%M:%S")

    if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) == 0:
        return

    try:
        df, flow_metadata = pcap_to_flows_with_metadata(pcap_file)
        if df.empty:
            return

        results = pred.predict_df_with_scores(df)
        if not results:
            return

        prediction_counts = Counter()

        with history_lock:
            for idx, (label, score) in enumerate(results):
                sequence_counter += 1

                if idx >= len(flow_metadata):
                    continue
                flow_info = flow_metadata[idx]

                if is_benign_system_traffic(flow_info):
                    traffic_stats.record_flow(filtered=True)
                    continue

                traffic_stats.record_flow(filtered=False)
                label, score = post_process_prediction(label, score, flow_info)
                prediction_counts[label] += 1

                # ── ML path → SIEM correlation ───────────────
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
                        run_async(_save_alerts_to_postgres(triggered, unified_log))
                        for a in triggered:
                            traffic_stats.record_alert()
                            print(f"[{timestamp}] 🚨 SIEM: {a.title} | {a.mitre_technique_id} | {a.rule.severity}")
                    elif label.upper() != "BENIGN":
                        traffic_stats.record_false_positive_prevented()

                except Exception as siem_err:
                    print(f"[!] SIEM error (non-fatal): {siem_err}")
                    if should_generate_alert(label, score, flow_info):
                        traffic_stats.record_alert()

            session_stats["captures"] += 1
            session_stats["flows_processed"] += len(df)

        if prediction_counts:
            print(f"[{timestamp}] 📊 {len(results)} flows → {dict(prediction_counts)}")

        # ── Rule-based layer (catches what ML misses) ────────
        _rule_based_detect(flow_metadata, timestamp)

    except Exception as e:
        print(f"[{timestamp}] ❌ Processing error: {e}")
        import traceback; traceback.print_exc()


# =============================================================================
# ASYNC DB SAVE
# =============================================================================

async def _save_alerts_to_postgres(triggered_alerts, unified_log):
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
        await db_session.flush()

        for alert_data in triggered_alerts:
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
                raw_log_id=db_log.id,
            )
            db_session.add(db_alert)

        await db_session.commit()


# =============================================================================
# RULE-BASED DETECTION LAYER
# =============================================================================

from collections import defaultdict as _dd

_rb_state = {
    "dst_ports_per_src": _dd(set),
    "ssh_attempts":      _dd(int),
    "ftp_attempts":      _dd(int),
    "bot_ports":         _dd(int),
    "http_reqs":         _dd(int),
    "last_alert":        _dd(float),
}
_RB_COOLDOWN = 30


def _rb_can_alert(key: str) -> bool:
    now = time.time()
    if now - _rb_state["last_alert"][key] > _RB_COOLDOWN:
        _rb_state["last_alert"][key] = now
        return True
    return False


def _rule_based_detect(flow_metadata: list, ts: str):
    C2_PORTS = {6667, 6668, 6669, 4444, 8080, 9090, 1080, 5555, 31337}

    local_ports = _dd(set)
    ssh_hits = _dd(int)
    ftp_hits = _dd(int)
    bot_hits = _dd(int)
    http_hits = _dd(int)

    for fl in flow_metadata:
        src   = fl.get("src_ip", "")
        dst   = fl.get("dst_ip", "")
        dport = int(fl.get("dst_port", 0))
        proto = fl.get("protocol", "TCP")

        local_ports[src].add(dport)
        if dport == 22:  ssh_hits[src]  += 1
        if dport == 21:  ftp_hits[src]  += 1
        if dport in C2_PORTS: bot_hits[src] += 1
        if dport == 80 and proto == "TCP": http_hits[dst] += 1

    for src, ports in local_ports.items():
        _rb_state["dst_ports_per_src"][src] |= ports
    for src, n in ssh_hits.items():  _rb_state["ssh_attempts"][src] += n
    for src, n in ftp_hits.items():  _rb_state["ftp_attempts"][src] += n
    for src, n in bot_hits.items():  _rb_state["bot_ports"][src]    += n
    for dst, n in http_hits.items(): _rb_state["http_reqs"][dst]    += n

    rb_alerts = []

    for src, ports in list(_rb_state["dst_ports_per_src"].items()):
        if len(ports) >= 30 and _rb_can_alert(f"portscan:{src}"):
            rb_alerts.append({"title": f"Port Scan from {src}", "attack_type": "PortScan",
                               "severity": "MEDIUM", "src_ip": src, "confidence": 0.91,
                               "mitre_technique_id": "T1046", "mitre_tactic": "Reconnaissance",
                               "mitre_technique_name": "Network Service Discovery"})
            _rb_state["dst_ports_per_src"][src].clear()

    for src, n in list(_rb_state["ssh_attempts"].items()):
        if n >= 10 and _rb_can_alert(f"ssh:{src}"):
            rb_alerts.append({"title": f"SSH Brute Force from {src} ({n} attempts)",
                               "attack_type": "SSH-Patator", "severity": "HIGH", "src_ip": src,
                               "confidence": 0.89, "mitre_technique_id": "T1110",
                               "mitre_tactic": "Credential Access", "mitre_technique_name": "Brute Force"})
            _rb_state["ssh_attempts"][src] = 0

    for src, n in list(_rb_state["ftp_attempts"].items()):
        if n >= 10 and _rb_can_alert(f"ftp:{src}"):
            rb_alerts.append({"title": f"FTP Brute Force from {src} ({n} attempts)",
                               "attack_type": "FTP-Patator", "severity": "HIGH", "src_ip": src,
                               "confidence": 0.87, "mitre_technique_id": "T1110",
                               "mitre_tactic": "Credential Access", "mitre_technique_name": "Brute Force"})
            _rb_state["ftp_attempts"][src] = 0

    for src, n in list(_rb_state["bot_ports"].items()):
        if n >= 5 and _rb_can_alert(f"bot:{src}"):
            rb_alerts.append({"title": f"Botnet C&C Activity from {src}", "attack_type": "Bot",
                               "severity": "HIGH", "src_ip": src, "confidence": 0.85,
                               "mitre_technique_id": "T1071", "mitre_tactic": "Command and Control",
                               "mitre_technique_name": "Application Layer Protocol"})
            _rb_state["bot_ports"][src] = 0

    for dst, n in list(_rb_state["http_reqs"].items()):
        if n >= 50 and _rb_can_alert(f"hulk:{dst}"):
            rb_alerts.append({"title": f"DoS HTTP Flood against {dst} ({n} requests)",
                               "attack_type": "DoS Hulk", "severity": "CRITICAL", "src_ip": "multiple",
                               "confidence": 0.93, "mitre_technique_id": "T1499",
                               "mitre_tactic": "Impact", "mitre_technique_name": "Endpoint Denial of Service"})
            _rb_state["http_reqs"][dst] = 0

    if not rb_alerts:
        return

    async def _save_rb():
        from database import AlertStatus
        from datetime import datetime as _dt
        try:
            async with AsyncSessionLocal() as session:
                sev_map = {"LOW": SeverityLevel.LOW, "MEDIUM": SeverityLevel.MEDIUM,
                           "HIGH": SeverityLevel.HIGH, "CRITICAL": SeverityLevel.CRITICAL}
                for a in rb_alerts:
                    row = Alert(
                        title=a["title"],
                        severity=sev_map.get(a["severity"], SeverityLevel.MEDIUM),
                        attack_type=a["attack_type"],
                        src_ip=a["src_ip"], dst_ip="",
                        confidence=a["confidence"],
                        mitre_technique_id=a["mitre_technique_id"],
                        mitre_tactic=a.get("mitre_tactic", ""),
                        mitre_technique_name=a.get("mitre_technique_name", ""),
                        status=AlertStatus.NEW,       # ← fixed: was OPEN
                        is_known_malicious=False,
                        created_at=_dt.utcnow(),
                    )
                    session.add(row)
                    traffic_stats.record_alert()
                    print(f"[{ts}] 🚨 RB-ALERT: {a['title']} | {a['severity']}")
                await session.commit()
        except Exception as e:
            print(f"[!] RB alert save error: {e}")

    # run_async expects a coroutine object, not a function
    run_async(_save_rb())


# =============================================================================
# LOG INGESTION — single implementation using _log_parser
# =============================================================================

# Lazy import to avoid circular issues
try:
    from core.log_collector import LogParser as _LogParser
    _log_parser = _LogParser()
except Exception:
    _log_parser = None

_log_source_stats: dict = defaultdict(lambda: {"received": 0, "alerts_fired": 0, "last_seen": None})
_log_throttle: dict = defaultdict(float)
_LOG_THROTTLE_S = 10


def _log_can_alert(key: str) -> bool:
    now = time.time()
    if now - _log_throttle[key] > _LOG_THROTTLE_S:
        _log_throttle[key] = now
        return True
    return False


LOG_RULES = {
    "ssh_failed_login":     ("SSH-Patator",   "HIGH",     "Brute Force SSH Login from {src}",     "T1110", "Credential Access",     "Brute Force"),
    "auth_root_login":      ("SSH-Patator",   "CRITICAL", "Root Login Attempt from {src}",         "T1078", "Initial Access",        "Valid Accounts"),
    "sudo_privilege_esc":   ("PrivilegeEsc",  "HIGH",     "Sudo Privilege Escalation by {user}",  "T1548", "Privilege Escalation",  "Abuse Elevation Control Mechanism"),
    "ssh_invalid_user":     ("SSH-Patator",   "MEDIUM",   "SSH Invalid User Probe from {src}",    "T1110", "Credential Access",     "Brute Force"),
    "nginx_sql_injection":  ("Web Attack",    "CRITICAL", "SQL Injection from {src}",             "T1190", "Initial Access",        "Exploit Public-Facing Application"),
    "nginx_xss_attempt":    ("Web Attack",    "HIGH",     "XSS Attempt from {src}",               "T1190", "Initial Access",        "Exploit Public-Facing Application"),
    "nginx_path_traversal": ("Web Attack",    "HIGH",     "Path Traversal from {src}",            "T1083", "Discovery",             "File and Directory Discovery"),
    "nginx_4xx":            ("Web Scanner",   "MEDIUM",   "Web Scan/Probe from {src}",            "T1595", "Reconnaissance",        "Active Scanning"),
    "nginx_5xx":            ("DoS",           "HIGH",     "Server Error Spike from {src}",        "T1499", "Impact",                "Endpoint Denial of Service"),
    "auth_failed_login":    ("Auth Brute",    "HIGH",     "Windows Login Failure from {src}",     "T1110", "Credential Access",     "Brute Force"),
    "account_created":      ("Persistence",   "HIGH",     "New User Account Created",             "T1136", "Persistence",           "Create Account"),
    "audit_cleared":        ("Defense Evasion","CRITICAL","Audit Log Cleared",                    "T1070", "Defense Evasion",       "Indicator Removal"),
    "service_installed":    ("Persistence",   "HIGH",     "New Service Installed",                "T1543", "Persistence",           "Create or Modify System Process"),
    "syslog_security_event":("Syslog",        "MEDIUM",   "Security Event: {msg}",               "T1059", "Execution",             "Command and Scripting Interpreter"),
}


async def _evaluate_and_save_log_event(event) -> bool:
    from database import AlertStatus
    from datetime import datetime as _dt

    rule = LOG_RULES.get(event.event_type)
    if not rule:
        return False

    attack_type, sev_str, title_tpl, mitre_id, mitre_tactic, mitre_name = rule

    throttle_key = f"{event.event_type}:{event.src_ip}"
    if not _log_can_alert(throttle_key):
        return False

    title = title_tpl.format(
        src=event.src_ip,
        user=event.username or "unknown",
        msg=(event.message or "")[:60],
    )

    sev_map = {"LOW": SeverityLevel.LOW, "MEDIUM": SeverityLevel.MEDIUM,
               "HIGH": SeverityLevel.HIGH, "CRITICAL": SeverityLevel.CRITICAL}

    try:
        async with AsyncSessionLocal() as session:
            row = Alert(
                title=title,
                severity=sev_map.get(sev_str, SeverityLevel.MEDIUM),
                attack_type=attack_type,
                src_ip=event.src_ip,
                dst_ip=getattr(event, "dst_ip", "") or "",
                confidence=0.95,
                mitre_technique_id=mitre_id,
                mitre_tactic=mitre_tactic,
                mitre_technique_name=mitre_name,
                status=AlertStatus.NEW,       # ← fixed: was OPEN
                is_known_malicious=False,
                created_at=_dt.utcnow(),
            )
            session.add(row)
            await session.commit()

        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🪵 LOG ALERT: {title} | {sev_str}")
        traffic_stats.record_alert()
        _log_source_stats[event.source_type]["alerts_fired"] += 1
        return True

    except Exception as e:
        print(f"[!] Log alert save error: {e}")
        return False


# ── Pydantic models for log ingestion ────────────────────────

class LogEntry(PydanticBase):
    source: str
    raw: str

class BulkLogRequest(PydanticBase):
    logs: list[LogEntry]


@app.post("/api/logs/ingest")
async def ingest_log(entry: LogEntry):
    """Ingest a single log line."""
    source = entry.source
    raw    = entry.raw.strip()
    if not raw:
        return {"status": "skipped", "reason": "empty"}

    _log_source_stats[source]["received"] += 1
    _log_source_stats[source]["last_seen"] = datetime.utcnow().isoformat()

    if _log_parser is None:
        return {"status": "error", "reason": "log_parser not available"}

    event = _log_parser.parse(source=source, raw=raw)
    if not event:
        return {"status": "skipped", "reason": "unrecognized or benign"}

    fired = await _evaluate_and_save_log_event(event)
    return {
        "status": "alert_fired" if fired else "ingested",
        "event_type": event.event_type,
        "src_ip": event.src_ip,
    }


@app.post("/api/logs/ingest/bulk")
async def ingest_bulk(request: BulkLogRequest):
    """Ingest multiple log lines at once."""
    results = {"received": len(request.logs), "parsed": 0, "alerts_fired": 0, "skipped": 0}

    if _log_parser is None:
        return {"status": "error", "reason": "log_parser not available"}

    # Parse all lines
    parsed_events = []
    for entry in request.logs:
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

    # Deduplicate: one alert per (event_type, src_ip)
    seen: dict = {}
    for ev in parsed_events:
        key = (ev.event_type, ev.src_ip)
        if key not in seen:
            seen[key] = ev

    # Evaluate
    for ev in seen.values():
        if await _evaluate_and_save_log_event(ev):
            results["alerts_fired"] += 1

    return {"status": "ok", **results}


@app.get("/api/logs/sources")
async def log_sources():
    return {
        "sources": [{"source": src, **stats} for src, stats in _log_source_stats.items()],
        "endpoints": {"single": "POST /api/logs/ingest", "bulk": "POST /api/logs/ingest/bulk"},
    }


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/api/siem/alerts")
async def siem_alerts(limit: int = Query(50, le=500)):
    from sqlalchemy import select, desc
    from database import Alert as SiemAlert
    try:
        async with AsyncSessionLocal() as s:
            result = await s.execute(
                select(SiemAlert).order_by(desc(SiemAlert.id)).limit(limit)
            )
            alerts = result.scalars().all()
        return {
            "alerts": [{
                "id": a.id, "title": a.title, "severity": str(a.severity),
                "src_ip": a.src_ip, "attack_type": a.attack_type, "confidence": a.confidence,
                "mitre_tactic": a.mitre_tactic, "mitre_technique_id": a.mitre_technique_id,
                "mitre_technique_name": a.mitre_technique_name,
                "is_known_malicious": a.is_known_malicious,
                "ip_country": a.ip_country, "ip_abuse_score": a.ip_abuse_score,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            } for a in alerts],
            "total": len(alerts),
        }
    except Exception as e:
        return {"error": str(e), "alerts": []}


@app.get("/api/siem/dashboard")
async def siem_dashboard():
    from sqlalchemy import select, func, desc
    from datetime import timedelta
    from database import Alert as SiemAlert
    try:
        since = datetime.utcnow() - timedelta(hours=24)
        async with AsyncSessionLocal() as s:
            total_r      = await s.execute(select(func.count(SiemAlert.id)).where(SiemAlert.created_at >= since))
            severity_r   = await s.execute(select(SiemAlert.severity, func.count(SiemAlert.id)).where(SiemAlert.created_at >= since).group_by(SiemAlert.severity))
            tactic_r     = await s.execute(select(SiemAlert.mitre_tactic, func.count(SiemAlert.id)).where(SiemAlert.created_at >= since).group_by(SiemAlert.mitre_tactic).order_by(desc(func.count(SiemAlert.id))))
            top_ips_r    = await s.execute(select(SiemAlert.src_ip, func.count(SiemAlert.id)).where(SiemAlert.created_at >= since).group_by(SiemAlert.src_ip).order_by(desc(func.count(SiemAlert.id))).limit(10))
        return {
            "total_alerts_24h": total_r.scalar(),
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
                        "created_at": a.created_at.isoformat() if a.created_at else None}
                       for a in alerts],
            "total": len(alerts),
        }
    except Exception as e:
        return {"error": str(e)}


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
            alert.status = AlertStatus.RESOLVED
            await s.commit()
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/set-threshold")
def set_threshold(threshold: float = Query(..., ge=0.5, le=0.95)):
    try:
        pred.set_confidence_threshold(threshold)
        return {"status": "success", "threshold": threshold}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/diagnostic")
async def diagnostic():
    from sqlalchemy import select, func
    from database import Alert as SiemAlert
    try:
        import joblib
        scaler        = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
        label_encoder = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        async with AsyncSessionLocal() as s:
            count_r = await s.execute(select(func.count(SiemAlert.id)))
            alert_count = count_r.scalar()
        return {
            "status": "operational",
            "model": {"features": scaler.n_features_in_,
                      "classes": len(label_encoder.classes_),
                      "threshold": pred.confidence_threshold},
            "database": {"total_alerts": alert_count},
            "session": session_stats,
            "interface": CAPTURE_INTERFACE,
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/")
def root():
    return {"name": "SentinelIQ", "version": "5.0", "status": "running"}


# =============================================================================
# START BACKGROUND THREADS
# =============================================================================

Thread(target=capture_thread, daemon=True).start()
Thread(target=process_thread,  daemon=True).start()

print(f"[*] Dashboard: http://localhost:3000")
print("-" * 60)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)