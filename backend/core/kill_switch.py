"""
SentinelIQ — Kill Switch Engine
================================
Radical remediation triggered on confirmed ransomware behaviour
(Volume Shadow Copy deletion, mass-encryption pattern, backup wipe).

Two actions (KILL_SWITCH_ACTION in .env):
  isolate  — DROP all iptables traffic; machine stays up for forensics
  shutdown — Full power-off; stops spread but prevents live forensics

SSH credentials are reused from REMOTE_RESPONSE_* settings.
"""

import subprocess
import threading
import time
from datetime import datetime
from typing import Optional


# ── In-memory audit log (survives the backend process, not the reboot) ────────
_log_lock = threading.Lock()
_audit_log: list[dict] = []


def _record(action: str, host: str, reason: str, success: bool, detail: str = ""):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "host": host,
        "reason": reason,
        "success": success,
        "detail": detail,
    }
    with _log_lock:
        _audit_log.append(entry)
    status = "✅" if success else "❌"
    print(f"\n{'!'*60}")
    print(f"[KILL SWITCH] {status} {action.upper()} | host={host}")
    print(f"[KILL SWITCH] reason: {reason}")
    if detail:
        print(f"[KILL SWITCH] detail: {detail}")
    print(f"{'!'*60}\n")


def get_audit_log() -> list[dict]:
    with _log_lock:
        return list(_audit_log)


# ── SSH helper ─────────────────────────────────────────────────────────────────
def _ssh(host: str, user: str, port: int,
         identity_file: Optional[str], command: str) -> tuple[bool, str]:
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=5",
        "-p", str(port),
    ]
    if identity_file:
        cmd += ["-i", identity_file]
    cmd += [f"{user}@{host}", command]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = (proc.stdout + proc.stderr).strip()
        return proc.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "SSH timeout"
    except Exception as e:
        return False, str(e)


# ── Kill Switch actions ────────────────────────────────────────────────────────

def isolate_host(host: str, user: str, port: int = 22,
                 identity_file: Optional[str] = None,
                 use_sudo: bool = True,
                 reason: str = "Ransomware detected") -> bool:
    """
    Block ALL network traffic on the remote host via iptables.
    Keeps the machine running so memory/disk can be imaged for forensics.
    One SSH rule is preserved so the analyst can still connect.
    """
    sudo = "sudo -n " if use_sudo else ""
    # Order matters: allow SSH first, then set DROP policies
    cmd = (
        f"{sudo}bash -c '"
        f"iptables -I INPUT  1 -p tcp --dport {port} -j ACCEPT 2>/dev/null; "
        f"iptables -I OUTPUT 1 -p tcp --sport {port} -j ACCEPT 2>/dev/null; "
        f"iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; "
        f"iptables -P INPUT   DROP; "
        f"iptables -P OUTPUT  DROP; "
        f"iptables -P FORWARD DROP"
        f"'"
    )
    ok, detail = _ssh(host, user, port, identity_file, cmd)
    _record("isolate", host, reason, ok, detail)
    return ok


def shutdown_host(host: str, user: str, port: int = 22,
                  identity_file: Optional[str] = None,
                  use_sudo: bool = True,
                  reason: str = "Ransomware confirmed — emergency shutdown") -> bool:
    """
    Immediately power off the remote host.
    Most radical option — stops encryption spread at the cost of live forensics.
    """
    sudo = "sudo -n " if use_sudo else ""
    ok, detail = _ssh(host, user, port, identity_file, f"{sudo}shutdown -h now")
    _record("shutdown", host, reason, ok, detail)
    return ok


def lift_isolation(host: str, user: str, port: int = 22,
                   identity_file: Optional[str] = None,
                   use_sudo: bool = True) -> bool:
    """Restore default ACCEPT policies after isolation (analyst override)."""
    sudo = "sudo -n " if use_sudo else ""
    cmd = (
        f"{sudo}bash -c '"
        f"iptables -P INPUT   ACCEPT; "
        f"iptables -P OUTPUT  ACCEPT; "
        f"iptables -P FORWARD ACCEPT"
        f"'"
    )
    ok, detail = _ssh(host, user, port, identity_file, cmd)
    _record("lift_isolation", host, "Manual analyst override", ok, detail)
    return ok


# ── Main dispatcher ────────────────────────────────────────────────────────────

def trigger(action: str, host: str, user: str, port: int = 22,
            identity_file: Optional[str] = None,
            use_sudo: bool = True,
            reason: str = "Ransomware detected") -> bool:
    """
    Called by main.py when a ransomware rule fires.
    Runs in a daemon thread so it never blocks alert persistence.
    """
    def _run():
        if action == "shutdown":
            shutdown_host(host, user, port, identity_file, use_sudo, reason)
        else:
            isolate_host(host, user, port, identity_file, use_sudo, reason)

    t = threading.Thread(target=_run, daemon=True, name="kill-switch")
    t.start()
    print(f"[KILL SWITCH] Dispatched '{action}' against {host} (thread started)")
    return True
