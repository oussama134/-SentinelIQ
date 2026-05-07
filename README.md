<div align="center">

# SentinelIQ

### An autonomous, full-stack SIEM built from scratch
### ML threat detection · real-time correlation · active response · kill switch

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-LSTM-EE4C2C?style=flat&logo=pytorch&logoColor=white)](https://pytorch.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)](https://reactjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-asyncpg-336791?style=flat&logo=postgresql&logoColor=white)](https://postgresql.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=flat)](https://attack.mitre.org)

</div>

---

## What is this?

SentinelIQ is a Security Information and Event Management system built entirely from scratch — no Elastic, no Splunk, no pre-built detection libraries. It captures live network traffic, ingests Linux system logs from remote machines, runs everything through a trained LSTM model and a 31-rule correlation engine, enriches every alert with MITRE ATT&CK mappings and real-time threat intelligence, and automatically blocks attackers on both the local Windows firewall and a remote Linux host over SSH.

When ransomware is confirmed, it can network-isolate or shut down the victim machine before encryption spreads.

---

## Detection Pipeline

```
 NETWORK PATH                            LOG PATH
 ────────────────────────────            ──────────────────────────────────────
 tshark captures live traffic            ubuntu_forwarder.py tails log files
           │                             /var/log/auth.log · nginx · syslog
           ▼                                         │ HTTP POST batches
 flow_extractor.py                                   ▼
 PCAP → 80-feature flow vectors          log_collector.py
           │                             AuthLogParser · NginxLogParser
           ▼                             SyslogParser · UA fingerprinting
 predictor.py  (LSTM)                                │
 PyTorch · 2 layers · hidden=64                      │
 CICIDS2017 · 15 attack classes                      │
 → (predicted_label, confidence)                     │
           │                                         │
           ▼                                         ▼
 NetworkFlowNormalizer               raw event → UnifiedLog
 wraps prediction into UnifiedLog    { event_type, src_ip, message }
 { predicted_label, confidence,      no ML label — rule fires on count
   event_type, src_ip, dst_ip }                      │
           │                                         │
           └──────────────┬──────────────────────────┘
                          ▼
             UnifiedLog  (common schema for all sources)
                          │
                          ▼
          Correlation Engine  (31 rules)
          sliding-window counts per (event_type, src_ip)
          ML confidence check → count threshold check → alert
          per-class thresholds · 60s alert suppressor
                          │
                          ▼
          Threat Intel enrichment  (async, non-blocking)
          ip-api.com geolocation · AbuseIPDB reputation · 1h cache
                          │
                    ┌─────┴──────┐
                    ▼            ▼
              PostgreSQL    Active Response
              7 tables      Windows Firewall (PowerShell)
                            SSH → iptables / ufw (Linux)
                            Kill Switch (isolate / shutdown)
                          │
                          ▼
                React Dashboard
                Live alerts · Threat Globe · MITRE heatmap · Log stream
```

---

## Features

### ML Detection — LSTM on CICIDS2017

A two-layer LSTM (hidden\_dim=64, seq\_len=5 flows) trained on the Canadian Institute for Cybersecurity 2017 dataset. Classifies network flows into 15 attack categories in real-time. Each class has its own minimum confidence threshold to suppress false positives on inherently noisy traffic patterns — DDoS requires 0.85 confidence, brute force 0.72. A post-processing layer applies hard constraints the model cannot learn from flow statistics alone: FTP brute force must target port 21, UDP traffic cannot be a SlowHTTP attack, short web flows are directory scanning not DoS.

**Classes:** DoS Slowloris · DoS Hulk · DoS GoldenEye · DoS Slowhttptest · DDoS · SSH-Patator · FTP-Patator · PortScan · Heartbleed · Web Attack–Brute Force · Web Attack–XSS · Web Attack–SQL Injection · Infiltration · Bot

### Correlation Engine — 31 Rules

A sliding-window event counter that groups events by source IP against time-windowed thresholds, with prefix-matching rule families and a per-(IP, rule) suppressor to prevent alert storms.

| Severity | Count | Examples |
|----------|-------|---------|
| CRITICAL | 10 | SQL injection, Heartbleed, DDoS, root login, ransomware VSS deletion, mass encryption |
| HIGH | 10 | SSH/FTP brute force, web scanner UA, privilege escalation via sudo, path traversal |
| MEDIUM | 7 | Port scan, XSS, 4xx flood (directory probe), SSH invalid user |
| LOW | 4 | First SSH failure, first invalid username — early-warning reconnaissance signals |

Rules R030 and R031 (ransomware detection) arm the Kill Switch in addition to generating an alert.

### MITRE ATT&CK Integration

Every alert is automatically tagged with tactic, technique ID, technique name, and kill chain stage across 9 MITRE tactics. The dashboard renders a kill chain coverage heatmap.

| Tactic | Techniques |
|--------|-----------|
| Reconnaissance | T1046 Network Service Discovery |
| Initial Access | T1189 Drive-by · T1190 Exploit Public App |
| Credential Access | T1110 Brute Force · T1552.004 Heartbleed |
| Privilege Escalation | T1548.003 Sudo abuse |
| Discovery | T1083 File/Directory (path traversal) |
| Lateral Movement | T1210 Remote Services exploitation |
| Command & Control | T1071.001 Application Layer Protocol |
| Defense Evasion | T1562 Impair Defenses |
| Impact | T1499 DoS · T1498 DDoS · T1486 Ransomware · T1490 VSS deletion |

### Multi-Source Log Ingestion

`ubuntu_forwarder.py` runs on any Linux host, tails four log sources in real-time, batches every 2 seconds, and ships to the SIEM over HTTP. Handles log rotation, syslog noise pre-filtering, and PCAP upload via tcpdump. Zero external dependencies — standard library only.

| Source | What it catches |
|--------|----------------|
| `/var/log/auth.log` | SSH failures, invalid users, root login attempts, sudo commands |
| `/var/log/nginx/access.log` | SQL injection, XSS, path traversal, scanner User-Agents, 4xx floods |
| `/var/log/apache2/access.log` | Same as nginx |
| `/var/log/syslog` | UFW blocks, service failures, OOM killer, iptables events (keyword pre-filtered) |

### Active Defense

Detection triggers enforcement immediately through registered callbacks:

- **Windows Firewall** — `New-NetFirewallRule` via PowerShell blocks attacker IPs on the SIEM machine
- **Remote Linux firewall** — SSH to victim machine, executes `iptables -I INPUT -s {ip} -j DROP` or `ufw insert 1 deny from {ip}`
- **SSH circuit breaker** — opens after 3 consecutive SSH failures, auto-resets after 120 seconds; prevents 20-second thread hangs when victim VM is offline
- **HTTP rate limiting** — 150 requests per 30s triggers auto-ban; 16 attack-tool User-Agents (sqlmap, nikto, hydra, metasploit, nuclei…) are auto-banned on first request
- **Analyst controls** — manual ban/unban per IP, flush all blocks by device, live ban list in dashboard

### Kill Switch

Ransomware detection (Volume Shadow Copy deletion or mass file encryption) triggers an SSH response that runs in a daemon thread — never blocking the alert pipeline:

- **Isolate** — drops all iptables traffic except the analyst's SSH port; machine stays up for memory forensics and disk imaging
- **Shutdown** — `shutdown -h now` — stops encryption spread immediately

Every action is written to an in-process audit log with timestamp, action, host, reason, and success/failure status.

### Threat Intelligence

Every alert's source IP is asynchronously enriched after alert persistence (never blocking):

- **Geolocation** via ip-api.com — country, city, ISP, VPN/proxy flag (free, no key)
- **Reputation** via AbuseIPDB — confidence score 0–100, total community reports, TOR exit node flag
- **Caching** — in-memory, 1-hour TTL, 2000-entry FIFO limit to cap memory on high-volume deployments
- Private/RFC1918 IPs are skipped automatically

---

## Stack

| Layer | Technology |
|-------|-----------|
| Machine Learning | PyTorch · scikit-learn · CICIDS2017 |
| Backend API | Python 3.11 · FastAPI · uvicorn · asyncio |
| Database | PostgreSQL · SQLAlchemy async · asyncpg |
| Packet capture | tshark (Windows) · tcpdump (Linux) |
| Frontend | React 18 · Tailwind CSS · lucide-react |
| Authentication | JWT · bcrypt |
| Threat Intel | aiohttp · ip-api.com · AbuseIPDB |
| Remote response | OpenSSH · iptables · ufw · PowerShell |

---

## Project Structure

```
sentineliq/
├── backend/
│   ├── src/
│   │   ├── main.py              # FastAPI app — 40+ endpoints, capture loop, response orchestration
│   │   ├── lstm_model.py        # PyTorch LSTM architecture
│   │   ├── predictor.py         # Inference pipeline with per-class confidence filtering
│   │   ├── flow_extractor.py    # PCAP → network flow feature vectors
│   │   └── traffic_filter.py   # Pre-inference noise filter + post-process business rules
│   ├── core/
│   │   ├── correlation.py       # 31-rule sliding-window engine, thread-safe
│   │   ├── ingestion.py         # Log parsers + UnifiedLog schema
│   │   ├── log_collector.py     # Advanced auth/nginx/syslog parsers, UA fingerprinting
│   │   ├── mitre.py             # MITRE ATT&CK mappings — all 15 CICIDS classes + 18 event types
│   │   ├── threat_intel.py      # Async IP enrichment with in-memory cache
│   │   ├── active_defense.py    # In-memory bans, rate limiting, firewall callbacks
│   │   ├── kill_switch.py       # Ransomware response — isolate or shutdown via SSH
│   │   └── auth.py              # JWT authentication
│   ├── database.py              # 7-table ORM schema
│   └── config.py                # Pydantic settings loaded from .env
├── frontend/src/
│   ├── App.jsx                  # Main dashboard — live alert stream, filtering, stats
│   └── components/
│       ├── AlertDetail.jsx      # Alert detail — MITRE, threat intel, timeline, response actions
│       ├── ThreatGlobe.jsx      # Geographic attack source visualization
│       ├── LogExplorer.jsx      # Real-time normalized log stream
│       └── ConfigPanel.jsx      # Live threshold and capture interface controls
└── ubuntu_forwarder.py          # Standalone Linux agent — zero dependencies
```

---

## Lab Setup

```
┌──────────────────────┐    192.168.56.0/24    ┌──────────────────────┐
│   Windows 10 Host    │◄─────────────────────►│   Ubuntu 22.04 VM    │
│   SIEM + ML Server   │                        │   Victim / Target    │
│   192.168.56.1       │                        │   192.168.56.200     │
│                      │◄── log batches ────────│                      │
│   tshark (capture)   │◄── PCAP windows ───────│   ubuntu_forwarder   │
│   FastAPI backend    │──── SSH iptables ──────►│   tcpdump · auth.log │
│   React dashboard    │                        │   nginx · syslog     │
└──────────────────────┘                        └──────────────────────┘
                              ▲
                   ┌──────────┴─────────┐
                   │   Kali Linux VM    │
                   │   192.168.56.101   │
                   │   Attack source    │
                   └────────────────────┘
```

---

## False Positive Reduction

Getting a model to fire on attacks is straightforward. Keeping it quiet on legitimate traffic is the engineering challenge. SentinelIQ handles this at three independent layers:

**Pre-inference filter** — drops DNS, DHCP, NTP, mDNS, SSDP, LLMNR, multicast, subnet broadcasts (`*.255`), and CDN prefixes (Google, Cloudflare, AWS, GitHub, Microsoft, Fastly) before data reaches the model.

**Per-class confidence thresholds** — DDoS requires 0.85, DoS variants 0.70–0.82, brute force 0.72. Classes the model finds ambiguous get higher bars.

**Business-rule post-processing** — hard constraints the model cannot infer from flow statistics:
- UDP flows cannot be Slowhttp attacks
- FTP brute force must target port 21; web attacks must target 80/443/8080/8443
- Router IPs need 0.98 confidence before any DoS alert fires
- Flows with fewer than 15 packets labeled as DoS/DDoS are re-labeled BENIGN (these are directory brute-force connections, not flood attacks)

---

## Getting Started

### Prerequisites

- Python 3.11+, Node.js 18+, PostgreSQL
- Wireshark / tshark (Windows) or tcpdump (Linux)

### Backend

```bash
cd backend
pip install -r requirements.txt

cp .env.example .env
# Set DB credentials, ABUSEIPDB_API_KEY, SMTP settings, REMOTE_RESPONSE_HOST

uvicorn src.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm start
# → http://localhost:3000   (default: admin / admin)
```

### Ubuntu Agent

```bash
# Run on the Linux host to monitor
sudo python3 ubuntu_forwarder.py \
  --siem http://<SIEM_IP>:8000 \
  --device-id production-server
```

### Simulate Attacks

```bash
cd backend/src
python log_simulator.py             # Auth log attack sequences
python attack_simulator_multi_ip.py # Multi-source network attacks
```

---

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `DB_HOST/PORT/NAME/USER/PASSWORD` | PostgreSQL | localhost / sentineliq |
| `SECRET_KEY` | JWT signing | change in production |
| `ABUSEIPDB_API_KEY` | IP reputation | empty |
| `SMTP_USER / SMTP_PASSWORD` | Email alerts | empty |
| `REMOTE_RESPONSE_ENABLED` | SSH→Linux firewall | false |
| `REMOTE_RESPONSE_HOST` | Linux host IP to protect | — |
| `REMOTE_RESPONSE_BACKEND` | `iptables` or `ufw` | iptables |
| `KILL_SWITCH_ENABLED` | Arm ransomware kill switch | false |
| `KILL_SWITCH_ACTION` | `isolate` or `shutdown` | isolate |
| `SENTINELIQ_CAPTURE_INTERFACE` | tshark interface index | 4 |

---

## Author

**Oussama Aouass** — Final Year Cybersecurity Engineering Project

Every component built from scratch. No managed detection libraries. No pre-built SIEM engines.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-oussama--aouass-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/oussama-aouass)
[![Email](https://img.shields.io/badge/Email-oussama.aouass10@gmail.com-EA4335?style=flat&logo=gmail&logoColor=white)](mailto:oussama.aouass10@gmail.com)

---

<div align="center">
<sub>If this project interests you — for a role, a collaboration, or just to talk security — reach out.</sub>
</div>
