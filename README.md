# 🛡️ SentinelIQ — AI-Powered SIEM & Intrusion Detection 

<p align="center">
  <em>An active-defense Security Information and Event Management (SIEM) system built over an LSTM Neural Network, designed to sniff, detect, and block cyber threats in real-time.</em>
</p>

## ✨ Key Features

- **🧠 Deep Learning Engine:** Uses an LSTM model trained on the CICIDS2017 dataset to classify 15 complex attack types with high confidence.
- **📡 Real-Time Packet Capture:** Integrates `tshark` to sniff live Wi-Fi or Ethernet traffic, convert it to flow features, and feed it to the ML model instantly.
- **🪵 Multi-Source Log Correlation:** Ingests and normalizes logs from Syslog, Nginx (`access.log`), Linux (`auth.log`), and Windows Events.
- **🗺️ MITRE ATT&CK Mapped:** Automatically tags detected threats (like Brute Force, SQLi, DoS) with their respective MITRE tactics and techniques.
- **🛡️ Active Defense System:** Capable of automatically blocking malicious IPs directly at the Windows Defender Firewall layer.
- **🌐 Threat Intelligence:** Enriches alerts with GeoIP locations and AbuseIPDB scores.
- **📊 Live React Dashboard:** A stunning, dark-mode web dashboard providing live alert feeds, pie charts, and MITRE heatmaps.

---

## 🏗️ Architecture Stack

| Layer | Technologies Used |
| :--- | :--- |
| **Frontend Dashboard** | React + Recharts |
| **Backend API** | Python 3.11, FastAPI, Uvicorn |
| **Machine Learning** | TensorFlow / Keras (LSTM), Scikit-Learn |
| **Database & Cache** | PostgreSQL 15, Redis 7 |
| **Infrastructure** | Docker Compose |

---

## 🚀 Quick Start Guide

### 1. Start the Infrastructure (Database)
Make sure Docker Desktop is running, then start the PostgreSQL and Redis containers:
```bash
docker-compose up -d
```

### 2. Launch the Backend (FastAPI + AI Engine)
Open a terminal in the project root, activate your python environment, and start the server:
```powershell
.\venv\Scripts\Activate.ps1
cd backend/src
uvicorn main:app --host 0.0.0.0 --port 8000
```
> **Note on Interfaces:** To change what network interface SentinelIQ sniffs on, edit `CAPTURE_INTERFACE` inside `backend/src/main.py`. 
> - For Wi-Fi: `CAPTURE_INTERFACE = "4"`  
> - For Host-Only VirtualBox / Ethernet: `CAPTURE_INTERFACE = "7"`
  
### 3. Launch the Frontend Dashboard
Open a new terminal, and start the React app:
```bash
cd frontend/src
npm start
```
The dashboard will open automatically at **http://localhost:3000**.

---

## 🧪 Testing the SIEM

Want to see SentinelIQ in action? We've included attack simulators! From your activated Python environment `(venv)` in the `backend/src` folder, you can run:

```bash
# Simulates live network attacks (DDoS, Botnet, Scans)
python attack_simulator_wifi.py

# Simulates real application logs (Auth fails, Nginx SQLi)
python log_simulator.py
```
Watch the SIEM dashboard light up in real-time as it catches and correlates the simulated attacks!

---
> **Note:** Developed as a Final Year Engineering Project (PFE) — Software Engineering  .