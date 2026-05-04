# 🔐 Network Security Monitor

> Real-time network traffic anomaly detection system built with Python

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

---

## 📌 Overview

A lightweight, zero-dependency Python application that monitors network telemetry data and detects anomalous behavior in real time using statistical machine learning techniques.

Built to identify threats such as:
- 🚨 **Brute force attacks** — repeated SSH/RDP connection attempts
- 📡 **Data exfiltration** — unusually high byte volume transfers  
- 🕵️ **Port scanning** — high-frequency connections from a single IP
- ⚠️ **Suspicious protocols** — unknown or raw protocol usage
- 🔓 **High-risk port access** — connections to ports 22, 23, 3389, 4444

---

## 🏗️ Architecture

```
network-security-monitor/
│
├── detector.py          # Core anomaly detection engine
├── sample_data.csv      # Sample network telemetry data
├── requirements.txt     # Dependencies (standard library only)
├── detections.log       # Generated detection log (auto-created)
└── README.md
```

---

## ⚙️ How It Works

### 1. Data Pipeline
Ingests network telemetry from CSV (simulating real-time SIEM feed):
```
timestamp | src_ip | dst_ip | protocol | port | bytes_sent | packets
```

### 2. Statistical Baseline Engine
Uses a **rolling window Z-score algorithm** to establish normal behavior:
- Tracks rolling mean and standard deviation over configurable window
- Flags events exceeding **2.5 standard deviations** from baseline
- Adapts dynamically as traffic patterns evolve

### 3. Multi-Rule Detection Engine
Combines statistical analysis with rule-based detection:

| Rule | Trigger | Risk Weight |
|------|---------|-------------|
| High byte volume | Z-score > 2.5 | Variable |
| Unusual packet count | Z-score > 2.5 | Variable |
| High-risk port access | Ports: 22, 23, 3389, 4444, 8080 | +3.0 |
| Suspicious protocol | UNKNOWN, RAW | +2.5 |
| Connection frequency | > 20 connections from single IP | +4.0 |

### 4. Risk Scoring & Classification

| Score | Risk Level |
|-------|-----------|
| ≥ 8.0 | 🔴 CRITICAL |
| ≥ 5.0 | 🟠 HIGH |
| ≥ 2.5 | 🟡 MEDIUM |
| > 0.0 | 🟢 LOW |

### 5. Logging & Reporting
- All detections logged to `detections.log` in structured JSON format
- Console report with risk breakdown and top detections

---

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- No external libraries required

### Run
```bash
# Clone the repository
git clone https://github.com/rahuldev7-web/network-security-monitor.git
cd network-security-monitor

# Run the detector
python detector.py
```

### Sample Output
```
[*] Network Security Monitor starting...
[*] Loading telemetry data...
[*] Processing 50 network events...

  ⚠️  [CRITICAL] 172.16.0.1 → 10.0.0.5 | Port 4444 | Score: 9.24 | Reasons: High byte volume, Suspicious protocol (UNKNOWN)
  ⚠️  [HIGH] 10.5.5.5 → 192.168.1.10 | Port 22 | Score: 7.82 | Reasons: High byte volume, High-risk port (22)
  ⚠️  [HIGH] 10.10.10.10 → 192.168.1.0 | Port 3389 | Score: 6.15 | Reasons: High byte volume, High-risk port (3389)

============================================================
  NETWORK SECURITY MONITOR — DETECTION REPORT
============================================================
  Total anomalies detected: 8
  Risk breakdown:
    CRITICAL   ██ (2)
    HIGH       ███ (3)
    MEDIUM     ██ (2)
    LOW        █ (1)
============================================================
```

---

## 🔧 Configuration

Edit `Config` class in `detector.py`:

```python
class Config:
    ANOMALY_THRESHOLD = 2.5      # Z-score threshold
    WINDOW_SIZE = 50             # Rolling baseline window
    HIGH_RISK_PORTS = {22, 23, 3389, 4444, 8080, 9090}
    SUSPICIOUS_PROTOCOLS = {"UNKNOWN", "RAW"}
```

---

## 📊 Detection Log Format

```json
{
  "timestamp": "2024-01-15T08:00:41",
  "risk_level": "CRITICAL",
  "score": 9.24,
  "reasons": ["High byte volume (z=4.2)", "Suspicious protocol (UNKNOWN)"],
  "event": {
    "src_ip": "172.16.0.1",
    "dst_ip": "10.0.0.5",
    "protocol": "UNKNOWN",
    "port": 4444,
    "bytes_sent": 250000,
    "packets": 1800
  }
}
```

---

## 🛣️ Roadmap

- [ ] Live packet capture using `scapy`
- [ ] REST API endpoint for real-time ingestion
- [ ] Web dashboard with real-time visualization
- [ ] ML model upgrade (Isolation Forest / Autoencoder)
- [ ] Slack/email alerting integration
- [ ] Docker containerization

---

## 👤 Author

**Kiran Rahul Pabboju**  
M.S. Computer and Information Systems Security  
📧 kiranrahulpabboju@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/pabboju-kiran-rahul)  
🐙 [GitHub](https://github.com/rahuldev7-web)

---

## 📄 License

MIT License — free to use, modify, and distribute.
