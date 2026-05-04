"""
Network Security Monitor - AI-Powered Anomaly Detection System
Author: Kiran Rahul Pabboju
GitHub: github.com/rahuldev7-web
Description: Real-time network traffic anomaly detection using statistical ML + Claude AI
"""

import csv
import json
import math
import datetime
import os
from collections import defaultdict

import anthropic
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
class Config:
    ANOMALY_THRESHOLD = 2.5
    WINDOW_SIZE = 50
    HIGH_RISK_PORTS = {22, 23, 3389, 4444, 8080, 9090}
    SUSPICIOUS_PROTOCOLS = {"UNKNOWN", "RAW"}
    LOG_FILE = "detections.log"
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────
class NetworkEvent:
    def __init__(self, timestamp, src_ip, dst_ip, protocol, port, bytes_sent, packets):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.port = int(port)
        self.bytes_sent = int(bytes_sent)
        self.packets = int(packets)

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "port": self.port,
            "bytes_sent": self.bytes_sent,
            "packets": self.packets,
        }


class AnomalyResult:
    def __init__(self, event, score, reasons, risk_level):
        self.event = event
        self.score = score
        self.reasons = reasons
        self.risk_level = risk_level
        self.ai_analysis = None  # Claude AI analysis added here

    def __str__(self):
        return (
            f"[{self.risk_level}] {self.event.src_ip} → {self.event.dst_ip} "
            f"| Port {self.event.port} | Score: {self.score:.2f} "
            f"| Reasons: {', '.join(self.reasons)}"
        )


# Pydantic model for API webhook ingestion
class EventPayload(BaseModel):
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    bytes_sent: int
    packets: int


# ──────────────────────────────────────────────
# Claude AI Analyzer
# ──────────────────────────────────────────────
class ClaudeAnalyzer:
    """Uses Claude AI to provide intelligent threat analysis and recommendations."""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)

    def analyze_threat(self, result: AnomalyResult) -> str:
        """Send anomaly to Claude for AI-powered threat analysis."""
        prompt = f"""You are a cybersecurity analyst. Analyze this network security anomaly and provide a concise threat assessment.

Anomaly Details:
- Risk Level: {result.risk_level}
- Score: {result.score:.2f}
- Source IP: {result.event.src_ip}
- Destination IP: {result.event.dst_ip}
- Protocol: {result.event.protocol}
- Port: {result.event.port}
- Bytes Sent: {result.event.bytes_sent}
- Packets: {result.event.packets}
- Detection Reasons: {', '.join(result.reasons)}

Provide:
1. Threat type (e.g., brute force, port scan, data exfiltration)
2. Likely attack vector
3. Recommended immediate action
4. Severity justification

Keep response under 150 words. Be specific and actionable."""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def generate_report_summary(self, detections: list, summary: dict) -> str:
        """Generate an executive summary report using Claude AI."""
        top_threats = sorted(detections, key=lambda x: x.score, reverse=True)[:3]
        threat_details = []
        for d in top_threats:
            threat_details.append(
                f"- {d.risk_level}: {d.event.src_ip} → {d.event.dst_ip} "
                f"(Port {d.event.port}, Score: {d.score:.2f})"
            )

        prompt = f"""You are a senior cybersecurity analyst. Generate a brief executive summary for this security monitoring report.

Detection Summary:
- Critical: {summary.get('CRITICAL', 0)}
- High: {summary.get('HIGH', 0)}
- Medium: {summary.get('MEDIUM', 0)}
- Low: {summary.get('LOW', 0)}
- Total anomalies: {len(detections)}

Top Threats:
{chr(10).join(threat_details)}

Write a 3-4 sentence executive summary covering: overall threat landscape, most concerning patterns, and recommended immediate actions. Be concise and professional."""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text


# ──────────────────────────────────────────────
# Statistical Engine
# ──────────────────────────────────────────────
class StatisticalBaseline:
    def __init__(self, window_size=Config.WINDOW_SIZE):
        self.window_size = window_size
        self.values = []

    def update(self, value):
        self.values.append(value)
        if len(self.values) > self.window_size:
            self.values.pop(0)

    def mean(self):
        if not self.values:
            return 0
        return sum(self.values) / len(self.values)

    def std(self):
        if len(self.values) < 2:
            return 0
        m = self.mean()
        variance = sum((x - m) ** 2 for x in self.values) / len(self.values)
        return math.sqrt(variance)

    def z_score(self, value):
        s = self.std()
        if s == 0:
            return 0
        return abs((value - self.mean()) / s)

    def is_anomalous(self, value, threshold=Config.ANOMALY_THRESHOLD):
        return self.z_score(value) > threshold


# ──────────────────────────────────────────────
# Anomaly Detector
# ──────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self):
        self.bytes_baseline = StatisticalBaseline()
        self.packets_baseline = StatisticalBaseline()
        self.ip_connection_count = defaultdict(int)
        self.detections = []

    def analyze(self, event):
        reasons = []
        score = 0.0

        bytes_z = self.bytes_baseline.z_score(event.bytes_sent)
        if bytes_z > Config.ANOMALY_THRESHOLD:
            reasons.append(f"High byte volume (z={bytes_z:.1f})")
            score += bytes_z

        packets_z = self.packets_baseline.z_score(event.packets)
        if packets_z > Config.ANOMALY_THRESHOLD:
            reasons.append(f"Unusual packet count (z={packets_z:.1f})")
            score += packets_z

        if event.port in Config.HIGH_RISK_PORTS:
            reasons.append(f"High-risk port ({event.port})")
            score += 3.0

        if event.protocol in Config.SUSPICIOUS_PROTOCOLS:
            reasons.append(f"Suspicious protocol ({event.protocol})")
            score += 2.5

        self.ip_connection_count[event.src_ip] += 1
        if self.ip_connection_count[event.src_ip] > 20:
            reasons.append(f"High connection frequency ({self.ip_connection_count[event.src_ip]} connections)")
            score += 4.0

        self.bytes_baseline.update(event.bytes_sent)
        self.packets_baseline.update(event.packets)

        if score == 0:
            return None

        if score >= 8:
            risk = "CRITICAL"
        elif score >= 5:
            risk = "HIGH"
        elif score >= 2.5:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        result = AnomalyResult(event, score, reasons, risk)
        self.detections.append(result)
        return result

    def summary(self):
        counts = defaultdict(int)
        for d in self.detections:
            counts[d.risk_level] += 1
        return dict(counts)


# ──────────────────────────────────────────────
# Data Pipeline
# ──────────────────────────────────────────────
class DataPipeline:
    def __init__(self, filepath):
        self.filepath = filepath

    def load(self):
        events = []
        try:
            with open(self.filepath, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        event = NetworkEvent(
                            timestamp=row["timestamp"],
                            src_ip=row["src_ip"],
                            dst_ip=row["dst_ip"],
                            protocol=row["protocol"],
                            port=row["port"],
                            bytes_sent=row["bytes_sent"],
                            packets=row["packets"],
                        )
                        events.append(event)
                    except (KeyError, ValueError):
                        continue
        except FileNotFoundError:
            print(f"[ERROR] File not found: {self.filepath}")
        return events


# ──────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────
class DetectionLogger:
    def __init__(self, log_file=Config.LOG_FILE):
        self.log_file = log_file

    def log(self, result):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "risk_level": result.risk_level,
            "score": round(result.score, 2),
            "reasons": result.reasons,
            "event": result.event.to_dict(),
            "ai_analysis": result.ai_analysis,
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")


# ──────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────
class ReportGenerator:
    def generate(self, detections, summary, ai_summary=None):
        print("\n" + "=" * 60)
        print("  NETWORK SECURITY MONITOR — AI-POWERED DETECTION REPORT")
        print("=" * 60)
        print(f"  Total anomalies detected: {len(detections)}")
        print(f"  Risk breakdown:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary.get(level, 0)
            bar = "█" * count
            print(f"    {level:<10} {bar} ({count})")
        print("=" * 60)

        if ai_summary:
            print("\n  🤖 AI EXECUTIVE SUMMARY (Powered by Claude):")
            print(f"  {ai_summary}")
            print()

        if detections:
            print("\n  TOP DETECTIONS WITH AI ANALYSIS:")
            top = sorted(detections, key=lambda x: x.score, reverse=True)[:5]
            for i, d in enumerate(top, 1):
                print(f"\n  {i}. {d}")
                if d.ai_analysis:
                    print(f"     🤖 Claude: {d.ai_analysis[:200]}...")

        print("\n" + "=" * 60 + "\n")


# ──────────────────────────────────────────────
# FastAPI Application
# ──────────────────────────────────────────────
app = FastAPI(
    title="Network Security Monitor API",
    description="AI-Powered Network Anomaly Detection with Claude AI",
    version="2.0.0"
)

detector = AnomalyDetector()
logger = DetectionLogger()
claude = ClaudeAnalyzer()


@app.get("/")
def root():
    return {
        "name": "Network Security Monitor",
        "version": "2.0.0",
        "author": "Kiran Rahul Pabboju",
        "status": "running",
        "ai_powered": True
    }


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}


@app.post("/analyze")
def analyze_event(payload: EventPayload):
    """Ingest a network event via webhook and analyze it with AI."""
    event = NetworkEvent(
        timestamp=payload.timestamp,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        protocol=payload.protocol,
        port=payload.port,
        bytes_sent=payload.bytes_sent,
        packets=payload.packets
    )

    result = detector.analyze(event)

    if result is None:
        return {"anomaly": False, "message": "No anomaly detected"}

    # Get Claude AI analysis for HIGH and CRITICAL threats
    if result.risk_level in ("CRITICAL", "HIGH") and Config.ANTHROPIC_API_KEY:
        try:
            result.ai_analysis = claude.analyze_threat(result)
        except Exception as e:
            result.ai_analysis = f"AI analysis unavailable: {str(e)}"

    logger.log(result)

    return {
        "anomaly": True,
        "risk_level": result.risk_level,
        "score": round(result.score, 2),
        "reasons": result.reasons,
        "event": result.event.to_dict(),
        "ai_analysis": result.ai_analysis
    }


@app.get("/detections")
def get_detections():
    """Get all detections from current session."""
    return {
        "total": len(detector.detections),
        "summary": detector.summary(),
        "detections": [
            {
                "risk_level": d.risk_level,
                "score": round(d.score, 2),
                "reasons": d.reasons,
                "event": d.event.to_dict(),
                "ai_analysis": d.ai_analysis
            }
            for d in detector.detections
        ]
    }


@app.get("/report")
def get_ai_report():
    """Generate an AI-powered executive summary report."""
    if not detector.detections:
        return {"message": "No detections yet"}

    summary = detector.summary()
    ai_summary = None

    if Config.ANTHROPIC_API_KEY:
        try:
            ai_summary = claude.generate_report_summary(detector.detections, summary)
        except Exception as e:
            ai_summary = f"AI summary unavailable: {str(e)}"

    return {
        "total_detections": len(detector.detections),
        "summary": summary,
        "ai_executive_summary": ai_summary,
        "generated_at": datetime.datetime.now().isoformat()
    }


# ──────────────────────────────────────────────
# Main — CLI Mode
# ──────────────────────────────────────────────
def main():
    print("\n[*] Network Security Monitor v2.0 starting...")
    print("[*] AI-Powered by Claude (Anthropic)")
    print("[*] Loading telemetry data...")

    pipeline = DataPipeline("sample_data.csv")
    events = pipeline.load()

    if not events:
        print("[!] No events loaded. Check sample_data.csv")
        return

    print(f"[*] Processing {len(events)} network events...")

    local_detector = AnomalyDetector()
    local_logger = DetectionLogger()
    local_claude = ClaudeAnalyzer() if Config.ANTHROPIC_API_KEY else None
    detections = []

    for event in events:
        result = local_detector.analyze(event)
        if result:
            detections.append(result)

            # Add Claude AI analysis for critical/high threats
            if result.risk_level in ("CRITICAL", "HIGH") and local_claude:
                try:
                    print(f"  🤖 Analyzing with Claude AI...")
                    result.ai_analysis = local_claude.analyze_threat(result)
                except Exception as e:
                    result.ai_analysis = None

            local_logger.log(result)

            if result.risk_level in ("CRITICAL", "HIGH"):
                print(f"  ⚠️  {result}")
                if result.ai_analysis:
                    print(f"  🤖 Claude: {result.ai_analysis[:150]}...")

    summary = local_detector.summary()

    # Generate AI executive summary
    ai_summary = None
    if local_claude and detections:
        try:
            print("\n[*] Generating AI executive summary...")
            ai_summary = local_claude.generate_report_summary(detections, summary)
        except Exception as e:
            pass

    reporter = ReportGenerator()
    reporter.generate(detections, summary, ai_summary)

    print(f"[*] Full log saved to: {Config.LOG_FILE}")
    print("[*] Scan complete.\n")
    print("[*] To start REST API server, run:")
    print("    python detector.py --api\n")


if __name__ == "__main__":
    import sys
    if "--api" in sys.argv:
        print("\n[*] Starting Network Security Monitor API Server...")
        print("[*] API docs available at: http://localhost:8000/docs")
        print("[*] Health check: http://localhost:8000/health")
        print("[*] Send events to: POST http://localhost:8000/analyze\n")
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        main()