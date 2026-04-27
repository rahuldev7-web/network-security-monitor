"""
Network Security Monitor - Anomaly Detection System
Author: Kiran Rahul Pabboju
GitHub: github.com/rahuldev7-web
Description: Real-time network traffic anomaly detection using statistical ML
"""

import csv
import json
import math
import random
import datetime
from collections import defaultdict


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
class Config:
    ANOMALY_THRESHOLD = 2.5      # Standard deviations for anomaly detection
    WINDOW_SIZE = 50             # Rolling window for baseline calculation
    HIGH_RISK_PORTS = {22, 23, 3389, 4444, 8080, 9090}
    SUSPICIOUS_PROTOCOLS = {"UNKNOWN", "RAW"}
    LOG_FILE = "detections.log"


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
        self.risk_level = risk_level  # LOW, MEDIUM, HIGH, CRITICAL

    def __str__(self):
        return (
            f"[{self.risk_level}] {self.event.src_ip} → {self.event.dst_ip} "
            f"| Port {self.event.port} | Score: {self.score:.2f} "
            f"| Reasons: {', '.join(self.reasons)}"
        )


# ──────────────────────────────────────────────
# Statistical Engine
# ──────────────────────────────────────────────
class StatisticalBaseline:
    """Rolling window baseline using mean and standard deviation."""

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

        # Rule 1: Statistical anomaly in bytes sent
        bytes_z = self.bytes_baseline.z_score(event.bytes_sent)
        if bytes_z > Config.ANOMALY_THRESHOLD:
            reasons.append(f"High byte volume (z={bytes_z:.1f})")
            score += bytes_z

        # Rule 2: Statistical anomaly in packets
        packets_z = self.packets_baseline.z_score(event.packets)
        if packets_z > Config.ANOMALY_THRESHOLD:
            reasons.append(f"Unusual packet count (z={packets_z:.1f})")
            score += packets_z

        # Rule 3: High-risk port
        if event.port in Config.HIGH_RISK_PORTS:
            reasons.append(f"High-risk port ({event.port})")
            score += 3.0

        # Rule 4: Suspicious protocol
        if event.protocol in Config.SUSPICIOUS_PROTOCOLS:
            reasons.append(f"Suspicious protocol ({event.protocol})")
            score += 2.5

        # Rule 5: Connection frequency (potential port scan / brute force)
        self.ip_connection_count[event.src_ip] += 1
        if self.ip_connection_count[event.src_ip] > 20:
            reasons.append(f"High connection frequency ({self.ip_connection_count[event.src_ip]} connections)")
            score += 4.0

        # Update baselines
        self.bytes_baseline.update(event.bytes_sent)
        self.packets_baseline.update(event.packets)

        # Determine risk level
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
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")


# ──────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────
class ReportGenerator:
    def generate(self, detections, summary):
        print("\n" + "=" * 60)
        print("  NETWORK SECURITY MONITOR — DETECTION REPORT")
        print("=" * 60)
        print(f"  Total anomalies detected: {len(detections)}")
        print(f"  Risk breakdown:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary.get(level, 0)
            bar = "█" * count
            print(f"    {level:<10} {bar} ({count})")
        print("=" * 60)

        if detections:
            print("\n  TOP DETECTIONS:")
            top = sorted(detections, key=lambda x: x.score, reverse=True)[:5]
            for i, d in enumerate(top, 1):
                print(f"\n  {i}. {d}")

        print("\n" + "=" * 60 + "\n")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    print("\n[*] Network Security Monitor starting...")
    print("[*] Loading telemetry data...")

    pipeline = DataPipeline("sample_data.csv")
    events = pipeline.load()

    if not events:
        print("[!] No events loaded. Check sample_data.csv")
        return

    print(f"[*] Processing {len(events)} network events...")

    detector = AnomalyDetector()
    logger = DetectionLogger()
    detections = []

    for event in events:
        result = detector.analyze(event)
        if result:
            detections.append(result)
            logger.log(result)
            if result.risk_level in ("CRITICAL", "HIGH"):
                print(f"  ⚠️  {result}")

    summary = detector.summary()
    reporter = ReportGenerator()
    reporter.generate(detections, summary)

    print(f"[*] Full log saved to: {Config.LOG_FILE}")
    print("[*] Scan complete.\n")


if __name__ == "__main__":
    main()
