# Network Security Monitor
### AI-Powered Real-Time Network Anomaly Detection

A production-grade Python application that monitors network traffic and detects anomalies using statistical ML and Claude AI (Anthropic).

## Features
- Real-Time Anomaly Detection using Z-score statistical engine
- Claude AI threat analysis for every CRITICAL/HIGH anomaly
- FastAPI REST endpoints for webhook event ingestion
- Multi-rule detection engine (brute force, port scanning, data exfiltration)
- Risk scoring: CRITICAL / HIGH / MEDIUM / LOW
- Structured JSON logging with AI analysis included

## API Endpoints
- GET / - System status
- GET /health - Health check
- POST /analyze - Ingest and analyze a network event via webhook
- GET /detections - All detections with AI analysis
- GET /report - AI-generated executive summary report

## Quick Start
pip install anthropic fastapi uvicorn
set ANTHROPIC_API_KEY=your-key-here
python detector.py

## Start API Server
python detector.py --api
Open http://localhost:8000/docs

## Author
Kiran Rahul Pabboju
M.S. Computer and Information Systems Security
kiranrahulpabboju@gmail.com
linkedin.com/in/pabboju-kiran-rahul
