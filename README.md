# 🛡️ Sh4d0w_St4lk3r

## Behavioral Threat Intelligence & Real-Time SOC Platform

> **Detect behavior. Correlate evidence. Explain risk. Investigate threats.**

Sh4d0w_St4lk3r is an AI-powered cybersecurity platform designed to detect **distributed and low-and-slow attacks** that traditional IP-based security rules can miss.

The system combines **statistical baselines, Isolation Forest, behavioral clustering, deterministic security rules, cross-entity correlation, and explainable risk scoring** into a real-time SOC workflow.

---

## 🚨 Problem

Modern banking infrastructure generates huge volumes of legitimate authentication and network activity.

Attackers can hide inside this traffic by distributing their activity across hundreds or thousands of IP addresses.

For example:

```text
IP-001 → 2 failed logins → NORMAL
IP-002 → 1 failed login  → NORMAL
IP-003 → 2 failed logins → NORMAL
...
IP-500 → 1 failed login  → NORMAL

Traditional detection may consider every IP individually and generate no alert.

But collectively:

500 IPs
   ↓
Same target accounts
   ↓
Same time window
   ↓
High IP diversity
   ↓
Abnormal account targeting
   ↓
Coordinated Attack
The key idea

An individual source can look normal while collective behavior reveals the attack.

🧠 How Sh4d0w_St4lk3r Works
🔍 Detection Engine<img width="4605" height="752" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/df5021e3-2a90-4b37-89c5-32293d42814e" />


Sh4d0w_St4lk3r uses multiple independent detection methods.

Statistical Baseline

Behavior is compared against expected historical patterns using statistical deviation and Z-scores.

z = (x - mean) / standard_deviation
Isolation Forest

Detects unusual combinations of behavioral features and produces a normalized anomaly score.

Behavioral Clustering

KMeans-based behavioral clusters identify observations that significantly deviate from normal behavioral regions.

Deterministic Rules

Security-specific rules detect patterns such as:

Distributed brute force
Credential stuffing
Port scanning
High source-IP diversity
Abnormal timing
Target concentration
🎯 Explainable Risk Score

Every detection produces a 0–100 Threat Risk Score.

Detection Signal	Maximum Contribution
Statistical Baseline	25
Isolation Forest	25
Behavioral Clustering	20
Deterministic Rules	20
Cross-Entity Correlation	10
Total	100
Severity
0–39     LOW
40–64    MEDIUM
65–84    HIGH
85–100   CRITICAL

The score represents the strength of available security evidence, not a probability of compromise.

🔗 Cross-Entity Correlation

This is the core of the platform.

Instead of looking only at an IP, the system correlates:

This allows the platform to detect coordinated attacks even when individual IPs remain below normal thresholds.

Example
500 source IPs
+
200 targeted accounts
+
95% authentication failures
+
unseen devices
+
same time window

can become strong evidence of credential stuffing.

🖥️ SOC Workflow

The SOC dashboard provides:

Real-time telemetry
Live threat/risk score
Active alerts
Critical threats
Alert investigation
Analyst assignment
Investigation checklist
Case management
Attack topology
Kill-chain context
Detection analytics
Threat reports
🎯 Attack Scenarios

The built-in simulator provides controlled synthetic attack scenarios.

1. Distributed Low-and-Slow Brute Force
~500 IPs
↓
1–2 attempts/IP
↓
Few targeted accounts
↓
High source diversity
↓
Distributed attack

Expected risk: 75–95

2. Credential Stuffing
~300 IPs
↓
~200 accounts
↓
~95% failures
↓
Unseen devices
↓
Credential stuffing

Expected risk: 80–98

3. Port Scanning
1–5 scanner IPs
↓
50–200 ports
↓
High refused/timeout rate
↓
Reconnaissance

Expected risk: 60–85

4. Normal Traffic

Used for behavioral baselines, model training, and comparison.

All attack data is synthetic and deterministic.

⚙️ Technology Stack
Backend
Python
FastAPI
SQLAlchemy
SQLite
Pydantic
Scikit-learn
Joblib
WebSockets
Pytest
Frontend
React
TypeScript
Vite
Tailwind CSS
React Router
Recharts
React Flow
Lucide React
📁 Project Structure
Threat-detection-monetoring/
│
├── backend/
│   ├── alerts/
│   ├── api/
│   ├── db/
│   ├── detection/
│   ├── features/
│   ├── ingestion/
│   ├── models/
│   ├── realtime/
│   ├── reports/
│   ├── repositories/
│   ├── risk/
│   └── simulation/
│
├── frontend/
│   └── src/
│       ├── components/
│       ├── pages/
│       └── services/
│
├── simulator/
├── tests/
├── docs/
├── artifacts/
├── requirements.txt
└── README.md
🚀 Quick Start
Clone
git clone https://github.com/gupta09-oop/Threat-detection-monetoring.git
cd Threat-detection-monetoring
Backend
python -m venv .venv

Windows:

.venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt

Start backend:

python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8099
Frontend

Open another terminal:

cd frontend
npm install
npm run dev

Backend health:

http://127.0.0.1:8099/health
🧪 Run the Demo
Normal
python -m simulator.cli --scenario normal --seed 42 --count 50
Distributed Brute Force
python -m simulator.cli --scenario distributed_bruteforce --seed 42 --count 500
Credential Stuffing
python -m simulator.cli --scenario credential_stuffing --seed 42
Port Scan
python -m simulator.cli --scenario port_scan --seed 42
Complete Demo
python -m simulator.cli --demo --seed 42
🏆 5-Minute Demo Story

The recommended demonstration follows:

NORMAL
  ↓
Attack Begins
  ↓
Individual IPs Look Normal
  ↓
Collective Behavior Becomes Abnormal
  ↓
Multiple Detectors Trigger
  ↓
Anomaly Fusion
  ↓
Risk Score Increases
  ↓
Alert Created
  ↓
Analyst Investigates
  ↓
Case Resolved
  ↓
Threat Report Generated

The key message to the judges:

"We don't need one obviously malicious IP. We identify the coordinated behavior across IPs, accounts, devices, destinations, and time."

📊 Traditional Detection vs Sh4d0w_St4lk3r
Traditional Approach	Sh4d0w_St4lk3r
IP-centric	Cross-entity behavioral
Fixed thresholds	Statistical baselines
Signature/rule focused	Rules + ML + behavioral signals
Individual events	Collective behavior
Alert-heavy	Deduplication + case correlation
Limited context	Investigation context
Difficult to explain complex behavior	Explainable risk breakdown
🛣️ Future Roadmap

The current version is optimized for a hackathon/MVP environment.

Future production improvements could include:

Apache Kafka / distributed streaming
PostgreSQL
Distributed model serving
Multi-region deployment
Enterprise authentication
RBAC
Audit logging
Centralized observability
Model monitoring
Detection-quality monitoring
🔐 Security & Scope

Sh4d0w_St4lk3r is a cybersecurity research and demonstration platform.

All attack scenarios use synthetic data.
No real banking customer data is required.
The platform is human-in-the-loop.
No destructive automated remediation is performed.
The project does not claim 100% detection accuracy or zero false positives.
📌 Project Goal

Sh4d0w_St4lk3r demonstrates how modern behavioral analytics can detect distributed attacks that traditional IP-centric security systems may overlook.

It combines:

Behavioral Analytics
        +
Machine Learning
        +
Security Rules
        +
Cross-Entity Correlation
        +
Explainable Risk
        +
Real-Time SOC

into one end-to-end threat detection and investigation platform.
