# Sh4d0w_St4lk3r

> **Behavioral Threat Detection & Alerting for Distributed Cyber
> Attacks**

Sh4d0w_St4lk3r is an AI-assisted Security Operations Center (SOC)
platform designed to detect distributed, low-and-slow attacks that
traditional IP-centric security rules can miss.

Instead of asking only:

> **"Is this IP suspicious?"**

Sh4d0w_St4lk3r asks:

> **"Is this behavior suspicious when we look at the relationships
> between IPs, accounts, devices, destinations, and ports?"**

The platform combines real-time telemetry ingestion, behavioral feature
engineering, statistical baselining, Isolation Forest, behavioral
clustering, deterministic security rules, explainable anomaly fusion,
risk scoring, alert/case management, live SOC visualization, analyst
workflows, and threat reporting.

------------------------------------------------------------------------

## Table of Contents

-   [Key Capabilities](#key-capabilities)
-   [Problem](#problem)
-   [Solution](#solution)
-   [Architecture](#architecture)
-   [Detection Pipeline](#detection-pipeline)
-   [Detection Engines](#detection-engines)
-   [Explainable Risk Scoring](#explainable-risk-scoring)
-   [Attack Scenarios](#attack-scenarios)
-   [SOC Workflow](#soc-workflow)
-   [Technology Stack](#technology-stack)
-   [Project Structure](#project-structure)
-   [Backend API](#backend-api)
-   [WebSocket](#websocket)
-   [Getting Started](#getting-started)
-   [Running the Platform](#running-the-platform)
-   [Running Attack Simulations](#running-attack-simulations)
-   [Testing](#testing)
-   [Production Deployment](#production-deployment)
-   [Demo Workflow](#demo-workflow)
-   [Security and Scope](#security-and-scope)
-   [Current Status](#current-status)
-   [Future Production Roadmap](#future-production-roadmap)

------------------------------------------------------------------------

## Key Capabilities

-   Real-time authentication, network, and system telemetry ingestion
-   Bounded asynchronous event processing
-   Canonical event normalization and validation
-   Sliding behavioral windows: **60 seconds, 5 minutes, and 15
    minutes**
-   User, IP, host, and global behavioral dimensions
-   Statistical baseline and Z-score anomaly detection
-   Isolation Forest anomaly detection
-   KMeans behavioral clustering
-   Deterministic security rules
-   Multi-detector anomaly fusion
-   Explainable **0--100** risk scoring
-   Cross-entity behavioral correlation
-   Automatic alert generation and deduplication
-   Security case creation and correlation
-   Analyst assignment and investigation workflow
-   Attack topology visualization
-   Scenario-specific response playbooks
-   Analyst notes and resolution workflow
-   Live WebSocket SOC updates
-   JSON and browser-generated PDF threat reports
-   Reproducible attack simulations
-   Clean reset for reliable demonstrations
-   Dark/light SOC dashboard
-   Production frontend/backend deployment support

------------------------------------------------------------------------

## Problem

Distributed attacks can evade traditional static thresholds.

For example:

``` text
2 attempts × 4,000 source IPs
```

Each individual IP may look normal.

Collectively, however, thousands of IPs targeting the same accounts
within a short period can reveal a coordinated credential attack.

Traditional approaches often struggle because they are:

-   IP-centric
-   dependent on static thresholds
-   signature-driven
-   weak against distributed behavior
-   prone to alert fatigue
-   limited in cross-entity correlation

Sh4d0w_St4lk3r addresses this by building behavioral context across
multiple entities and independent detection methods.

------------------------------------------------------------------------

## Solution

The platform follows an end-to-end detection pipeline:

``` text
┌───────────────────────┐
│ Authentication Logs   │
│ Network Telemetry     │
│ System Telemetry      │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Real-Time Ingestion   │
│ Validation            │
│ Normalization         │
└───────────┬───────────┘
            ↓
┌───────────────────────┐
│ Behavioral Features   │
│ 60s / 5m / 15m        │
└───────────┬───────────┘
            ↓
┌──────────────────────────────────────┐
│ Independent Detection                │
│                                      │
│ Statistical Baseline                 │
│ Isolation Forest                     │
│ Behavioral Clustering                │
│ Deterministic Rules                  │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ Anomaly Fusion                       │
│ + Cross-Entity Correlation           │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ Explainable Risk Score 0–100         │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ Alerts → Cases → Analyst             │
│ Investigation → Resolution           │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ SOC Dashboard + Threat Reports       │
└──────────────────────────────────────┘
```

------------------------------------------------------------------------

## Detection Pipeline

### 1. Telemetry Ingestion

The backend accepts authentication, network, and system events through
the REST API.

Events are:

1.  Received
2.  Validated
3.  Normalized
4.  Placed into a bounded asynchronous queue
5.  Processed by a background consumer
6.  Persisted
7.  Used for behavioral feature extraction

Invalid telemetry is isolated through a dead-letter path rather than
being interpreted as legitimate activity.

### 2. Behavioral Feature Engineering

Features are calculated over:

-   60-second windows
-   5-minute windows
-   15-minute windows

Entity dimensions:

-   USER
-   IP
-   HOST
-   GLOBAL

Examples of authentication features:

-   Failed login rate
-   Success rate
-   Unique accounts targeted
-   Unique source IPs
-   IP diversity
-   Account diversity
-   Geographic diversity
-   Device diversity
-   Login frequency
-   Time deviation

Examples of network features:

-   Unique destination ports
-   Port diversity
-   Connection rate
-   Destination diversity
-   Failed connection rate
-   Protocol diversity

Cross-entity features include:

-   IP-to-account ratio
-   Accounts-to-IP ratio
-   Distributed attempt score
-   Temporal concentration
-   Source diversity

------------------------------------------------------------------------

# Detection Engines

## Statistical Baseline

The statistical detector compares current behavioral measurements with
empirical historical baselines.

A Z-score is used to measure deviation:

``` text
z = (observed_value - baseline_mean) / baseline_std
```

Key behavior:

-   Z-score threshold: approximately **3σ**
-   Contributions are capped
-   Cold-start behavior is explicitly handled
-   Insufficient evidence results in abstention rather than false
    confidence
-   Entity baselines can fall back to global baselines when appropriate

------------------------------------------------------------------------

## Isolation Forest

Isolation Forest provides an unsupervised machine-learning signal.

Implementation characteristics:

-   Canonical **21-dimensional** behavioral feature vector
-   StandardScaler preprocessing
-   Normal-data-oriented training
-   Target training volume: approximately **5,000 normal windows**
-   Minimum training requirements are configurable
-   Contamination: approximately **0.05**
-   Deterministic seed: **42**
-   Persisted model artifacts using Joblib
-   Normalized anomaly score: **0--100**
-   Top feature deviations available for explanation

The model is trained separately from live evaluation so that persisted
artifacts can be reused during demonstrations.

------------------------------------------------------------------------

## Behavioral Clustering

Behavioral clustering provides another independent view of abnormal
activity.

Implementation:

-   KMeans
-   K = 5
-   StandardScaler
-   `n_init = 10`
-   Random seed = 42
-   PCA-based 2D behavioral representation
-   95th-percentile distance threshold
-   Distance converted to a normalized 0--100 anomaly score

The clustering model is trained around normal behavior. An event can
therefore be anomalous because it is far from normal cluster structure
even when its nearest cluster is nominal.

------------------------------------------------------------------------

## Deterministic Rules

Rules provide explicit security evidence alongside the ML detectors.

Implemented rule concepts include:

  -----------------------------------------------------------------------
  Rule                                Detection Signal
  ----------------------------------- -----------------------------------
  Distributed login                   Many unique IPs targeting an
                                      account with low attempts per IP

  Credential stuffing                 Many accounts targeted with a high
                                      failure ratio

  Target concentration                Unusually concentrated account
                                      targeting

  IP diversity                        Source-IP diversity above baseline

  Port scanning                       Many destination ports with high
                                      failure/refusal rate

  Timing deviation                    Significant deviation from normal
                                      timing

  Success-rate change                 Abnormal change in successful
                                      authentication behavior
  -----------------------------------------------------------------------

Rules are treated as evidence rather than replacing the statistical and
ML detectors.

------------------------------------------------------------------------

# Anomaly Fusion

Sh4d0w_St4lk3r does not hide all detection logic inside one opaque
model.

Independent detector families are preserved:

``` text
Statistical Baseline
        │
        ├──────────────┐
Isolation Forest      │
        │             │
        ├──────┐      │
Clustering   Rules    │
        │      │      │
        └──────┴──────┘
               ↓
        Anomaly Fusion
               ↓
      Evidence Strength
```

Evidence strength is based on independent detector agreement:

    Independent Signals Evidence Strength
  --------------------- -------------------
                      0 LOW
                      1 MODERATE
                      2 STRONG
                     3+ CONCLUSIVE

The system does not treat missing detector data as evidence of normal
behavior.

------------------------------------------------------------------------

# Explainable Risk Scoring

The final security risk score is deterministic, explainable, and bounded
from **0 to 100**.

  Component                    Maximum
  -------------------------- ---------
  Statistical anomaly               25
  Isolation Forest                  25
  Behavioral clustering             20
  Deterministic rules               20
  Cross-entity correlation          10
  **Total**                    **100**

### Severity

      Score Severity
  --------- ----------
      0--39 LOW
     40--64 MEDIUM
     65--84 HIGH
    85--100 CRITICAL

The score represents security risk evidence. It is **not presented as a
probability of compromise**.

Cross-detector correlation contributes:

``` text
0–1 independent detectors → +0
2 detectors              → +5
3 detectors              → +8
4+ detectors             → +10
```

This structure makes the final score explainable to an analyst and a
reviewer.

------------------------------------------------------------------------

# Cross-Entity Detection

The core behavioral model follows relationships such as:

``` text
Source IPs
    │
    ├──────────────┐
    ↓              ↓
Accounts        Devices
    │              │
    └──────┬───────┘
           ↓
      Destinations
           │
           ↓
         Ports
```

This is particularly important for distributed attacks.

Instead of evaluating:

``` text
IP A → 2 attempts → normal
IP B → 1 attempt  → normal
IP C → 2 attempts → normal
...
```

the platform can evaluate:

``` text
Hundreds of IPs
      ↓
Few targeted accounts
      ↓
Short time window
      ↓
High source diversity
      ↓
Abnormal relationship pattern
      ↓
Collective anomaly
```

------------------------------------------------------------------------

# Attack Scenarios

## 1. Distributed Low-and-Slow Brute Force

Characteristics:

-   Approximately 500 rotating source IPs
-   Strictly 1--2 attempts per IP
-   Small set of targeted accounts
-   Approximately 10--15 minute attack window

Expected behavior:

``` text
Per-IP signal: weak
Collective signal: strong
```

This scenario is designed specifically to demonstrate why IP-only
thresholds can fail.

------------------------------------------------------------------------

## 2. Credential Stuffing

Characteristics:

-   Approximately 300 source IPs
-   Approximately 200 targeted accounts
-   Approximately 95% failed attempts
-   Small number of successful attempts
-   Unseen devices
-   Distributed source behavior

The combination of account diversity, source diversity, failure rate,
device novelty, and successful authentication evidence creates a strong
behavioral signal.

------------------------------------------------------------------------

## 3. Port Scanning / Reconnaissance

Characteristics:

-   Approximately 1--5 scanner IPs
-   Approximately 50--200 destination ports
-   High refused/timeout ratio
-   High port diversity

This scenario provides a network-focused detection path.

------------------------------------------------------------------------

# SOC Workflow

The system connects detection directly to analyst operations.

``` text
Attack
  ↓
Telemetry
  ↓
Detection
  ↓
Risk Score
  ↓
Alert
  ↓
Case Correlation
  ↓
Assign Analyst
  ↓
Attack Intelligence
  ↓
Response Playbook
  ↓
Analyst Notes
  ↓
Resolution
  ↓
Threat Report
```

## Alert Lifecycle

``` text
NEW
 ↓
ACKNOWLEDGED
 ↓
ESCALATED
 ↓
CLOSED
```

`CLOSED` is a terminal state.

Alerts are deduplicated for the same entity and evidence family within a
five-minute window while occurrence counts and peak risk are retained.

## Case Lifecycle

``` text
OPEN
 ↓
INVESTIGATING
 ↓
RESOLVED / DISMISSED
```

Cases correlate related alerts within the five-minute correlation
window.

------------------------------------------------------------------------

# Attack Intelligence

The investigation interface provides a consolidated view of an incident.

It includes:

-   Attack classification
-   Severity
-   Risk score
-   Evidence strength
-   Source IPs
-   Target accounts
-   Devices
-   Destination IPs/hosts
-   Destination ports
-   Geo/network intelligence
-   Activity volume
-   Independent detector evidence
-   Explainable risk breakdown
-   Kill-chain evidence
-   Assigned analyst
-   Response playbook
-   Analyst notes
-   Resolution workflow

This turns the platform from a detection-only system into an
analyst-oriented SOC workflow.

------------------------------------------------------------------------

# Threat Reporting

Threat reports are generated from real backend alert/case data.

Supported output:

-   JSON export
-   Browser print / Save as PDF

Report information includes:

-   Incident identity
-   Attack classification
-   Severity
-   Risk score
-   Risk component breakdown
-   Detection evidence
-   Correlated entities
-   Timeline
-   Analyst notes
-   Resolution
-   Recommended response playbook

------------------------------------------------------------------------

# SOC Dashboard

The frontend provides:

-   Command Center
-   Alerts
-   Alert Investigation
-   Cases
-   Case Details
-   Attack Topology
-   Detection Analytics
-   Threat Reports

Live updates use native WebSocket communication with automatic reconnect
and polling fallback.

The dashboard supports:

-   Live telemetry
-   Risk visualization
-   Evidence cards
-   Kill-chain tracking
-   Attack topology
-   Investigation context
-   Alert/case management
-   Analyst assignment
-   Response guidance
-   Resolution workflow
-   Threat reporting
-   Dark/light mode

------------------------------------------------------------------------

# Technology Stack

## Backend

-   Python
-   FastAPI
-   Pydantic
-   SQLAlchemy
-   SQLite
-   asyncio
-   NumPy
-   SciPy
-   scikit-learn
-   Joblib

## Frontend

-   React 19
-   TypeScript
-   Vite
-   TailwindCSS
-   React Router v7
-   Lucide React
-   React Flow (`@xyflow/react`)
-   Recharts
-   Native WebSocket

## Deployment

-   Render --- Backend
-   Vercel --- Frontend

------------------------------------------------------------------------

# Project Structure

A simplified view of the project:

``` text
Sh4d0w_St4lk3r/
│
├── backend/
│   ├── api/
│   ├── alerts/
│   ├── cases/
│   ├── config/
│   ├── database/
│   ├── features/
│   ├── fusion/
│   ├── realtime/
│   ├── risk/
│   ├── simulation/
│   ├── simulator/
│   └── ...
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── ...
│   ├── package.json
│   └── ...
│
├── simulator/
│
├── tests/
│   └── integration/
│
├── requirements.txt
├── .env.example
├── .python-version
├── README.md
└── ...
```

------------------------------------------------------------------------

# Backend API

Important endpoints include:

### Health

``` text
GET /health
```

### Telemetry

``` text
POST /api/events
GET  /api/events
```

### Risk

``` text
GET /api/risk/results
GET /api/risk/{id}
GET /api/risk/{id}/history
```

### Alerts

``` text
POST  /api/alerts/evaluate
GET   /api/alerts
GET   /api/alerts/{alert_id}
PATCH /api/alerts/{alert_id}/status
```

### Cases

``` text
POST  /api/cases
GET   /api/cases
GET   /api/cases/{case_id}
PATCH /api/cases/{case_id}/status

GET /api/cases/{case_id}/timeline
GET /api/cases/{case_id}/alerts
```

### Fusion

``` text
POST /api/fusion/evaluate
POST /api/fusion/evaluate-active
GET  /api/fusion/results
GET  /api/fusion/results/{id}
GET  /api/fusion/entity/{entity_id}
```

### Simulation

``` text
POST /api/simulation/start
GET  /api/simulation/status
POST /api/simulation/stop
POST /api/simulation/bootstrap
POST /api/simulation/reset
```

### Reports

``` text
POST /api/reports/export
```

------------------------------------------------------------------------

# WebSocket

Live SOC events are delivered through:

``` text
/ws/events
```

Event types include:

``` text
alert.created
alert.updated
alert.status_changed

case.created
case.updated
case.status_changed
```

The frontend automatically reconnects if the WebSocket connection is
interrupted and can fall back to polling.

------------------------------------------------------------------------

# Getting Started

## Prerequisites

Recommended environment:

-   Python 3.13
-   Node.js
-   npm
-   Git

------------------------------------------------------------------------

## 1. Clone the Repository

``` bash
git clone https://github.com/gupta09-oop/Threat-detection-monetoring.git
cd Threat-detection-monetoring
```

------------------------------------------------------------------------

## 2. Create a Python Virtual Environment

### Windows PowerShell

``` powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux/macOS

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

------------------------------------------------------------------------

## 3. Install Backend Dependencies

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

## 4. Configure Environment

Copy the example environment file:

### Windows

``` powershell
Copy-Item .env.example .env
```

### Linux/macOS

``` bash
cp .env.example .env
```

Use the local backend/frontend URLs defined by the project
configuration.

------------------------------------------------------------------------

# Running the Platform

## Start the Backend

From the repository root:

``` bash
uvicorn backend.main:app --host 127.0.0.1 --port 8099 --reload
```

Backend health endpoint:

``` text
http://127.0.0.1:8099/health
```

------------------------------------------------------------------------

## Start the Frontend

Open a second terminal:

``` bash
cd frontend
npm install
npm run dev
```

The Vite development server will provide the frontend URL shown in the
terminal.

Make sure the frontend API/WebSocket configuration points to:

``` text
REST:
http://127.0.0.1:8099

WebSocket:
ws://127.0.0.1:8099/ws/events
```

------------------------------------------------------------------------

# Running Attack Simulations

The simulator provides deterministic scenarios for demonstration and
testing.

## Normal Traffic

``` bash
python -m simulator.cli --scenario normal --seed 42 --count 50
```

## Distributed Brute Force

``` bash
python -m simulator.cli --scenario distributed_bruteforce --seed 42 --count 500
```

## Credential Stuffing

``` bash
python -m simulator.cli --scenario credential_stuffing --seed 42
```

## Port Scanning

``` bash
python -m simulator.cli --scenario port_scan --seed 42
```

## All Scenarios

``` bash
python -m simulator.cli --scenario all --seed 42
```

## Pipeline Demonstration

``` bash
python -m simulator.cli --scenario distributed_bruteforce --count 80 --seed 42 --run-pipeline
```

## Full Demo

``` bash
python -m simulator.cli --demo --seed 42
```

The simulator uses deterministic random seeds so demonstrations can be
reproduced consistently.

------------------------------------------------------------------------

# Clean Demo Reset

Before a live demonstration, reset the platform:

``` text
POST /api/simulation/reset
```

The reset flow returns the operational state to:

``` text
Risk:              0.0 / 100
Severity:          LOW
Active Alerts:     0
Critical Threats:  0
Open Cases:        0
Evidence Strength: NONE
Telemetry:         Empty
Topology:          Empty
Simulation:        Idle
```

Persisted ML artifacts survive the reset, allowing a new attack scenario
to be detected immediately.

------------------------------------------------------------------------

# Testing

Run the complete Python test suite:

``` bash
pytest -q
```

The verified project state includes:

``` text
163 backend tests passed
0 backend test failures

Integration demo suite:
9 / 9 passed

Python compile check:
clean

Frontend production build:
clean
```

The live end-to-end workflow has also been verified:

``` text
Attack Telemetry
      ↓
Ingestion
      ↓
Features
      ↓
Detection
      ↓
Fusion
      ↓
Risk
      ↓
Alert
      ↓
Case
      ↓
Investigation
      ↓
Resolution
      ↓
Report
```

------------------------------------------------------------------------

# Production Deployment

The current deployment architecture is:

``` text
                    Internet
                       │
             ┌─────────┴─────────┐
             ↓                   ↓
        Vercel Frontend      Render Backend
             │                   │
             │ REST              │
             └──────────────────→│
             │                   │
             │ WebSocket         │
             └──────────────────→│
                                 │
                              SQLite
```

## Live Frontend

``` text
https://sh4d0w-st4lk3r.vercel.app/
```

## Live Backend

``` text
https://sh4d0w-st4lk3r.onrender.com
```

## Backend Health

``` text
https://sh4d0w-st4lk3r.onrender.com/health
```

For the deployed frontend, the environment configuration uses:

``` text
VITE_API_URL=https://sh4d0w-st4lk3r.onrender.com
VITE_WS_URL=wss://sh4d0w-st4lk3r.onrender.com/ws/events
```

Production CORS is configured for the deployed frontend origin.

Python 3.13 is pinned for deployment compatibility with the scientific
Python dependencies.

------------------------------------------------------------------------

# Demo Workflow

The recommended primary demonstration scenario is **Distributed
Low-and-Slow Brute Force**.

### Step 1 --- Clean State

Show:

``` text
Risk: 0
Alerts: 0
Cases: 0
Evidence: NONE
```

### Step 2 --- Start Attack

Start the distributed brute-force scenario.

### Step 3 --- Show Live Telemetry

Show authentication events entering the dashboard.

### Step 4 --- Explain the Key Problem

Point out that individual IPs generate only a small number of attempts.

### Step 5 --- Show Behavioral Detection

Show:

-   Source-IP diversity
-   Target-account concentration
-   Distributed attempt behavior
-   Statistical deviation
-   Isolation Forest signal
-   Clustering signal
-   Rule evidence

### Step 6 --- Show Fusion

Demonstrate independent detectors converging on the same behavior.

### Step 7 --- Show Risk

Open the risk breakdown and explain the 0--100 score.

### Step 8 --- Investigate

Open the alert and Attack Intelligence view.

Inspect:

``` text
Source IPs
    ↓
Accounts
    ↓
Devices
    ↓
Destinations
    ↓
Ports
```

### Step 9 --- Analyst Workflow

Assign an analyst, review the response playbook, add notes, and resolve
the alert/case.

### Step 10 --- Report

Generate the JSON/PDF threat report.

### Closing Concept

> Traditional systems ask whether one IP is suspicious. Sh4d0w_St4lk3r
> evaluates whether the overall behavior is suspicious across the
> relationships between entities.

------------------------------------------------------------------------

# Security and Scope

This project is an experimental/demo-oriented security platform using
synthetic telemetry.

Important scope decisions:

-   No real banking customer data is used.
-   Attack traffic is simulated.
-   Documentation/test IP ranges are used for repeatable scenarios.
-   No automatic destructive remediation is performed.
-   Analyst response playbooks provide guidance only.
-   The risk score is an explainable security score, not a probability
    of compromise.
-   Production-scale infrastructure is not falsely represented as
    implemented.

------------------------------------------------------------------------

# Current Status

## Implementation Status

  Component                   Status
  --------------------------- -----------------------
  Foundation                  Complete
  Telemetry Model             Complete
  Real-Time Ingestion         Complete
  Feature Engineering         Complete
  Statistical Baseline        Complete
  Isolation Forest            Complete
  Behavioral Clustering       Complete
  Deterministic Rules         Complete
  Anomaly Fusion              Complete
  Explainable Risk Scoring    Complete
  Attack Simulation           Complete
  Alerts                      Complete
  Cases                       Complete
  WebSocket Realtime Layer    Complete
  SOC Dashboard               Complete
  Attack Intelligence         Complete
  Analyst Workflow            Complete
  Threat Reports              Complete
  Clean Reset                 Complete
  Automated Testing           Complete
  Frontend Production Build   Verified
  Deployment                  Configured / Verified

------------------------------------------------------------------------

# Future Production Roadmap

The current MVP intentionally avoids unnecessary distributed
infrastructure.

Potential production-scale extensions include:

### Event Streaming

``` text
Kafka / Redpanda
```

for horizontally scalable telemetry ingestion.

### Persistent Analytics Database

``` text
PostgreSQL / TimescaleDB
```

for high-volume time-series telemetry and historical behavioral
analysis.

### Distributed Model Serving

Dedicated model-serving infrastructure for independently scalable
detector workloads.

### Advanced Entity Graph

A persistent graph layer for large-scale relationship analysis across
accounts, devices, IPs, hosts, and destinations.

### Adaptive Baselines

Continuous baseline learning using verified normal operational behavior.

### Production Identity Integration

Integration with enterprise identity, IAM, SSO, and SOC tooling.

These are roadmap items and are intentionally not claimed as part of the
current MVP.

------------------------------------------------------------------------

# Why Sh4d0w_St4lk3r Is Different

The project is not simply an anomaly-detection dashboard.

Its main differentiators are:

### Behavioral rather than IP-only detection

The platform looks for relationships and collective behavior.

### Multiple independent detection methods

Statistical analysis, Isolation Forest, clustering, and deterministic
rules provide complementary evidence.

### Explainable AI-assisted detection

The system preserves detector evidence and shows how the final risk
score was constructed.

### Cross-entity correlation

Source IPs, accounts, devices, destinations, ports, and timing are
evaluated together.

### Operational SOC workflow

Detection continues into:

``` text
Alert
→ Case
→ Analyst
→ Investigation
→ Response
→ Resolution
→ Report
```

### Reproducible live demonstrations

Deterministic simulation, ML bootstrap, and clean reset make the
complete detection workflow repeatable.

------------------------------------------------------------------------

# Repository

GitHub:

https://github.com/gupta09-oop/Threat-detection-monetoring

Live Frontend:

https://sh4d0w-st4lk3r.vercel.app/

Live Backend:

https://sh4d0w-st4lk3r.onrender.com

------------------------------------------------------------------------

## Project Status

**Sh4d0w_St4lk3r --- Judge-Ready MVP**

> **Detect the behavior, not just the IP.**
