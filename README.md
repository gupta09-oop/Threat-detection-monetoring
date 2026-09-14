# Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

> **Phase 3: Behavioral Feature Engineering**  
> Sliding time windows (60s, 5m, 15m), entity-relationship extraction, authentication/network/cross-entity behavioral evidence calculation, and SQLite feature snapshot persistence.

---

## 📁 Project Structure

```text
├── backend/
│   ├── api/             # API routers (/health, /api/events, /api/features)
│   ├── detection/       # Anomaly & signature detection engines (Phase 4+)
│   ├── features/        # Feature windows, calculator, service, and schemas
│   ├── ingestion/       # EventBus, DeadLetterQueue, BackgroundConsumer
│   ├── models/          # CanonicalEvent, TelemetryEventDB, FeatureSnapshotDB
│   ├── repositories/    # EventRepository, FeatureRepository (SQLite persistence)
│   ├── reports/         # PDF and threat report generators (Phase 4+)
│   ├── db/              # Database engine, session, and base DeclarativeBase
│   ├── config.py        # pydantic-settings configuration
│   └── main.py          # FastAPI application entrypoint & lifespan
├── frontend/            # React web dashboard (Phase 4+)
├── simulator/           # Deterministic telemetry simulator
│   ├── generators/      # AUTH, NETWORK, and SYSTEM generators
│   ├── scenarios/       # Normal baseline scenario configuration
│   └── cli/             # CLI simulator runner
├── tests/
│   ├── unit/            # Unit tests (canonical, queue, db, simulator, features)
│   ├── integration/     # Integration tests (ingestion & features APIs)
│   └── ws/              # WebSocket tests (Phase 4+)
├── docs/                # Architecture blueprints and design documentation
├── .env.example         # Example environment configuration
├── .gitignore           # Git ignore rules
├── requirements.txt     # Python project dependencies
└── README.md            # Getting started guide
```

---

## 🚀 Quickstart Guide

### 1. Create a Virtual Environment

Open your terminal in the project root directory:

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

*(Optional) Configure local environment variables:*
```bash
# Windows (cmd)
copy .env.example .env

# Windows (PowerShell) / Linux / macOS
cp .env.example .env
```

### 3. Start FastAPI

Run the application using Uvicorn:

```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

The application will start at `http://127.0.0.1:8000`.

### 4. Open Swagger Documentation

Once the server is running, explore the interactive OpenAPI documentation:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

#### Verify the Health Check

```bash
curl http://127.0.0.1:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Sh4d0w_St4lk3r",
  "version": "1.0.0"
}
```

### 5. Ingest Telemetry

Ingest a single event or a batch of events:

```bash
curl -X POST http://127.0.0.1:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "10.0.10.15",
    "user_id": "alice.smith",
    "login_result": "SUCCESS",
    "auth_method": "MFA",
    "device_id": "DEV-CORP-W10-01"
  }'
```

Query persisted events:

```bash
curl http://127.0.0.1:8000/api/events?limit=10
```

### 6. Compute Behavioral Features

Compute time-windowed feature snapshots (windows: 60s, 300s [5m], 900s [15m]):

```bash
# Calculate & persist features for a specific user over 5m
curl -X POST http://127.0.0.1:8000/api/features/calculate \
  -H "Content-Type: application/json" \
  -d '{
    "window_seconds": 300,
    "entity_type": "USER",
    "entity_id": "alice.smith",
    "persist": true
  }'

# Automatically calculate & persist snapshots for all active entities over 1m
curl -X POST "http://127.0.0.1:8000/api/features/calculate-active?window_seconds=60"

# Query persisted snapshots
curl http://127.0.0.1:8000/api/features/snapshots?limit=5
```

### 7. Run the Telemetry Simulator

Generate normal synthetic telemetry and send directly to the ingestion API:

```bash
# Generate 50 normal events to console
python simulator/cli/main.py --count 50 --seed 42

# Stream 100 events to running API
python simulator/cli/main.py --count 100 --seed 42 --target-url http://127.0.0.1:8000/api/events
```

### 8. Run Tests

Execute the automated test suite using `pytest`:

```bash
pytest -v
```
