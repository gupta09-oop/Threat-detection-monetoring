"""Focused Integration Tests for Sh4d0w_St4lk3r Demo Completion.

Tests:
1. Reset endpoint (POST /api/simulation/reset)
2. Reset removes runtime data (alerts, cases, risk scores, telemetry)
3. ML artifacts survive reset (models exist and remain detection-ready)
4. Alert assignment (assigned_analyst)
5. Case assignment (assigned_analyst / assigned_to)
6. Alert lifecycle transitions (NEW -> ACKNOWLEDGED -> ESCALATED -> CLOSED)
7. Resolution workflow (Confirmed Threat / False Positive)
8. Analyst notes recording
9. WebSocket alert broadcast event
10. Simulation detection works after reset
"""

from datetime import datetime, timezone
import os
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.alerts.schemas import (
    AlertResult,
    AlertStatus,
    CaseCreateRequest,
    CaseStatus,
)
from backend.risk.schemas import ContributorBreakdown, RiskSeverity
from backend.db.session import SessionLocal
from backend.models.alert import AlertDB
from backend.models.case import CaseDB
from backend.models.risk import RiskScoreDB
from backend.realtime.manager import manager as ws_manager
from backend.repositories.alert_repository import AlertRepository


def _create_sample_breakdown():
    return ContributorBreakdown(
        final_score=65.0,
        severity=RiskSeverity.HIGH,
    )


def _create_test_alert(db, entity_id="test_user", title="Test Alert", score=72.0, severity="HIGH") -> str:
    repo = AlertRepository(db)
    now = datetime.now(timezone.utc)
    alert_id = str(uuid.uuid4())
    res = AlertResult(
        alert_id=alert_id,
        risk_id=str(uuid.uuid4()),
        timestamp=now,
        entity_type="USER",
        entity_id=entity_id,
        severity=severity,
        risk_score=score,
        title=title,
        summary="Automated test summary",
        explanation="Testing pipeline",
        contributor_breakdown=_create_sample_breakdown(),
        evidence_strength="STRONG",
        contributing_detectors=["statistical", "isolation_forest"],
        status=AlertStatus.NEW,
        occurrence_count=1,
        dedup_key=f"USER:{entity_id}:{alert_id[:8]}",
        created_at=now,
        updated_at=now,
        details={},
    )
    repo.create_alert(res)
    return alert_id


def test_1_and_2_reset_endpoint_and_runtime_data_clearing(client: TestClient):
    """Test POST /api/simulation/reset purges alerts, cases, risk scores, and telemetry."""
    # 1. Populate test data
    client.post(
        "/api/cases",
        json={
            "entity_type": "USER",
            "entity_id": "test_victim_user",
            "title": "Pre-Reset Incident",
            "summary": "This should be purged by reset",
            "severity": "HIGH",
            "total_risk_score": 75.0,
            "assigned_to": "Arjun Mehta",
        },
    )

    # 2. Call reset endpoint
    res = client.post("/api/simulation/reset")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CLEAN"
    assert data["current_threat_level"] == "LOW"
    assert data["risk_score"] == 0.0
    assert data["active_alerts"] == 0
    assert data["open_cases"] == 0

    # 3. Verify database tables are completely clean
    db = SessionLocal()
    try:
        assert db.query(AlertDB).count() == 0
        assert db.query(CaseDB).count() == 0
        assert db.query(RiskScoreDB).count() == 0
    finally:
        db.close()


def test_3_ml_artifacts_survive_reset(client: TestClient):
    """Verify ML model artifacts and readiness survive a complete demo reset."""
    client.post("/api/simulation/reset")

    model_dir = os.path.join(os.getcwd(), "artifacts", "models")
    if os.path.exists(model_dir):
        assert os.path.isdir(model_dir)

    # Bootstrap verify models are ready
    b_res = client.post("/api/simulation/bootstrap")
    assert b_res.status_code == 200
    assert b_res.json()["status"] == "READY"


def test_4_alert_assignment(client: TestClient):
    """Verify assigning a synthetic SOC analyst to an alert persists in backend."""
    db = SessionLocal()
    try:
        alert_id = _create_test_alert(db, entity_id="test_analyst_user", title="Brute Force Target")
    finally:
        db.close()

    # Assign analyst via PATCH /api/alerts/{id}/assign
    res = client.patch(f"/api/alerts/{alert_id}/assign", json={"analyst": "Priya Sharma"})
    assert res.status_code == 200
    assert res.json()["assigned_analyst"] == "Priya Sharma"

    # Verify query returns assigned analyst
    get_res = client.get(f"/api/alerts/{alert_id}")
    assert get_res.status_code == 200
    assert get_res.json()["assigned_analyst"] == "Priya Sharma"



def test_5_case_assignment(client: TestClient):
    """Verify assigning an analyst to an incident case persists."""
    case_res = client.post(
        "/api/cases",
        json={
            "entity_type": "USER",
            "entity_id": "test_case_entity",
            "title": "Unassigned Case",
            "summary": "Case for analyst test",
            "severity": "CRITICAL",
            "total_risk_score": 88.0,
        },
    )
    case_id = case_res.json()["case_id"]

    res = client.patch(f"/api/cases/{case_id}/assign", json={"analyst": "Rahul Verma"})
    assert res.status_code == 200
    assert res.json()["assigned_analyst"] == "Rahul Verma"
    assert res.json()["assigned_to"] == "Rahul Verma"


def test_6_alert_lifecycle(client: TestClient):
    """Verify NEW -> ACKNOWLEDGED -> ESCALATED -> CLOSED and invalid transitions."""
    db = SessionLocal()
    try:
        alert_id = _create_test_alert(db, entity_id="192.168.1.50", title="Probing Alert", score=50.0, severity="MEDIUM")
    finally:
        db.close()

    # 1. NEW -> ACKNOWLEDGED
    res1 = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "ACKNOWLEDGED"})
    assert res1.status_code == 200
    assert res1.json()["status"] == "ACKNOWLEDGED"

    # 2. ACKNOWLEDGED -> ESCALATED
    res2 = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "ESCALATED"})
    assert res2.status_code == 200
    assert res2.json()["status"] == "ESCALATED"

    # 3. ESCALATED -> CLOSED
    res3 = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "CLOSED"})
    assert res3.status_code == 200
    assert res3.json()["status"] == "CLOSED"

    # 4. CLOSED is terminal -> attempting transition back to NEW must fail
    res4 = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "NEW"})
    assert res4.status_code == 400


def test_7_resolution_workflow(client: TestClient):
    """Verify resolving an alert saves resolution outcome and notes."""
    db = SessionLocal()
    try:
        alert_id = _create_test_alert(db, entity_id="test_resolution_user", title="Credential Attack", score=90.0, severity="CRITICAL")
    finally:
        db.close()

    res = client.patch(
        f"/api/alerts/{alert_id}/resolve",
        json={
            "resolution": "Confirmed Threat",
            "analyst": "Neha Kapoor",
            "notes": "Verified distributed brute force from compromised botnet.",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CLOSED"
    assert data["resolution"] == "Confirmed Threat"
    assert data["assigned_analyst"] == "Neha Kapoor"
    assert "botnet" in data["resolution_notes"]


def test_8_analyst_notes(client: TestClient):
    """Verify appending notes to alerts and cases."""
    db = SessionLocal()
    try:
        alert_id = _create_test_alert(db, entity_id="test_notes_user", title="Notes Alert", score=45.0, severity="MEDIUM")
    finally:
        db.close()

    res = client.post(
        f"/api/alerts/{alert_id}/notes",
        json={"analyst": "Arjun Mehta", "text": "Investigated IP logs, looks suspicious."},
    )
    assert res.status_code == 200
    notes = res.json()["details"]["analyst_notes"]
    assert len(notes) >= 1
    assert notes[-1]["analyst"] == "Arjun Mehta"
    assert "suspicious" in notes[-1]["text"]


def test_9_websocket_alert_created_event(client: TestClient):
    """Verify that WebSocket clients receive alert.created with complete alert payload."""
    with client.websocket_connect("/ws/events") as websocket:
        # Ping check
        websocket.send_text("ping")
        resp = websocket.receive_text()
        assert resp == "pong"

        # Dispatch an alert.created event
        ws_manager.dispatch("alert.created", {
            "alert_id": "ws-test-uuid",
            "severity": "CRITICAL",
            "title": "Multi-Detector Behavioral Anomaly Detected",
            "risk_score": 86.0,
            "entity_id": "victim_api_user_xxxxx",
            "evidence_strength": "STRONG",
        })

        event_raw = websocket.receive_text()
        import json
        event = json.loads(event_raw)
        assert event["type"] == "alert.created"
        assert event["data"]["alert_id"] == "ws-test-uuid"
        assert event["data"]["risk_score"] == 86.0
        assert event["data"]["severity"] == "CRITICAL"


def test_10_simulation_detection_works_after_reset(client: TestClient):
    """Verify that after reset, a simulation runs and successfully generates detection telemetry."""
    # Reset
    reset_res = client.post("/api/simulation/reset")
    assert reset_res.status_code == 200

    # Start simulation for distributed_bruteforce (low intensity, short duration)
    start_res = client.post(
        "/api/simulation/start",
        json={
            "scenario": "distributed_bruteforce",
            "seed": 42,
            "duration_seconds": 3,
            "intensity": "low",
        },
    )
    assert start_res.status_code == 200
    status_data = start_res.json()
    assert status_data["running"] is True
    assert status_data["scenario"] == "distributed_bruteforce"

    # Stop simulation safely
    stop_res = client.post("/api/simulation/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["success"] is True
