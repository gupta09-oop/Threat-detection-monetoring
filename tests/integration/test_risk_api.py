"""Integration tests for Explainable Risk Scoring API endpoints.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Tests:
- POST /api/risk/evaluate with explicit evidence
- POST /api/risk/evaluate with snapshot_id
- POST /api/risk/evaluate with fusion_id
- POST /api/risk/evaluate-active batch evaluation
- GET /api/risk/results with filtering and pagination
- GET /api/risk/results/{risk_id} lookup
- GET /api/risk/{entity_id} latest entity lookup
- GET /api/risk/{entity_id}/history entity evaluation history
"""

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.db.session import SessionLocal
from backend.models.anomaly import AnomalyResultDB
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.models.fusion import FusionResultDB


def test_evaluate_risk_explicit_evidence(client: TestClient):
    """POST /api/risk/evaluate with direct detector evidence."""
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "entity_type": "USER",
        "entity_id": "test_risk_api_user_1",
        "window_seconds": 300,
        "detector_evidence": [
            {
                "detector_type": "STATISTICAL_BASELINE",
                "detector_status": "ANOMALOUS",
                "detector_score": 0.88,
                "is_anomalous": True,
                "explanation": "Z-score exceeded threshold",
                "timestamp": now,
                "entity_type": "USER",
                "entity_id": "test_risk_api_user_1",
            },
            {
                "detector_type": "ISOLATION_FOREST",
                "detector_status": "ANOMALOUS",
                "detector_score": 85.0,
                "is_anomalous": True,
                "explanation": "Unusual vector",
                "timestamp": now,
                "entity_type": "USER",
                "entity_id": "test_risk_api_user_1",
            },
        ],
        "persist": True,
    }

    resp = client.post("/api/risk/evaluate", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["entity_id"] == "test_risk_api_user_1"
    assert data["statistical_contribution"] == 22.0  # (88 / 100) * 25 = 22.0
    assert data["isolation_forest_contribution"] == 21.2 or data["isolation_forest_contribution"] == 21.3 or data["isolation_forest_contribution"] == 21.2  # (85 / 100) * 25 = 21.25 -> 21.2
    assert data["correlation_contribution"] == 5.0  # 2 anomalous detectors
    assert data["final_score"] > 0
    assert data["severity"] in ("MEDIUM", "HIGH")
    assert "Threat Risk Score" in data["explanation"]
    assert "contributor_breakdown" in data
    assert "risk_id" in data


def test_evaluate_risk_with_snapshot_id(client: TestClient):
    """POST /api/risk/evaluate referencing persisted snapshot and detector records."""
    db = SessionLocal()
    snap_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    try:
        # Create FeatureSnapshotDB record
        snap_db = FeatureSnapshotDB(
            snapshot_id=snap_id,
            timestamp=now,
            window_seconds=300,
            window_start=now,
            window_end=now,
            entity_type="USER",
            entity_id="test_risk_api_user_2",
            event_count=1,
            features={"failed_logins": 5.0},
        )
        db.add(snap_db)

        # Create AnomalyResultDB records
        anom_db = AnomalyResultDB(
            result_id=str(uuid.uuid4()),
            timestamp=now,
            detector_type="ISOLATION_FOREST",
            entity_type="USER",
            entity_id="test_risk_api_user_2",
            snapshot_id=snap_id,
            window_seconds=300,
            feature_name="ALL_FEATURES",
            current_value=-0.35,
            is_anomalous=True,
            anomaly_score=92.0,
            explanation="Significant outlier detected",
            status="ANOMALOUS",
            details={"normalized_anomaly_score": 92.0, "raw_decision_score": -0.35},
        )
        db.add(anom_db)
        db.commit()
    finally:
        db.close()

    resp = client.post(
        "/api/risk/evaluate",
        json={"snapshot_id": snap_id, "persist": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["snapshot_id"] == snap_id
    assert data["entity_id"] == "test_risk_api_user_2"
    assert data["isolation_forest_contribution"] == 23.0  # (92 / 100) * 25 = 23.0
    assert data["final_score"] == 23.0


def test_evaluate_risk_with_fusion_id(client: TestClient):
    """POST /api/risk/evaluate referencing an existing persisted FusionResult."""
    db = SessionLocal()
    fusion_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    try:
        fusion_db = FusionResultDB(
            fusion_id=fusion_id,
            timestamp=now,
            entity_type="USER",
            entity_id="test_risk_api_user_3",
            snapshot_id=str(uuid.uuid4()),
            window_seconds=300,
            independent_detector_count=2,
            anomalous_detector_count=2,
            evidence_strength="STRONG",
            contributing_detectors=["ISOLATION_FOREST", "STATISTICAL_BASELINE"],
            explanation="Two independent detectors identified anomalies",
            detector_results=[
                {
                    "detector_type": "STATISTICAL_BASELINE",
                    "detector_status": "ANOMALOUS",
                    "detector_score": 0.80,
                    "is_anomalous": True,
                    "explanation": "High volume",
                    "timestamp": now.isoformat(),
                    "entity_type": "USER",
                    "entity_id": "test_risk_api_user_3",
                },
                {
                    "detector_type": "ISOLATION_FOREST",
                    "detector_status": "ANOMALOUS",
                    "detector_score": 80.0,
                    "is_anomalous": True,
                    "explanation": "Anomalous vector",
                    "timestamp": now.isoformat(),
                    "entity_type": "USER",
                    "entity_id": "test_risk_api_user_3",
                },
            ],
            correlation_window_seconds=300,
        )
        db.add(fusion_db)
        db.commit()
    finally:
        db.close()

    resp = client.post(
        "/api/risk/evaluate",
        json={"fusion_id": fusion_id, "persist": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["source_fusion_id"] == fusion_id
    assert data["entity_id"] == "test_risk_api_user_3"
    assert data["statistical_contribution"] == 20.0
    assert data["isolation_forest_contribution"] == 20.0
    assert data["correlation_contribution"] == 5.0
    assert data["final_score"] == 45.0
    assert data["severity"] == "MEDIUM"


def test_evaluate_risk_bad_request(client: TestClient):
    """POST /api/risk/evaluate fails with 400 when missing parameters."""
    resp = client.post("/api/risk/evaluate", json={})
    assert resp.status_code == 400


def test_evaluate_active_risk(client: TestClient):
    """POST /api/risk/evaluate-active runs batch risk scoring across active snapshots."""
    resp = client.post("/api/risk/evaluate-active", json={"limit": 5})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_query_results_and_lookup(client: TestClient):
    """Test GET /api/risk/results, /results/{risk_id}, /{entity_id}, and /{entity_id}/history."""
    now = datetime.now(timezone.utc).isoformat()
    unique_user = f"query_user_{uuid.uuid4().hex[:8]}"

    eval_payload = {
        "entity_type": "USER",
        "entity_id": unique_user,
        "window_seconds": 60,
        "detector_evidence": [
            {
                "detector_type": "BEHAVIORAL_CLUSTERING",
                "detector_status": "ANOMALOUS",
                "detector_score": 75.0,
                "is_anomalous": True,
                "explanation": "Cluster distance",
                "timestamp": now,
                "entity_type": "USER",
                "entity_id": unique_user,
            }
        ],
        "persist": True,
    }

    eval_resp = client.post("/api/risk/evaluate", json=eval_payload)
    assert eval_resp.status_code == 200
    created = eval_resp.json()
    risk_id = created["risk_id"]

    # 1. Query by ID
    get_resp = client.get(f"/api/risk/results/{risk_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["risk_id"] == risk_id

    # 2. Query list filtered by entity_id
    list_resp = client.get(f"/api/risk/results?entity_id={unique_user}")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) >= 1
    assert items[0]["entity_id"] == unique_user

    # 3. Query latest entity risk
    entity_resp = client.get(f"/api/risk/{unique_user}")
    assert entity_resp.status_code == 200
    assert entity_resp.json()["entity_id"] == unique_user

    # 4. Query entity history
    hist_resp = client.get(f"/api/risk/{unique_user}/history")
    assert hist_resp.status_code == 200
    hist = hist_resp.json()
    assert len(hist) >= 1
    assert hist[0]["entity_id"] == unique_user
