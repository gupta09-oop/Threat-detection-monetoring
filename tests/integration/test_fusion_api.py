"""Integration tests for Anomaly Fusion API endpoints and multi-detector correlation pipeline.

Tests:
- POST /api/fusion/evaluate with explicit detector evidence
- POST /api/fusion/evaluate referencing persisted snapshot detector records
- GET /api/fusion/results with filtering and pagination
- GET /api/fusion/results/{fusion_id} lookup
- GET /api/fusion/entity/{entity_id} lookup
- POST /api/fusion/evaluate-active batch evaluation
- Deterministic rule integration via API
"""

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.db.session import SessionLocal
from backend.models.anomaly import AnomalyResultDB
from backend.models.feature_snapshot import FeatureSnapshotDB


def test_evaluate_fusion_explicit_evidence(client: TestClient):
    """POST /api/fusion/evaluate with explicit detector evidence."""
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "entity_type": "USER",
        "entity_id": "test_user_fusion_1",
        "window_seconds": 300,
        "detector_evidence": [
            {
                "detector_type": "STATISTICAL_BASELINE",
                "detector_status": "ANOMALOUS",
                "detector_score": 0.92,
                "is_anomalous": True,
                "explanation": "Z-score exceeded threshold (z=3.9)",
                "timestamp": now,
                "entity_type": "USER",
                "entity_id": "test_user_fusion_1",
            },
            {
                "detector_type": "ISOLATION_FOREST",
                "detector_status": "ANOMALOUS",
                "detector_score": 89.0,
                "is_anomalous": True,
                "explanation": "Unusual behavioral vector isolated early",
                "timestamp": now,
                "entity_type": "USER",
                "entity_id": "test_user_fusion_1",
            },
            {
                "detector_type": "BEHAVIORAL_CLUSTERING",
                "detector_status": "ANOMALOUS",
                "detector_score": 86.5,
                "is_anomalous": True,
                "explanation": "Distance exceeded 95th percentile threshold",
                "timestamp": now,
                "entity_type": "USER",
                "entity_id": "test_user_fusion_1",
            },
        ],
        "persist": True,
    }

    res = client.post("/api/fusion/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["independent_detector_count"] == 3
    assert data["anomalous_detector_count"] == 3
    assert data["evidence_strength"] == "CONCLUSIVE"
    assert set(data["contributing_detectors"]) == {
        "BEHAVIORAL_CLUSTERING",
        "ISOLATION_FOREST",
        "STATISTICAL_BASELINE",
    }
    assert len(data["detector_results"]) == 3
    assert "Three independent detection methods" in data["fusion_explanation"]
    assert "fusion_id" in data


def test_evaluate_fusion_with_rule_evidence(client: TestClient):
    """POST /api/fusion/evaluate with extensible deterministic rule evidence."""
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "entity_type": "IP",
        "entity_id": "10.0.0.99",
        "window_seconds": 60,
        "detector_evidence": [
            {
                "detector_type": "ISOLATION_FOREST",
                "detector_status": "ANOMALOUS",
                "detector_score": 93.0,
                "is_anomalous": True,
                "explanation": "High port diversity outlier",
                "timestamp": now,
                "entity_type": "IP",
                "entity_id": "10.0.0.99",
            },
        ],
        "rule_evidence": [
            {
                "rule_id": "RULE-NET-SCAN-001",
                "is_anomalous": True,
                "score": 20.0,
                "explanation": "Horizontal port scan detected across 50 ports",
                "timestamp": now,
                "entity_type": "IP",
                "entity_id": "10.0.0.99",
            }
        ],
        "persist": True,
    }

    res = client.post("/api/fusion/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["independent_detector_count"] == 2
    assert data["anomalous_detector_count"] == 2
    assert data["evidence_strength"] == "STRONG"
    assert set(data["contributing_detectors"]) == {"DETERMINISTIC_RULE", "ISOLATION_FOREST"}


def test_evaluate_fusion_from_persisted_snapshot(client: TestClient):
    """POST /api/fusion/evaluate by snapshot_id correlated across persisted anomaly_results."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    snap_id = f"snap_fusion_test_{uuid.uuid4()}"

    # 1. Create FeatureSnapshotDB record
    snap = FeatureSnapshotDB(
        snapshot_id=snap_id,
        timestamp=now,
        window_seconds=300,
        window_start=now,
        window_end=now,
        entity_type="USER",
        entity_id="victor",
        event_count=50,
        features={"failed_login_count": 15.0},
        relationships={},
    )
    db.add(snap)

    # 2. Add Statistical detector result (ANOMALOUS)
    stat_res = AnomalyResultDB(
        result_id=f"stat_res_{uuid.uuid4()}",
        timestamp=now,
        detector_type="STATISTICAL_ZSCORE",
        entity_type="USER",
        entity_id="victor",
        snapshot_id=snap_id,
        window_seconds=300,
        feature_name="failed_login_count",
        current_value=15.0,
        baseline_mean=2.0,
        baseline_stddev=1.0,
        sample_count=25,
        signed_z_score=13.0,
        absolute_z_score=13.0,
        is_anomalous=True,
        anomaly_score=1.0,
        explanation="Statistical spike in failed logins",
        status="ANOMALOUS",
        details={},
    )
    db.add(stat_res)

    # 3. Add Isolation Forest detector result (NORMAL)
    if_res = AnomalyResultDB(
        result_id=f"if_res_{uuid.uuid4()}",
        timestamp=now,
        detector_type="ISOLATION_FOREST",
        entity_type="USER",
        entity_id="victor",
        snapshot_id=snap_id,
        window_seconds=300,
        feature_name="BEHAVIORAL_VECTOR_21D",
        current_value=0.15,
        sample_count=100,
        is_anomalous=False,
        anomaly_score=15.0,
        explanation="Normal feature vector",
        status="NORMAL",
        details={"normalized_anomaly_score": 15.0},
    )
    db.add(if_res)

    # 4. Add Behavioral Clustering detector result (ANOMALOUS)
    bc_res = AnomalyResultDB(
        result_id=f"bc_res_{uuid.uuid4()}",
        timestamp=now,
        detector_type="BEHAVIORAL_CLUSTERING",
        entity_type="USER",
        entity_id="victor",
        snapshot_id=snap_id,
        window_seconds=300,
        feature_name="BEHAVIORAL_VECTOR_21D",
        current_value=5.5,
        baseline_mean=3.2,
        sample_count=100,
        absolute_z_score=1.72,
        is_anomalous=True,
        anomaly_score=85.0,
        explanation="Cluster distance exceeded 95th percentile",
        status="ANOMALOUS",
        details={"normalized_anomaly_score": 85.0, "cluster_distance": 5.5},
    )
    db.add(bc_res)
    db.commit()
    db.close()

    # 5. Call POST /api/fusion/evaluate referencing snap_id
    res = client.post("/api/fusion/evaluate", json={"snapshot_id": snap_id, "persist": True})
    assert res.status_code == 200
    data = res.json()

    assert data["snapshot_id"] == snap_id
    assert data["entity_id"] == "victor"
    assert data["independent_detector_count"] == 3
    assert data["anomalous_detector_count"] == 2
    assert data["evidence_strength"] == "STRONG"
    assert set(data["contributing_detectors"]) == {"BEHAVIORAL_CLUSTERING", "STATISTICAL_BASELINE"}
    assert len(data["detector_results"]) == 3


def test_query_fusion_results_and_by_id(client: TestClient):
    """GET /api/fusion/results and GET /api/fusion/results/{fusion_id}."""
    now = datetime.now(timezone.utc).isoformat()
    test_entity = f"user_query_{uuid.uuid4()}"

    # Evaluate and persist one result
    eval_res = client.post(
        "/api/fusion/evaluate",
        json={
            "entity_type": "USER",
            "entity_id": test_entity,
            "window_seconds": 300,
            "detector_evidence": [
                {
                    "detector_type": "STATISTICAL_BASELINE",
                    "detector_status": "NORMAL",
                    "detector_score": 0.05,
                    "is_anomalous": False,
                    "explanation": "Normal",
                    "timestamp": now,
                    "entity_type": "USER",
                    "entity_id": test_entity,
                }
            ],
            "persist": True,
        },
    )
    assert eval_res.status_code == 200
    f_id = eval_res.json()["fusion_id"]

    # Query by ID
    get_res = client.get(f"/api/fusion/results/{f_id}")
    assert get_res.status_code == 200
    assert get_res.json()["fusion_id"] == f_id
    assert get_res.json()["entity_id"] == test_entity

    # Query by entity
    entity_res = client.get(f"/api/fusion/entity/{test_entity}")
    assert entity_res.status_code == 200
    results = entity_res.json()
    assert len(results) >= 1
    assert results[0]["entity_id"] == test_entity

    # Query list with filters
    list_res = client.get(
        "/api/fusion/results",
        params={"entity_id": test_entity, "evidence_strength": "LOW"},
    )
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1


def test_evaluate_active_fusion_api(client: TestClient):
    """POST /api/fusion/evaluate-active runs batch fusion on recent active snapshots."""
    res = client.post("/api/fusion/evaluate-active", json={"limit": 5})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_evaluate_fusion_bad_request_when_empty(client: TestClient):
    """POST /api/fusion/evaluate returns 400 when neither snapshot_id nor evidence provided."""
    res = client.post("/api/fusion/evaluate", json={})
    assert res.status_code == 400
    assert "Must provide either snapshot_id or detector_evidence" in res.json()["detail"]
