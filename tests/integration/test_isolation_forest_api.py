"""Integration tests for the Isolation Forest Anomaly Detection API endpoints."""

import time
import pytest
from fastapi.testclient import TestClient

from backend.detection.isolation_forest_service import isolation_forest_service
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import CANONICAL_FEATURE_NAMES
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.normal import NormalTrafficScenario


def test_isolation_forest_status_and_unready_score(client: TestClient):
    """GET /status returns status schema, and POST /score before training returns 503 if unready."""
    status_res = client.get("/api/isolation-forest/status")
    assert status_res.status_code == 200
    data = status_res.json()
    assert "is_ready" in data
    assert "status" in data
    assert "feature_count" in data
    assert data["feature_count"] == 21


def test_isolation_forest_train_and_score_pipeline(client: TestClient):
    """Full integration pipeline:

    Simulator normal events -> POST /api/events -> feature snapshots
    -> POST /api/isolation-forest/train -> POST /score -> GET /results
    """
    # 1. Ingest normal baseline events via simulator
    scenario = NormalTrafficScenario(ScenarioConfig(seed=42, count=30))
    events = scenario.generate()

    # Push to /api/events
    ingest_res = client.post("/api/events", json=events)
    assert ingest_res.status_code == 202

    # Give consumer a moment to flush batch
    time.sleep(1.0)

    # 2. Populate normal baseline feature snapshots with natural variation
    from backend.db.session import SessionLocal
    from backend.models.feature_snapshot import FeatureSnapshotDB
    from datetime import datetime, timedelta, timezone
    import uuid

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    for i in range(25):
        features = {name: float(0.02 + 0.005 * (i % 4)) for name in CANONICAL_FEATURE_NAMES}
        features["login_frequency"] = float(0.05 + 0.01 * (i % 3))
        features["connection_rate"] = float(0.1 + 0.02 * (i % 4))
        snap = FeatureSnapshotDB(
            snapshot_id=f"pipeline_snap_{uuid.uuid4()}",
            timestamp=now - timedelta(minutes=i),
            window_seconds=60,
            window_start=now - timedelta(minutes=i, seconds=60),
            window_end=now - timedelta(minutes=i),
            entity_type="GLOBAL",
            entity_id=f"pipeline_entity_{i % 3}",
            event_count=10,
            features=features,
            relationships={},
        )
        db.add(snap)
    db.commit()
    db.close()

    # 3. Train Isolation Forest
    train_res = client.post("/api/isolation-forest/train", json={
        "min_samples": 5,
        "contamination": 0.2,
        "random_seed": 42,
        "n_estimators": 30,
    })
    assert train_res.status_code == 200
    train_data = train_res.json()
    assert train_data["status"] == "SUCCESS"
    assert train_data["training_sample_count"] >= 5
    assert train_data["feature_count"] == 21

    # 4. Verify status is now READY
    status_res = client.get("/api/isolation-forest/status")
    assert status_res.status_code == 200
    assert status_res.json()["is_ready"] is True
    assert status_res.json()["status"] == "READY"

    # 5. Score a normal feature snapshot
    normal_features = {name: 0.02 for name in CANONICAL_FEATURE_NAMES}
    normal_snap = {
        "window_seconds": 60,
        "window_start": "2026-09-14T10:00:00Z",
        "window_end": "2026-09-14T10:01:00Z",
        "entity_type": "USER",
        "entity_id": "normal_user",
        "event_count": 5,
        "features": normal_features,
        "relationships": {},
    }

    score_norm_res = client.post("/api/isolation-forest/score", json={
        "snapshot": normal_snap,
        "persist": True,
    })
    assert score_norm_res.status_code == 200
    norm_result = score_norm_res.json()
    assert norm_result["detector_type"] == "ISOLATION_FOREST"
    assert norm_result["raw_prediction"] == 1
    assert norm_result["is_anomalous"] is False
    assert norm_result["status"] == "NORMAL"
    assert 0.0 <= norm_result["normalized_anomaly_score"] <= 100.0

    # 6. Score an anomalous feature snapshot with extreme values
    anom_features = {name: 50.0 for name in CANONICAL_FEATURE_NAMES}
    anom_features["failed_login_rate"] = 100.0
    anom_features["unique_accounts_targeted"] = 1000.0
    anom_features["connection_rate"] = 500.0

    anom_snap = {
        "window_seconds": 60,
        "window_start": "2026-09-14T10:00:00Z",
        "window_end": "2026-09-14T10:01:00Z",
        "entity_type": "IP",
        "entity_id": "10.0.0.99",
        "event_count": 500,
        "features": anom_features,
        "relationships": {},
    }

    score_anom_res = client.post("/api/isolation-forest/score", json={
        "snapshot": anom_snap,
        "persist": True,
    })
    assert score_anom_res.status_code == 200
    anom_result = score_anom_res.json()
    assert anom_result["detector_type"] == "ISOLATION_FOREST"
    assert anom_result["raw_prediction"] in [-1, 1]
    assert anom_result["normalized_anomaly_score"] >= 0.0
    assert len(anom_result["top_feature_deviations"]) > 0
    assert "Isolation Forest" in anom_result["explanation"]

    # 7. Test POST /api/isolation-forest/score-active
    active_res = client.post("/api/isolation-forest/score-active", json={"limit": 5})
    assert active_res.status_code == 200
    active_results = active_res.json()
    assert isinstance(active_results, list)

    # 8. Test GET /api/isolation-forest/results
    results_res = client.get("/api/isolation-forest/results?limit=10")
    assert results_res.status_code == 200
    records = results_res.json()
    assert isinstance(records, list)
    assert len(records) > 0

    # 9. Test GET /api/isolation-forest/results/{result_id}
    target_id = records[0]["result_id"]
    single_res = client.get(f"/api/isolation-forest/results/{target_id}")
    assert single_res.status_code == 200
    assert single_res.json()["result_id"] == target_id
    assert single_res.json()["detector_type"] == "ISOLATION_FOREST"
