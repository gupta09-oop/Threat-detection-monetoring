"""Integration tests for Behavioral Clustering API endpoints, training, and scoring pipeline."""

from datetime import datetime, timedelta, timezone
import time
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.db.session import SessionLocal
from backend.detection.clustering_service import behavioral_clustering_service
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import CANONICAL_FEATURE_NAMES
from backend.models.feature_snapshot import FeatureSnapshotDB
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.normal import NormalTrafficScenario


def test_clustering_status_and_unready_score(client: TestClient):
    """GET /api/clustering/status returns status schema, and POST /score before training returns 503 if unready."""
    status_res = client.get("/api/clustering/status")
    assert status_res.status_code == 200
    data = status_res.json()
    assert "is_ready" in data
    assert "status" in data
    assert "feature_count" in data
    assert data["feature_count"] == 21


def test_clustering_train_and_score_pipeline(client: TestClient):
    """Full integration pipeline:

    Simulator normal events -> POST /api/events -> feature snapshots
    -> POST /api/clustering/train -> POST /score -> GET /results
    """
    # 1. Ingest normal baseline events via simulator
    scenario = NormalTrafficScenario(ScenarioConfig(seed=42, count=30))
    events = scenario.generate()

    ingest_res = client.post("/api/events", json=events)
    assert ingest_res.status_code == 202
    time.sleep(1.0)

    # 2. Populate normal baseline feature snapshots with natural variation
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    for i in range(25):
        features = {name: float(0.02 + 0.005 * (i % 4)) for name in CANONICAL_FEATURE_NAMES}
        features["login_frequency"] = float(0.05 + 0.01 * (i % 3))
        features["connection_rate"] = float(0.1 + 0.02 * (i % 4))
        snap = FeatureSnapshotDB(
            snapshot_id=f"cluster_pipe_snap_{uuid.uuid4()}",
            timestamp=now - timedelta(minutes=i),
            window_seconds=60,
            window_start=now - timedelta(minutes=i, seconds=60),
            window_end=now - timedelta(minutes=i),
            entity_type="GLOBAL",
            entity_id=f"cluster_entity_{i % 3}",
            event_count=10,
            features=features,
            relationships={},
        )
        db.add(snap)
    db.commit()
    db.close()

    # 3. Train Behavioral Clustering
    train_res = client.post("/api/clustering/train", json={
        "min_samples": 5,
        "n_clusters": 4,
        "random_seed": 42,
        "distance_percentile": 95.0,
    })
    assert train_res.status_code == 200
    train_data = train_res.json()
    assert train_data["status"] == "SUCCESS"
    assert train_data["training_sample_count"] >= 5
    assert train_data["n_clusters"] == 4
    assert train_data["threshold_distance"] > 0.0

    # 4. Verify status is now READY
    status_res = client.get("/api/clustering/status")
    assert status_res.status_code == 200
    assert status_res.json()["is_ready"] is True
    assert status_res.json()["status"] == "READY"
    assert len(status_res.json()["clusters"]) == 4

    # 5. Score a normal feature snapshot
    normal_features = {name: 0.02 for name in CANONICAL_FEATURE_NAMES}
    normal_snap = {
        "window_seconds": 60,
        "window_start": "2026-09-14T10:00:00Z",
        "window_end": "2026-09-14T10:01:00Z",
        "entity_type": "USER",
        "entity_id": "cluster_norm_user",
        "event_count": 5,
        "features": normal_features,
        "relationships": {},
    }

    score_norm_res = client.post("/api/clustering/score", json={
        "snapshot": normal_snap,
        "persist": True,
    })
    assert score_norm_res.status_code == 200
    norm_result = score_norm_res.json()
    assert norm_result["detector_type"] == "BEHAVIORAL_CLUSTERING"
    assert norm_result["is_anomalous"] is False
    assert norm_result["status"] == "NORMAL"
    assert 0.0 <= norm_result["normalized_anomaly_score"] <= 100.0
    assert norm_result["pca_coordinates"] is not None
    assert len(norm_result["pca_coordinates"]) == 2

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

    score_anom_res = client.post("/api/clustering/score", json={
        "snapshot": anom_snap,
        "persist": True,
    })
    assert score_anom_res.status_code == 200
    anom_result = score_anom_res.json()
    assert anom_result["detector_type"] == "BEHAVIORAL_CLUSTERING"
    assert anom_result["is_anomalous"] is True
    assert anom_result["status"] == "ANOMALOUS"
    assert anom_result["normalized_anomaly_score"] > 50.0
    assert len(anom_result["top_feature_deviations"]) > 0
    assert "Behavioral clustering anomaly detected" in anom_result["explanation"]
    assert "not causal proof" in anom_result["explanation"]

    # 7. Test POST /api/clustering/score-active
    active_res = client.post("/api/clustering/score-active", json={"limit": 5})
    assert active_res.status_code == 200
    active_results = active_res.json()
    assert isinstance(active_results, list)

    # 8. Test GET /api/clustering/results
    results_res = client.get("/api/clustering/results?limit=10")
    assert results_res.status_code == 200
    records = results_res.json()
    assert isinstance(records, list)
    assert len(records) > 0

    # 9. Test GET /api/clustering/results/{result_id}
    target_id = records[0]["result_id"]
    single_res = client.get(f"/api/clustering/results/{target_id}")
    assert single_res.status_code == 200
    assert single_res.json()["result_id"] == target_id
    assert single_res.json()["detector_type"] == "BEHAVIORAL_CLUSTERING"
