"""Integration tests for Statistical Baseline & Anomaly Detection API endpoints."""

import time
from fastapi.testclient import TestClient

from backend.features.schemas import EntityType, FeatureSnapshot
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.normal import NormalTrafficScenario


def test_build_and_query_baselines_api(client: TestClient):
    """Verify POST /api/baselines/build and GET /api/baselines."""
    # 1. Build baselines from whatever snapshots currently exist
    build_res = client.post("/api/baselines/build", json={"max_samples": 500})
    assert build_res.status_code == 200
    baselines = build_res.json()
    assert isinstance(baselines, list)

    # 2. Query baselines
    get_res = client.get("/api/baselines?limit=10")
    assert get_res.status_code == 200
    assert isinstance(get_res.json(), list)


def test_score_snapshot_api(client: TestClient):
    """Verify POST /api/statistical/score evaluates a snapshot and returns anomaly results."""
    # First create and persist a synthetic snapshot
    calc_res = client.post("/api/features/calculate", json={
        "window_seconds": 60,
        "entity_type": "GLOBAL",
        "entity_id": "GLOBAL",
        "persist": True,
    })
    assert calc_res.status_code == 200
    snapshot_id = calc_res.json()["snapshot_id"]

    # Build baselines
    client.post("/api/baselines/build", json={"max_samples": 500})

    # Score by snapshot_id
    score_res = client.post("/api/statistical/score", json={
        "snapshot_id": snapshot_id,
        "persist": True,
    })
    assert score_res.status_code == 200
    results = score_res.json()
    assert len(results) > 0
    assert any("feature_name" in r for r in results)
    assert any("signed_z_score" in r or r["status"] == "ABSTAIN" for r in results)


def test_query_anomaly_results_api(client: TestClient):
    """Verify GET /api/statistical/results retrieves persisted results."""
    results_res = client.get("/api/statistical/results?limit=10")
    assert results_res.status_code == 200
    records = results_res.json()
    assert isinstance(records, list)

    if records:
        target_id = records[0]["result_id"]
        single_res = client.get(f"/api/statistical/results/{target_id}")
        assert single_res.status_code == 200
        assert single_res.json()["result_id"] == target_id


def test_end_to_end_telemetry_to_statistical_anomaly_pipeline(client: TestClient):
    """Verify full end-to-end integration:
    Simulator -> Ingest -> Persist Events -> Feature Snapshots -> Baselines -> Statistical Detector -> Anomaly Results.
    """
    # 1. Generate 30 normal events
    config = ScenarioConfig(seed=999, count=30)
    scenario = NormalTrafficScenario(config)
    sim_events = scenario.generate()

    # 2. Ingest
    ingest_res = client.post("/api/events", json=sim_events)
    assert ingest_res.status_code == 202

    # 3. Allow consumer to persist events into SQLite
    time.sleep(0.7)

    # 4. Generate feature snapshots for active entities
    snap_res = client.post("/api/features/calculate-active?window_seconds=60")
    assert snap_res.status_code == 200
    assert len(snap_res.json()) >= 1

    # 5. Build baselines from the generated snapshots
    base_res = client.post("/api/baselines/build", json={"max_samples": 500})
    assert base_res.status_code == 200

    # 6. Score active snapshots
    score_res = client.post("/api/statistical/score-active?limit=5")
    assert score_res.status_code == 200
    scored_items = score_res.json()
    assert len(scored_items) > 0

    # 7. Verify anomaly results query
    all_results_res = client.get("/api/statistical/results?limit=20")
    assert all_results_res.status_code == 200
    assert len(all_results_res.json()) > 0
