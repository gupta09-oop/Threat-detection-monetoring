"""Integration tests for Feature Engineering API and Simulator-to-Feature pipeline."""

import time
from fastapi.testclient import TestClient
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.normal import NormalTrafficScenario


def test_calculate_features_api(client: TestClient):
    """Verify POST /api/features/calculate returns a valid FeatureSnapshot."""
    payload = {
        "window_seconds": 60,
        "entity_type": "GLOBAL",
        "entity_id": "GLOBAL",
        "persist": True,
    }
    response = client.post("/api/features/calculate", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "snapshot_id" in data
    assert data["window_seconds"] == 60
    assert data["entity_type"] == "GLOBAL"
    assert "features" in data
    assert "failed_login_rate" in data["features"]
    assert "unique_destination_ports" in data["features"]
    assert "distributed_attempt_score" in data["features"]


def test_calculate_features_invalid_window(client: TestClient):
    """Verify unsupported window size returns HTTP 400."""
    payload = {
        "window_seconds": 45,  # Not in [60, 300, 900]
        "entity_type": "GLOBAL",
        "entity_id": "GLOBAL",
    }
    response = client.post("/api/features/calculate", json=payload)
    assert response.status_code == 400
    assert "Unsupported window" in response.json()["detail"]


def test_query_snapshots_api(client: TestClient):
    """Verify GET /api/features/snapshots retrieves persisted feature snapshots."""
    # Ensure at least one snapshot exists
    calc_res = client.post("/api/features/calculate", json={
        "window_seconds": 300,
        "entity_type": "USER",
        "entity_id": "api_test_user",
        "persist": True,
    })
    assert calc_res.status_code == 200
    snap_id = calc_res.json()["snapshot_id"]

    # Query snapshots
    get_res = client.get("/api/features/snapshots?entity_id=api_test_user")
    assert get_res.status_code == 200
    items = get_res.json()
    assert len(items) >= 1
    assert any(item["snapshot_id"] == snap_id for item in items)

    # Query by ID
    id_res = client.get(f"/api/features/snapshots/{snap_id}")
    assert id_res.status_code == 200
    assert id_res.json()["snapshot_id"] == snap_id


def test_end_to_end_simulator_to_feature_pipeline(client: TestClient):
    """Verify: Simulator -> POST /api/events -> SQLite -> Feature Engineering -> Feature Snapshot."""
    # 1. Generate 20 normal events using simulator
    config = ScenarioConfig(seed=42, count=20)
    scenario = NormalTrafficScenario(config)
    simulated_events = scenario.generate()

    # 2. Ingest events into API
    post_res = client.post("/api/events", json=simulated_events)
    assert post_res.status_code == 202
    assert post_res.json()["accepted_count"] == 20

    # 3. Allow background consumer to persist events into SQLite
    time.sleep(0.7)

    # 4. Trigger feature engineering calculation for active entities over 15m window
    calc_active_res = client.post("/api/features/calculate-active?window_seconds=900")
    assert calc_active_res.status_code == 200
    snapshots = calc_active_res.json()

    assert len(snapshots) >= 1
    # Check that global snapshot was generated
    global_snaps = [s for s in snapshots if s["entity_type"] == "GLOBAL"]
    assert len(global_snaps) >= 1
    global_feat = global_snaps[0]["features"]

    # Verify features are populated and valid
    assert "login_frequency" in global_feat
    assert "connection_rate" in global_feat
    assert "port_diversity" in global_feat
    assert "source_diversity" in global_feat
