"""Unit tests for the live attack simulation service, schemas, and API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.db.session import SessionLocal
from backend.main import app
from backend.simulation.bootstrap import ensure_ml_models_ready
from backend.simulation.schemas import SimulationStartRequest
from backend.simulation.service import simulation_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_simulation():
    """Ensure simulation is stopped before and after each test."""
    simulation_service.stop_simulation()
    yield
    simulation_service.stop_simulation()


def test_simulation_status_idle():
    """Status endpoint returns idle state when no simulation is active."""
    response = client.get("/api/simulation/status")
    assert response.status_code == 200
    data = response.json()
    assert "running" in data
    assert "progress" in data
    assert "events_generated" in data


def test_start_simulation_invalid_scenario():
    """Starting an unknown scenario must return 400 Bad Request."""
    payload = {
        "scenario": "invalid_attack_type",
        "seed": 42,
        "duration_seconds": 10,
        "intensity": "normal",
    }
    response = client.post("/api/simulation/start", json=payload)
    assert response.status_code == 400
    assert "Invalid scenario" in response.json()["detail"]


def test_start_simulation_invalid_intensity():
    """Starting with invalid intensity must return 400 Bad Request."""
    payload = {
        "scenario": "distributed_bruteforce",
        "seed": 42,
        "duration_seconds": 10,
        "intensity": "extreme_overload",
    }
    response = client.post("/api/simulation/start", json=payload)
    assert response.status_code == 400
    assert "Invalid intensity" in response.json()["detail"]


def test_start_stop_simulation_lifecycle():
    """Start simulation, verify status is running, then stop cleanly."""
    payload = {
        "scenario": "normal",
        "seed": 42,
        "duration_seconds": 20,
        "intensity": "low",
    }
    response = client.post("/api/simulation/start", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["running"] is True
    assert data["scenario"] == "normal"

    # Status should reflect running
    status_resp = client.get("/api/simulation/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["running"] is True

    # Duplicate start must be rejected with 409 Conflict
    dup_resp = client.post("/api/simulation/start", json=payload)
    assert dup_resp.status_code == 409

    # Stop simulation
    stop_resp = client.post("/api/simulation/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["success"] is True

    # Status should now be not running
    final_status = client.get("/api/simulation/status")
    assert final_status.status_code == 200
    assert final_status.json()["running"] is False


def test_stop_when_idle():
    """Calling stop when no simulation is active returns success gracefully."""
    response = client.post("/api/simulation/stop")
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_ml_bootstrap_endpoint():
    """Test the ML baseline bootstrap endpoint."""
    response = client.post("/api/simulation/bootstrap")
    assert response.status_code == 200
    data = response.json()
    assert "isolation_forest_ready" in data
    assert "clustering_ready" in data
    assert data["isolation_forest_ready"] is True
    assert data["clustering_ready"] is True
