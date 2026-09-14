"""Unit tests for the /health endpoint."""

from fastapi.testclient import TestClient


def test_health_endpoint_returns_200(client: TestClient):
    """Verify GET /health returns HTTP 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_endpoint_response_structure(client: TestClient):
    """Verify GET /health response contains status, service, and version fields."""
    response = client.get("/health")
    assert response.status_code == 200

    payload = response.json()
    assert "status" in payload
    assert "service" in payload
    assert "version" in payload

    assert payload["status"] == "healthy"
    assert payload["service"] == "Sh4d0w_St4lk3r"
    assert payload["version"] == "1.0.0"
