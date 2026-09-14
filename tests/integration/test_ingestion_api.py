"""Integration tests for the Telemetry Ingestion API (POST & GET /api/events)."""

import time
from fastapi.testclient import TestClient

from backend.ingestion.queue import dead_letter_queue


def test_single_event_ingestion_http_202(client: TestClient):
    """Verify single event ingestion returns HTTP 202 Accepted."""
    payload = {
        "source_ip": "10.0.10.22",
        "user_id": "alice.smith",
        "login_result": "SUCCESS",
        "auth_method": "MFA",
        "device_id": "DEV-CORP-W10-01",
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["accepted_count"] == 1
    assert data["rejected_count"] == 0
    assert len(data["event_ids"]) == 1


def test_batch_event_ingestion_http_202(client: TestClient):
    """Verify batch event ingestion returns HTTP 202 Accepted with all IDs."""
    batch = [
        {
            "source_ip": "10.0.10.15",
            "destination_ip": "142.250.190.46",
            "destination_port": 443,
            "protocol": "TCP",
            "bytes_sent": 1200,
            "bytes_received": 5400,
            "connection_result": "ALLOW",
        },
        {
            "host": "DEV-CORP-LNX-01",
            "process": "sshd",
            "event_type": "PROCESS_START",
            "username": "root",
        },
    ]
    response = client.post("/api/events", json=batch)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["accepted_count"] == 2
    assert data["rejected_count"] == 0
    assert len(data["event_ids"]) == 2


def test_malformed_payload_rejected_and_recorded_in_dead_letter(client: TestClient):
    """Verify malformed events are rejected and recorded in DeadLetterQueue."""
    dead_letter_queue.clear()

    bad_payload = {
        "invalid_field": "unknown",
        "no_source_type": True,
    }
    response = client.post("/api/events", json=bad_payload)
    assert response.status_code == 400

    # Verify dead letter queue recorded the failure
    assert dead_letter_queue.count() >= 1
    recent_failures = dead_letter_queue.get_failures(limit=5)
    assert any("Validation failed" in f["error"] for f in recent_failures)

    # Verify via dead-letter inspection endpoint
    dl_resp = client.get("/api/events/dead-letter")
    assert dl_resp.status_code == 200
    assert len(dl_resp.json()) >= 1


def test_persistence_and_retrieval_via_api(client: TestClient):
    """Verify ingested events are persisted to SQLite and retrievable via GET /api/events."""
    unique_user = f"test.verify.{int(time.time())}"
    payload = {
        "source_ip": "192.168.1.99",
        "user_id": unique_user,
        "login_result": "SUCCESS",
        "auth_method": "SSO",
    }
    post_res = client.post("/api/events", json=payload)
    assert post_res.status_code == 202
    event_id = post_res.json()["event_ids"][0]

    # Allow background consumer a brief moment to persist if running asynchronously
    time.sleep(0.6)

    # Retrieve events
    get_res = client.get(f"/api/events?user_id={unique_user}")
    assert get_res.status_code == 200
    events = get_res.json()
    assert len(events) >= 1
    matched = [e for e in events if e["event_id"] == event_id]
    assert len(matched) == 1
    assert matched[0]["user_id"] == unique_user
    assert matched[0]["source_type"] == "AUTH"
