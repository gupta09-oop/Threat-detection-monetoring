"""Unit tests for EventRepository operations in SQLite."""

import uuid
from backend.db.session import SessionLocal
from backend.models.canonical import CanonicalEvent, SourceType
from backend.repositories.event_repository import EventRepository


def test_repository_create_and_retrieve_event():
    """Verify storing a canonical event in SQLite and retrieving it by event_id."""
    db = SessionLocal()
    try:
        repo = EventRepository(db)
        event_id = str(uuid.uuid4())
        event = CanonicalEvent(
            event_id=event_id,
            source_type=SourceType.AUTH,
            event_type="LOGIN",
            result="SUCCESS",
            user_id="repo.user",
            source_ip="192.168.10.5",
        )

        db_record = repo.create_event(event)
        assert db_record.id is not None
        assert db_record.event_id == event_id

        fetched = repo.get_by_event_id(event_id)
        assert fetched is not None
        assert fetched.user_id == "repo.user"
        assert fetched.source_ip == "192.168.10.5"

        canonical_back = fetched.to_canonical()
        assert canonical_back.event_id == event_id
        assert canonical_back.user_id == "repo.user"
    finally:
        db.close()


def test_repository_batch_create_and_filtering():
    """Verify batch insertion and query filtering by source_type."""
    db = SessionLocal()
    try:
        repo = EventRepository(db)
        events = [
            CanonicalEvent(
                source_type=SourceType.NETWORK,
                event_type="CONNECTION",
                result="ALLOW",
                destination_ip="10.0.1.50",
                port=443,
                protocol="TCP",
            ),
            CanonicalEvent(
                source_type=SourceType.SYSTEM,
                event_type="PROCESS_START",
                result="SUCCESS",
                device_id="SRV-LINUX-01",
            ),
        ]

        batch_results = repo.create_batch_events(events)
        assert len(batch_results) == 2

        net_events = repo.get_events(source_type="NETWORK", limit=10)
        assert any(e.destination_ip == "10.0.1.50" for e in net_events)

        recent = repo.get_recent_events(limit=5)
        assert len(recent) > 0
    finally:
        db.close()
