"""Unit tests for FeatureRepository in SQLite."""

from datetime import datetime, timezone
import uuid
from backend.db.session import SessionLocal
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.repositories.feature_repository import FeatureRepository


def test_feature_snapshot_create_and_retrieve():
    """Verify persisting a FeatureSnapshot to SQLite and retrieving it by snapshot_id."""
    db = SessionLocal()
    try:
        repo = FeatureRepository(db)
        snapshot_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        snapshot = FeatureSnapshot(
            snapshot_id=snapshot_id,
            timestamp=now,
            window_seconds=60,
            window_start=now,
            window_end=now,
            entity_type=EntityType.USER,
            entity_id="test.user",
            event_count=5,
            features={"failed_login_rate": 0.20, "success_rate": 0.80},
            relationships={"ip_to_accounts": {"10.0.0.1": ["test.user"]}},
        )

        db_rec = repo.create_snapshot(snapshot)
        assert db_rec.id is not None
        assert db_rec.snapshot_id == snapshot_id

        fetched = repo.get_by_snapshot_id(snapshot_id)
        assert fetched is not None
        assert fetched.entity_id == "test.user"
        assert fetched.features["success_rate"] == 0.80

        schema = fetched.to_schema()
        assert schema.snapshot_id == snapshot_id
        assert schema.entity_type == EntityType.USER
    finally:
        db.close()


def test_feature_repository_filtering_and_batches():
    """Verify querying snapshots with entity and window filters."""
    db = SessionLocal()
    try:
        repo = FeatureRepository(db)
        now = datetime.now(timezone.utc)
        snapshots = [
            FeatureSnapshot(
                window_seconds=60,
                window_start=now,
                window_end=now,
                entity_type=EntityType.IP,
                entity_id="192.168.1.10",
                features={"connection_rate": 2.5},
            ),
            FeatureSnapshot(
                window_seconds=300,
                window_start=now,
                window_end=now,
                entity_type=EntityType.GLOBAL,
                entity_id="GLOBAL",
                features={"connection_rate": 10.0},
            ),
        ]

        batch_created = repo.create_batch_snapshots(snapshots)
        assert len(batch_created) == 2

        ip_snaps = repo.get_snapshots(entity_id="192.168.1.10", window_seconds=60)
        assert len(ip_snaps) >= 1
        assert ip_snaps[0].entity_id == "192.168.1.10"

        recent = repo.get_recent_snapshots(window_seconds=300, limit=5)
        assert any(s.entity_id == "GLOBAL" for s in recent)
    finally:
        db.close()
