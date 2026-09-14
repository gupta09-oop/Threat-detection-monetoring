"""Behavioral feature engineering service for Sh4d0w_St4lk3r.

Orchestrates time-windowed event aggregation, behavioral feature calculation,
and database persistence of feature snapshots.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import List, Optional, Set
import uuid
from sqlalchemy.orm import Session

from backend.features.calculator import FeatureCalculator
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.windows import FeatureWindow
from backend.models.canonical import CanonicalEvent
from backend.models.db_event import TelemetryEventDB
from backend.repositories.feature_repository import FeatureRepository

logger = logging.getLogger(__name__)


class FeatureEngineeringService:
    """Service orchestrating behavioral feature extraction and snapshot generation."""

    def calculate_for_events(
        self,
        events: List[CanonicalEvent],
        window_seconds: int = FeatureWindow.WINDOW_60S,
        entity_type: EntityType = EntityType.GLOBAL,
        entity_id: str = "GLOBAL",
        window_end: Optional[datetime] = None,
    ) -> FeatureSnapshot:
        """Compute a feature snapshot from an in-memory list of canonical events."""
        end_time = window_end or datetime.now(timezone.utc)
        start_time = end_time - timedelta(seconds=window_seconds)

        calculator = FeatureCalculator(window_seconds=window_seconds)
        flat_features, relationships = calculator.calculate_all(events)

        return FeatureSnapshot(
            snapshot_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            window_seconds=window_seconds,
            window_start=start_time,
            window_end=end_time,
            entity_type=entity_type,
            entity_id=entity_id,
            event_count=len(events),
            features=flat_features,
            relationships=relationships,
        )

    def extract_and_persist_for_window(
        self,
        db: Session,
        window_seconds: int = FeatureWindow.WINDOW_60S,
        entity_type: EntityType = EntityType.GLOBAL,
        entity_id: str = "GLOBAL",
        window_end: Optional[datetime] = None,
    ) -> FeatureSnapshot:
        """Query canonical events in SQLite for the specified window, calculate features, and persist snapshot."""
        end_time = window_end or datetime.now(timezone.utc)
        start_time = end_time - timedelta(seconds=window_seconds)

        # Query events within the window range
        query = db.query(TelemetryEventDB).filter(
            TelemetryEventDB.timestamp >= start_time,
            TelemetryEventDB.timestamp <= end_time,
        )

        if entity_type == EntityType.USER and entity_id != "GLOBAL":
            query = query.filter(TelemetryEventDB.user_id == entity_id)
        elif entity_type == EntityType.IP and entity_id != "GLOBAL":
            query = query.filter(TelemetryEventDB.source_ip == entity_id)
        elif entity_type == EntityType.HOST and entity_id != "GLOBAL":
            query = query.filter(TelemetryEventDB.device_id == entity_id)

        db_events = query.all()
        canonical_events = [e.to_canonical() for e in db_events]

        calculator = FeatureCalculator(window_seconds=window_seconds)
        flat_features, relationships = calculator.calculate_all(canonical_events)

        snapshot = FeatureSnapshot(
            snapshot_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            window_seconds=window_seconds,
            window_start=start_time,
            window_end=end_time,
            entity_type=entity_type,
            entity_id=entity_id,
            event_count=len(canonical_events),
            features=flat_features,
            relationships=relationships,
        )

        # Persist to database via repository
        repo = FeatureRepository(db)
        repo.create_snapshot(snapshot)
        logger.debug(
            "Persisted feature snapshot [%s] for %s:%s (window=%ds, events=%d).",
            snapshot.snapshot_id,
            entity_type.value,
            entity_id,
            window_seconds,
            len(canonical_events),
        )

        return snapshot

    def generate_snapshots_for_active_entities(
        self,
        db: Session,
        window_seconds: int = FeatureWindow.WINDOW_60S,
        window_end: Optional[datetime] = None,
    ) -> List[FeatureSnapshot]:
        """Discover active users and IPs in the window and generate persisted snapshots for each, plus GLOBAL."""
        end_time = window_end or datetime.now(timezone.utc)
        start_time = end_time - timedelta(seconds=window_seconds)

        # Query all events in window
        db_events = db.query(TelemetryEventDB).filter(
            TelemetryEventDB.timestamp >= start_time,
            TelemetryEventDB.timestamp <= end_time,
        ).all()

        snapshots: List[FeatureSnapshot] = []

        # 1. Global Snapshot
        global_snapshot = self.extract_and_persist_for_window(
            db=db,
            window_seconds=window_seconds,
            entity_type=EntityType.GLOBAL,
            entity_id="GLOBAL",
            window_end=end_time,
        )
        snapshots.append(global_snapshot)

        # 2. Extract active distinct users and IPs
        active_users: Set[str] = {e.user_id for e in db_events if e.user_id}
        active_ips: Set[str] = {e.source_ip for e in db_events if e.source_ip}

        for user in sorted(active_users):
            snap = self.extract_and_persist_for_window(
                db=db,
                window_seconds=window_seconds,
                entity_type=EntityType.USER,
                entity_id=user,
                window_end=end_time,
            )
            snapshots.append(snap)

        for ip in sorted(active_ips):
            snap = self.extract_and_persist_for_window(
                db=db,
                window_seconds=window_seconds,
                entity_type=EntityType.IP,
                entity_id=ip,
                window_end=end_time,
            )
            snapshots.append(snap)

        return snapshots


# Global service instance
feature_service = FeatureEngineeringService()
