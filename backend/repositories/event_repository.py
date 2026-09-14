"""Repository for persisting and querying telemetry events.

Provides a clean data abstraction layer decoupling the database implementation
from the ingestion queue and future anomaly detection engines.
"""

from typing import List, Optional
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.models.canonical import CanonicalEvent
from backend.models.db_event import TelemetryEventDB
from backend.repositories.base import BaseRepository


class EventRepository(BaseRepository[TelemetryEventDB]):
    """Repository handling telemetry events data persistence and retrieval."""

    def __init__(self, db: Session):
        super().__init__(TelemetryEventDB, db)

    def create_event(self, event: CanonicalEvent) -> TelemetryEventDB:
        """Persist a single canonical telemetry event into the database."""
        db_obj = TelemetryEventDB.from_canonical(event)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def create_batch_events(self, events: List[CanonicalEvent]) -> List[TelemetryEventDB]:
        """Persist a batch of canonical telemetry events efficiently."""
        if not events:
            return []

        db_objects = [TelemetryEventDB.from_canonical(e) for e in events]
        self.db.add_all(db_objects)
        self.db.commit()
        for db_obj in db_objects:
            self.db.refresh(db_obj)
        return db_objects

    def get_events(
        self,
        skip: int = 0,
        limit: int = 100,
        source_type: Optional[str] = None,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> List[TelemetryEventDB]:
        """Query events with filtering and pagination."""
        query = self.db.query(TelemetryEventDB)

        if source_type:
            query = query.filter(TelemetryEventDB.source_type == source_type.upper())
        if user_id:
            query = query.filter(TelemetryEventDB.user_id == user_id)
        if event_type:
            query = query.filter(TelemetryEventDB.event_type == event_type.upper())
        if source_ip:
            query = query.filter(TelemetryEventDB.source_ip == source_ip)

        return query.order_by(desc(TelemetryEventDB.timestamp)).offset(skip).limit(limit).all()

    def get_recent_events(
        self,
        limit: int = 100,
        source_type: Optional[str] = None,
    ) -> List[TelemetryEventDB]:
        """Fetch the most recent telemetry events."""
        return self.get_events(skip=0, limit=limit, source_type=source_type)

    def get_by_event_id(self, event_id: str) -> Optional[TelemetryEventDB]:
        """Fetch a specific event by its unique UUID event_id."""
        return self.db.query(TelemetryEventDB).filter(TelemetryEventDB.event_id == event_id).first()
