"""SQLAlchemy ORM model for persisting behavioral feature snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    Index,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.features.schemas import FeatureSnapshot

from backend.db.base import Base


class FeatureSnapshotDB(Base):
    """Database table storing computed behavioral feature vectors over time windows."""

    __tablename__ = "feature_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    window_seconds = Column(Integer, index=True, nullable=False)
    window_start = Column(DateTime(timezone=True), index=True, nullable=False)
    window_end = Column(DateTime(timezone=True), index=True, nullable=False)
    entity_type = Column(String(32), index=True, nullable=False)
    entity_id = Column(String(128), index=True, nullable=False)
    event_count = Column(Integer, default=0, nullable=False)
    features = Column(JSON, nullable=False)
    relationships = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_snapshot_entity_time", "entity_type", "entity_id", "timestamp"),
        Index("ix_snapshot_window_time", "window_seconds", "timestamp"),
    )

    @classmethod
    def from_schema(cls, snapshot: "FeatureSnapshot") -> "FeatureSnapshotDB":
        """Convert a FeatureSnapshot Pydantic instance to an ORM entity."""
        et = snapshot.entity_type
        if hasattr(et, "value"):
            et = et.value

        return cls(
            snapshot_id=snapshot.snapshot_id,
            timestamp=snapshot.timestamp,
            window_seconds=snapshot.window_seconds,
            window_start=snapshot.window_start,
            window_end=snapshot.window_end,
            entity_type=str(et),
            entity_id=snapshot.entity_id,
            event_count=snapshot.event_count,
            features=snapshot.features,
            relationships=snapshot.relationships,
        )

    def to_schema(self) -> "FeatureSnapshot":
        """Convert this database ORM instance back into a FeatureSnapshot Pydantic model."""
        from backend.features.schemas import FeatureSnapshot, EntityType

        return FeatureSnapshot(
            snapshot_id=self.snapshot_id,
            timestamp=self.timestamp,
            window_seconds=self.window_seconds,
            window_start=self.window_start,
            window_end=self.window_end,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            event_count=self.event_count,
            features=self.features or {},
            relationships=self.relationships or {},
        )
