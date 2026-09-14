"""SQLAlchemy ORM model for persisting telemetry events in SQLite/PostgreSQL."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    BigInteger,
    String,
    DateTime,
    JSON,
    Index,
)
from backend.db.base import Base
from backend.models.canonical import CanonicalEvent, SourceType


class TelemetryEventDB(Base):
    """Database table for canonical telemetry events."""

    __tablename__ = "telemetry_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), index=True, nullable=False, default=lambda: datetime.now(timezone.utc))
    source_type = Column(String(32), index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), nullable=True)
    user_id = Column(String(64), index=True, nullable=True)
    device_id = Column(String(64), nullable=True)
    event_type = Column(String(64), index=True, nullable=False)
    action = Column(String(64), nullable=True)
    result = Column(String(32), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    bytes = Column(BigInteger, nullable=True)
    geo = Column(JSON, nullable=True)
    event_metadata = Column(JSON, nullable=True)

    # Composite index for temporal-source queries
    __table_args__ = (
        Index("ix_telemetry_timestamp_source", "timestamp", "source_type"),
        Index("ix_telemetry_user_timestamp", "user_id", "timestamp"),
    )

    @classmethod
    def from_canonical(cls, event: CanonicalEvent) -> "TelemetryEventDB":
        """Convert a CanonicalEvent Pydantic model to a SQLAlchemy ORM instance."""
        st = event.source_type
        if hasattr(st, "value"):
            st = st.value

        return cls(
            event_id=event.event_id,
            timestamp=event.timestamp,
            source_type=str(st),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            user_id=event.user_id,
            device_id=event.device_id,
            event_type=event.event_type,
            action=event.action,
            result=event.result,
            port=event.port,
            protocol=event.protocol,
            bytes=event.bytes,
            geo=event.geo,
            event_metadata=event.metadata,
        )

    def to_canonical(self) -> CanonicalEvent:
        """Convert this database model back into a CanonicalEvent Pydantic instance."""
        return CanonicalEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            source_type=SourceType(self.source_type),
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            user_id=self.user_id,
            device_id=self.device_id,
            event_type=self.event_type,
            action=self.action,
            result=self.result,
            port=self.port,
            protocol=self.protocol,
            bytes=self.bytes,
            geo=self.geo,
            metadata=self.event_metadata or {},
        )
