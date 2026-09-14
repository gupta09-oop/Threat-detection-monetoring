"""SQLAlchemy ORM model for security alerts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import (
    Column,
    Float,
    Integer,
    String,
    DateTime,
    JSON,
    Index,
)
from backend.db.base import Base

if TYPE_CHECKING:
    from backend.alerts.schemas import AlertResult


class AlertDB(Base):
    """Database table storing actionable security alerts generated from risk evaluations."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    risk_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    entity_type = Column(String(32), index=True, nullable=False)
    entity_id = Column(String(128), index=True, nullable=False)
    source_type = Column(String(32), nullable=True, default="BEHAVIORAL")
    severity = Column(String(32), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    title = Column(String(256), nullable=False)
    summary = Column(String, nullable=False)
    explanation = Column(String, nullable=False)
    contributor_breakdown = Column(JSON, nullable=False)
    evidence_strength = Column(String(32), nullable=False)
    contributing_detectors = Column(JSON, nullable=False)
    fusion_id = Column(String(64), index=True, nullable=True)
    snapshot_id = Column(String(64), index=True, nullable=True)
    case_id = Column(String(64), index=True, nullable=True)
    status = Column(String(32), index=True, nullable=False, default="NEW")
    occurrence_count = Column(Integer, nullable=False, default=1)
    dedup_key = Column(String(128), index=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    assigned_analyst = Column(String(128), nullable=True, default=None)
    resolution = Column(String(64), nullable=True, default=None)
    resolution_notes = Column(String, nullable=True, default=None)
    details = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_alerts_entity_time", "entity_type", "entity_id", "timestamp"),
        Index("ix_alerts_severity_time", "severity", "timestamp"),
        Index("ix_alerts_status_time", "status", "timestamp"),
        Index("ix_alerts_dedup", "entity_id", "dedup_key", "timestamp"),
    )

    @classmethod
    def from_schema(cls, result: "AlertResult") -> "AlertDB":
        """Convert an AlertResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        sev = result.severity
        if hasattr(sev, "value"):
            sev = sev.value

        st = result.status
        if hasattr(st, "value"):
            st = st.value

        cb = result.contributor_breakdown
        serialized_breakdown = (
            cb.model_dump(mode="json") if hasattr(cb, "model_dump") else cb
        )

        return cls(
            alert_id=result.alert_id,
            risk_id=result.risk_id,
            timestamp=result.timestamp,
            entity_type=str(et),
            entity_id=result.entity_id,
            source_type=result.source_type,
            severity=str(sev),
            risk_score=float(result.risk_score),
            title=result.title,
            summary=result.summary,
            explanation=result.explanation,
            contributor_breakdown=serialized_breakdown,
            evidence_strength=str(result.evidence_strength),
            contributing_detectors=result.contributing_detectors,
            fusion_id=result.fusion_id,
            snapshot_id=result.snapshot_id,
            case_id=result.case_id,
            status=str(st),
            occurrence_count=int(result.occurrence_count),
            dedup_key=result.dedup_key,
            created_at=result.created_at,
            updated_at=result.updated_at,
            assigned_analyst=result.assigned_analyst,
            resolution=result.resolution,
            resolution_notes=result.resolution_notes,
            details=result.details or {},
        )

    def to_schema(self) -> "AlertResult":
        """Convert this database ORM instance back into an AlertResult Pydantic schema."""
        from backend.features.schemas import EntityType
        from backend.risk.schemas import ContributorBreakdown, RiskSeverity
        from backend.alerts.schemas import AlertResult, AlertStatus

        raw_cb = self.contributor_breakdown or {}
        parsed_cb = (
            ContributorBreakdown(**raw_cb) if isinstance(raw_cb, dict) else raw_cb
        )

        return AlertResult(
            alert_id=self.alert_id,
            risk_id=self.risk_id,
            timestamp=self.timestamp,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            source_type=self.source_type,
            severity=RiskSeverity(self.severity),
            risk_score=self.risk_score,
            title=self.title,
            summary=self.summary,
            explanation=self.explanation,
            contributor_breakdown=parsed_cb,
            evidence_strength=self.evidence_strength,
            contributing_detectors=self.contributing_detectors or [],
            fusion_id=self.fusion_id,
            snapshot_id=self.snapshot_id,
            case_id=self.case_id,
            status=AlertStatus(self.status),
            occurrence_count=self.occurrence_count,
            dedup_key=self.dedup_key,
            created_at=self.created_at,
            updated_at=self.updated_at,
            assigned_analyst=self.assigned_analyst,
            resolution=self.resolution,
            resolution_notes=self.resolution_notes,
            details=self.details or {},
        )
