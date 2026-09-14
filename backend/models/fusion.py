"""SQLAlchemy ORM model for storing anomaly fusion results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    Index,
)
from backend.db.base import Base

if TYPE_CHECKING:
    from backend.detection.schemas import FusionResult


class FusionResultDB(Base):
    """Database table storing multi-detector anomaly fusion evaluations."""

    __tablename__ = "fusion_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fusion_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    entity_type = Column(String(32), index=True, nullable=False)
    entity_id = Column(String(128), index=True, nullable=False)
    snapshot_id = Column(String(64), index=True, nullable=True)
    window_seconds = Column(Integer, index=True, nullable=True)
    independent_detector_count = Column(Integer, nullable=False, default=0)
    anomalous_detector_count = Column(Integer, nullable=False, default=0)
    evidence_strength = Column(String(32), index=True, nullable=False)
    contributing_detectors = Column(JSON, nullable=False)
    explanation = Column(String, nullable=False)
    detector_results = Column(JSON, nullable=False)
    correlation_window_seconds = Column(Integer, nullable=False, default=300)
    details = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_fusion_entity_time", "entity_type", "entity_id", "timestamp"),
        Index("ix_fusion_strength_time", "evidence_strength", "timestamp"),
    )

    @classmethod
    def from_schema(cls, result: "FusionResult") -> "FusionResultDB":
        """Convert a FusionResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        strength = result.evidence_strength
        if hasattr(strength, "value"):
            strength = strength.value

        serialized_detector_results = [
            ev.model_dump(mode="json") if hasattr(ev, "model_dump") else ev
            for ev in result.detector_results
        ]

        return cls(
            fusion_id=result.fusion_id,
            timestamp=result.timestamp,
            entity_type=str(et),
            entity_id=result.entity_id,
            snapshot_id=result.snapshot_id,
            window_seconds=result.window_seconds,
            independent_detector_count=int(result.independent_detector_count),
            anomalous_detector_count=int(result.anomalous_detector_count),
            evidence_strength=str(strength),
            contributing_detectors=list(result.contributing_detectors),
            explanation=str(result.fusion_explanation),
            detector_results=serialized_detector_results,
            correlation_window_seconds=int(result.correlation_window_seconds),
            details=result.details or {},
        )

    def to_schema(self) -> "FusionResult":
        """Convert this database ORM instance back into a FusionResult Pydantic schema."""
        from backend.detection.schemas import (
            EvidenceStrength,
            FusionDetectorEvidence,
            FusionResult,
        )
        from backend.features.schemas import EntityType

        raw_evidences = self.detector_results or []
        parsed_evidences = [
            FusionDetectorEvidence(**ev) if isinstance(ev, dict) else ev
            for ev in raw_evidences
        ]

        return FusionResult(
            fusion_id=self.fusion_id,
            timestamp=self.timestamp,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            snapshot_id=self.snapshot_id,
            window_seconds=self.window_seconds,
            independent_detector_count=self.independent_detector_count,
            anomalous_detector_count=self.anomalous_detector_count,
            evidence_strength=EvidenceStrength(self.evidence_strength),
            contributing_detectors=self.contributing_detectors or [],
            detector_results=parsed_evidences,
            fusion_explanation=self.explanation,
            correlation_window_seconds=self.correlation_window_seconds,
            details=self.details or {},
        )
