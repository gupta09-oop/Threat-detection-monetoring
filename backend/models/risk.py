"""SQLAlchemy ORM model for storing Threat Risk Score results."""

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
    from backend.risk.schemas import RiskScoreResult


class RiskScoreDB(Base):
    """Database table storing explainable Threat Risk Score evaluations."""

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    risk_id = Column(String(64), unique=True, index=True, nullable=False)
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
    final_score = Column(Float, nullable=False)
    severity = Column(String(32), index=True, nullable=False)
    statistical_contribution = Column(Float, nullable=False, default=0.0)
    isolation_forest_contribution = Column(Float, nullable=False, default=0.0)
    clustering_contribution = Column(Float, nullable=False, default=0.0)
    rules_contribution = Column(Float, nullable=False, default=0.0)
    correlation_contribution = Column(Float, nullable=False, default=0.0)
    evidence_strength = Column(String(32), nullable=False)
    contributor_breakdown = Column(JSON, nullable=False)
    explanation = Column(String, nullable=False)
    source_fusion_id = Column(String(64), index=True, nullable=True)
    details = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_risk_entity_time", "entity_type", "entity_id", "timestamp"),
        Index("ix_risk_severity_time", "severity", "timestamp"),
        Index("ix_risk_source_fusion", "source_fusion_id"),
    )

    @classmethod
    def from_schema(cls, result: "RiskScoreResult") -> "RiskScoreDB":
        """Convert a RiskScoreResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        sev = result.severity
        if hasattr(sev, "value"):
            sev = sev.value

        cb = result.contributor_breakdown
        serialized_breakdown = (
            cb.model_dump(mode="json") if hasattr(cb, "model_dump") else cb
        )

        return cls(
            risk_id=result.risk_id,
            timestamp=result.timestamp,
            entity_type=str(et),
            entity_id=result.entity_id,
            snapshot_id=result.snapshot_id,
            window_seconds=result.window_seconds,
            final_score=float(result.final_score),
            severity=str(sev),
            statistical_contribution=float(result.statistical_contribution),
            isolation_forest_contribution=float(result.isolation_forest_contribution),
            clustering_contribution=float(result.clustering_contribution),
            rules_contribution=float(result.rules_contribution),
            correlation_contribution=float(result.correlation_contribution),
            evidence_strength=str(result.evidence_strength),
            contributor_breakdown=serialized_breakdown,
            explanation=str(result.explanation),
            source_fusion_id=result.source_fusion_id,
            details=result.details or {},
        )

    def to_schema(self) -> "RiskScoreResult":
        """Convert this database ORM instance back into a RiskScoreResult Pydantic schema."""
        from backend.features.schemas import EntityType
        from backend.risk.schemas import (
            ContributorBreakdown,
            RiskScoreResult,
            RiskSeverity,
        )

        raw_cb = self.contributor_breakdown or {}
        parsed_cb = (
            ContributorBreakdown(**raw_cb) if isinstance(raw_cb, dict) else raw_cb
        )

        return RiskScoreResult(
            risk_id=self.risk_id,
            timestamp=self.timestamp,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            snapshot_id=self.snapshot_id,
            window_seconds=self.window_seconds,
            final_score=self.final_score,
            severity=RiskSeverity(self.severity),
            statistical_contribution=self.statistical_contribution,
            isolation_forest_contribution=self.isolation_forest_contribution,
            clustering_contribution=self.clustering_contribution,
            rules_contribution=self.rules_contribution,
            correlation_contribution=self.correlation_contribution,
            evidence_strength=self.evidence_strength,
            contributor_breakdown=parsed_cb,
            explanation=self.explanation,
            source_fusion_id=self.source_fusion_id,
            details=self.details or {},
        )
