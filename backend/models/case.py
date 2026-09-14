"""SQLAlchemy ORM model for SOC incident cases."""

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
    from backend.alerts.schemas import CaseResult


class CaseDB(Base):
    """Database table storing correlated SOC incident cases."""

    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), unique=True, index=True, nullable=False)
    entity_type = Column(String(32), index=True, nullable=False)
    entity_id = Column(String(128), index=True, nullable=False)
    title = Column(String(256), nullable=False)
    summary = Column(String, nullable=False)
    opened_at = Column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    status = Column(String(32), index=True, nullable=False, default="OPEN")
    severity = Column(String(32), index=True, nullable=False)
    total_risk_score = Column(Float, nullable=False)
    alert_count = Column(Integer, nullable=False, default=1)
    kill_chain_stages = Column(JSON, nullable=False)
    affected_entities = Column(JSON, nullable=False)
    evidence_summary = Column(JSON, nullable=False)
    risk_history = Column(JSON, nullable=False)
    assigned_to = Column(String(128), nullable=True)
    resolution = Column(String(64), nullable=True, default=None)
    resolution_notes = Column(String, nullable=True)

    __table_args__ = (
        Index("ix_cases_entity_opened", "entity_type", "entity_id", "opened_at"),
        Index("ix_cases_status_opened", "status", "opened_at"),
        Index("ix_cases_severity_opened", "severity", "opened_at"),
    )

    @classmethod
    def from_schema(cls, result: "CaseResult") -> "CaseDB":
        """Convert a CaseResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        sev = result.severity
        if hasattr(sev, "value"):
            sev = sev.value

        st = result.status
        if hasattr(st, "value"):
            st = st.value

        assigned = result.assigned_analyst or result.assigned_to

        return cls(
            case_id=result.case_id,
            entity_type=str(et),
            entity_id=result.entity_id,
            title=result.title,
            summary=result.summary,
            opened_at=result.opened_at,
            updated_at=result.updated_at,
            status=str(st),
            severity=str(sev),
            total_risk_score=float(result.total_risk_score),
            alert_count=int(result.alert_count),
            kill_chain_stages=result.kill_chain_stages or [],
            affected_entities=result.affected_entities or {},
            evidence_summary=result.evidence_summary or {},
            risk_history=result.risk_history or [],
            assigned_to=assigned,
            resolution=result.resolution,
            resolution_notes=result.resolution_notes,
        )

    def to_schema(self) -> "CaseResult":
        """Convert this database ORM instance back into a CaseResult Pydantic schema."""
        from backend.features.schemas import EntityType
        from backend.risk.schemas import RiskSeverity
        from backend.alerts.schemas import CaseResult, CaseStatus

        return CaseResult(
            case_id=self.case_id,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            title=self.title,
            summary=self.summary,
            opened_at=self.opened_at,
            updated_at=self.updated_at,
            status=CaseStatus(self.status),
            severity=RiskSeverity(self.severity),
            total_risk_score=self.total_risk_score,
            alert_count=self.alert_count,
            kill_chain_stages=self.kill_chain_stages or [],
            affected_entities=self.affected_entities or {},
            evidence_summary=self.evidence_summary or {},
            risk_history=self.risk_history or [],
            assigned_to=self.assigned_to,
            assigned_analyst=self.assigned_to,
            resolution=self.resolution,
            resolution_notes=self.resolution_notes,
        )
