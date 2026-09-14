"""Repository for persisting and querying Threat Risk Score results."""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.risk.schemas import RiskScoreResult

from backend.models.risk import RiskScoreDB
from backend.repositories.base import BaseRepository


class RiskRepository(BaseRepository[RiskScoreDB]):
    """Data access layer for Threat Risk Score evaluations."""

    def __init__(self, db: Session):
        super().__init__(RiskScoreDB, db)

    def create_score(self, score: "RiskScoreResult") -> RiskScoreDB:
        """Persist a Threat Risk Score result."""
        db_obj = RiskScoreDB.from_schema(score)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def get_by_risk_id(self, risk_id: str) -> Optional[RiskScoreDB]:
        """Retrieve a specific risk score record by UUID."""
        return (
            self.db.query(RiskScoreDB)
            .filter(RiskScoreDB.risk_id == risk_id)
            .first()
        )

    def get_by_source_fusion_id(self, source_fusion_id: str) -> Optional[RiskScoreDB]:
        """Retrieve risk score associated with a specific fusion evaluation."""
        return (
            self.db.query(RiskScoreDB)
            .filter(RiskScoreDB.source_fusion_id == source_fusion_id)
            .first()
        )

    def get_by_entity(self, entity_id: str) -> Optional[RiskScoreDB]:
        """Retrieve the latest risk score evaluation for an entity."""
        return (
            self.db.query(RiskScoreDB)
            .filter(RiskScoreDB.entity_id == entity_id)
            .order_by(desc(RiskScoreDB.timestamp))
            .first()
        )

    def get_entity_history(
        self, entity_id: str, limit: int = 100
    ) -> List[RiskScoreDB]:
        """Retrieve chronological history of risk score evaluations for an entity."""
        return (
            self.db.query(RiskScoreDB)
            .filter(RiskScoreDB.entity_id == entity_id)
            .order_by(desc(RiskScoreDB.timestamp))
            .limit(limit)
            .all()
        )

    def get_scores(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        severity: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        source_fusion_id: Optional[str] = None,
    ) -> List[RiskScoreDB]:
        """Query persisted risk scores with filtering and pagination."""
        query = self.db.query(RiskScoreDB)

        if entity_type:
            query = query.filter(RiskScoreDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(RiskScoreDB.entity_id == entity_id)
        if severity:
            query = query.filter(RiskScoreDB.severity == severity.upper())
        if snapshot_id:
            query = query.filter(RiskScoreDB.snapshot_id == snapshot_id)
        if source_fusion_id:
            query = query.filter(RiskScoreDB.source_fusion_id == source_fusion_id)

        return (
            query.order_by(desc(RiskScoreDB.timestamp))
            .offset(skip)
            .limit(limit)
            .all()
        )
