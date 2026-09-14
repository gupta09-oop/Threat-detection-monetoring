"""Repository for persisting and querying anomaly fusion results."""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.detection.schemas import FusionResult

from backend.models.fusion import FusionResultDB
from backend.repositories.base import BaseRepository


class FusionRepository(BaseRepository[FusionResultDB]):
    """Data access layer for anomaly fusion evidence evaluations."""

    def __init__(self, db: Session):
        super().__init__(FusionResultDB, db)

    def create_result(self, result: "FusionResult") -> FusionResultDB:
        """Persist an anomaly fusion result."""
        db_obj = FusionResultDB.from_schema(result)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def create_batch_results(self, results: List["FusionResult"]) -> List[FusionResultDB]:
        """Persist a batch of anomaly fusion results."""
        if not results:
            return []
        db_objs = [FusionResultDB.from_schema(r) for r in results]
        self.db.add_all(db_objs)
        self.db.commit()
        for obj in db_objs:
            self.db.refresh(obj)
        return db_objs

    def get_by_fusion_id(self, fusion_id: str) -> Optional[FusionResultDB]:
        """Retrieve a specific fusion result by UUID."""
        return (
            self.db.query(FusionResultDB)
            .filter(FusionResultDB.fusion_id == fusion_id)
            .first()
        )

    def get_by_snapshot_id(self, snapshot_id: str) -> List[FusionResultDB]:
        """Retrieve fusion results for a specific feature snapshot."""
        return (
            self.db.query(FusionResultDB)
            .filter(FusionResultDB.snapshot_id == snapshot_id)
            .order_by(desc(FusionResultDB.timestamp))
            .all()
        )

    def get_by_entity(
        self,
        entity_id: str,
        limit: int = 100,
        skip: int = 0,
    ) -> List[FusionResultDB]:
        """Retrieve fusion results for a specific entity ID."""
        return (
            self.db.query(FusionResultDB)
            .filter(FusionResultDB.entity_id == entity_id)
            .order_by(desc(FusionResultDB.timestamp))
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_results(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        evidence_strength: Optional[str] = None,
        snapshot_id: Optional[str] = None,
    ) -> List[FusionResultDB]:
        """Query fusion results with filtering and pagination."""
        query = self.db.query(FusionResultDB)

        if entity_type:
            query = query.filter(FusionResultDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(FusionResultDB.entity_id == entity_id)
        if evidence_strength:
            query = query.filter(FusionResultDB.evidence_strength == evidence_strength.upper())
        if snapshot_id:
            query = query.filter(FusionResultDB.snapshot_id == snapshot_id)

        return (
            query.order_by(desc(FusionResultDB.timestamp))
            .offset(skip)
            .limit(limit)
            .all()
        )
