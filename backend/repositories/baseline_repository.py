"""Repository for persisting and querying statistical baselines."""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.detection.schemas import StatisticalBaseline

from backend.models.baseline import StatisticalBaselineDB
from backend.repositories.base import BaseRepository


class BaselineRepository(BaseRepository[StatisticalBaselineDB]):
    """Data access layer for statistical behavioral baselines."""

    def __init__(self, db: Session):
        super().__init__(StatisticalBaselineDB, db)

    def upsert_baseline(self, baseline: "StatisticalBaseline") -> StatisticalBaselineDB:
        """Insert or update a statistical baseline for an entity, window, and feature."""
        et = baseline.entity_type
        if hasattr(et, "value"):
            et = et.value

        existing = self.db.query(StatisticalBaselineDB).filter(
            StatisticalBaselineDB.entity_type == str(et),
            StatisticalBaselineDB.entity_id == baseline.entity_id,
            StatisticalBaselineDB.window_seconds == baseline.window_seconds,
            StatisticalBaselineDB.feature_name == baseline.feature_name,
        ).first()

        if existing:
            existing.mean = float(baseline.mean)
            existing.stddev = float(baseline.stddev)
            existing.sample_count = int(baseline.sample_count)
            existing.updated_at = baseline.updated_at
            self.db.commit()
            self.db.refresh(existing)
            return existing

        new_obj = StatisticalBaselineDB.from_schema(baseline)
        self.db.add(new_obj)
        self.db.commit()
        self.db.refresh(new_obj)
        return new_obj

    def batch_upsert_baselines(self, baselines: List["StatisticalBaseline"]) -> List[StatisticalBaselineDB]:
        """Batch upsert statistical baselines."""
        return [self.upsert_baseline(b) for b in baselines]

    def get_baseline(
        self,
        entity_type: str,
        entity_id: str,
        window_seconds: int,
        feature_name: str,
    ) -> Optional[StatisticalBaselineDB]:
        """Fetch exact baseline by entity, window, and feature name."""
        return self.db.query(StatisticalBaselineDB).filter(
            StatisticalBaselineDB.entity_type == entity_type.upper(),
            StatisticalBaselineDB.entity_id == entity_id,
            StatisticalBaselineDB.window_seconds == window_seconds,
            StatisticalBaselineDB.feature_name == feature_name,
        ).first()

    def get_baselines_for_entity(
        self,
        entity_type: str,
        entity_id: str,
        window_seconds: Optional[int] = None,
    ) -> List[StatisticalBaselineDB]:
        """Retrieve all feature baselines for a specific entity."""
        query = self.db.query(StatisticalBaselineDB).filter(
            StatisticalBaselineDB.entity_type == entity_type.upper(),
            StatisticalBaselineDB.entity_id == entity_id,
        )
        if window_seconds is not None:
            query = query.filter(StatisticalBaselineDB.window_seconds == window_seconds)
        return query.all()

    def get_all_baselines(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        feature_name: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[StatisticalBaselineDB]:
        """Query baselines with filtering and pagination."""
        query = self.db.query(StatisticalBaselineDB)
        if entity_type:
            query = query.filter(StatisticalBaselineDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(StatisticalBaselineDB.entity_id == entity_id)
        if feature_name:
            query = query.filter(StatisticalBaselineDB.feature_name == feature_name)
        if window_seconds is not None:
            query = query.filter(StatisticalBaselineDB.window_seconds == window_seconds)

        return query.order_by(desc(StatisticalBaselineDB.updated_at)).offset(skip).limit(limit).all()
