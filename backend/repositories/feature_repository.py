"""Repository for persisting and querying behavioral feature snapshots."""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.features.schemas import FeatureSnapshot

from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.base import BaseRepository


class FeatureRepository(BaseRepository[FeatureSnapshotDB]):
    """Data access layer for behavioral feature snapshots."""

    def __init__(self, db: Session):
        super().__init__(FeatureSnapshotDB, db)

    def create_snapshot(self, snapshot: FeatureSnapshot) -> FeatureSnapshotDB:
        """Persist a single feature snapshot."""
        db_obj = FeatureSnapshotDB.from_schema(snapshot)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def create_batch_snapshots(self, snapshots: List[FeatureSnapshot]) -> List[FeatureSnapshotDB]:
        """Persist multiple feature snapshots efficiently."""
        if not snapshots:
            return []
        db_objs = [FeatureSnapshotDB.from_schema(s) for s in snapshots]
        self.db.add_all(db_objs)
        self.db.commit()
        for obj in db_objs:
            self.db.refresh(obj)
        return db_objs

    def get_snapshots(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[FeatureSnapshotDB]:
        """Query feature snapshots with filtering and pagination."""
        query = self.db.query(FeatureSnapshotDB)

        if entity_id:
            query = query.filter(FeatureSnapshotDB.entity_id == entity_id)
        if entity_type:
            query = query.filter(FeatureSnapshotDB.entity_type == entity_type.upper())
        if window_seconds is not None:
            query = query.filter(FeatureSnapshotDB.window_seconds == window_seconds)

        return query.order_by(desc(FeatureSnapshotDB.timestamp)).offset(skip).limit(limit).all()

    def get_recent_snapshots(
        self,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        window_seconds: Optional[int] = None,
        limit: int = 50,
    ) -> List[FeatureSnapshotDB]:
        """Fetch latest snapshots."""
        return self.get_snapshots(
            skip=0,
            limit=limit,
            entity_id=entity_id,
            entity_type=entity_type,
            window_seconds=window_seconds,
        )

    def get_by_snapshot_id(self, snapshot_id: str) -> Optional[FeatureSnapshotDB]:
        """Retrieve a specific snapshot by UUID snapshot_id."""
        return self.db.query(FeatureSnapshotDB).filter(FeatureSnapshotDB.snapshot_id == snapshot_id).first()
