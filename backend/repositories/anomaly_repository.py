"""Repository for persisting and querying anomaly detection results."""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.detection.schemas import (
        StatisticalAnomalyResult,
        IsolationForestAnomalyResult,
        BehavioralClusteringAnomalyResult,
    )

from backend.models.anomaly import AnomalyResultDB
from backend.repositories.base import BaseRepository


class AnomalyRepository(BaseRepository[AnomalyResultDB]):
    """Data access layer for anomaly detection evidence and results."""

    def __init__(self, db: Session):
        super().__init__(AnomalyResultDB, db)

    def create_result(self, result: "StatisticalAnomalyResult") -> AnomalyResultDB:
        """Persist an anomaly detection result."""
        db_obj = AnomalyResultDB.from_schema(result)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def create_batch_results(self, results: List["StatisticalAnomalyResult"]) -> List[AnomalyResultDB]:
        """Persist a batch of anomaly detection results."""
        if not results:
            return []
        db_objs = [AnomalyResultDB.from_schema(r) for r in results]
        self.db.add_all(db_objs)
        self.db.commit()
        for obj in db_objs:
            self.db.refresh(obj)
        return db_objs

    def create_isolation_forest_result(
        self, result: "IsolationForestAnomalyResult"
    ) -> AnomalyResultDB:
        """Persist an Isolation Forest anomaly detection result."""
        db_obj = AnomalyResultDB.from_isolation_forest_schema(result)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def create_isolation_forest_batch(
        self, results: List["IsolationForestAnomalyResult"]
    ) -> List[AnomalyResultDB]:
        """Persist a batch of Isolation Forest anomaly detection results."""
        if not results:
            return []
        db_objs = [
            AnomalyResultDB.from_isolation_forest_schema(r) for r in results
        ]
        self.db.add_all(db_objs)
        self.db.commit()
        for obj in db_objs:
            self.db.refresh(obj)
        return db_objs

    def create_clustering_result(
        self, result: "BehavioralClusteringAnomalyResult"
    ) -> AnomalyResultDB:
        """Persist a Behavioral Clustering anomaly detection result."""
        db_obj = AnomalyResultDB.from_clustering_schema(result)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def create_clustering_batch(
        self, results: List["BehavioralClusteringAnomalyResult"]
    ) -> List[AnomalyResultDB]:
        """Persist a batch of Behavioral Clustering anomaly detection results."""
        if not results:
            return []
        db_objs = [
            AnomalyResultDB.from_clustering_schema(r) for r in results
        ]
        self.db.add_all(db_objs)
        self.db.commit()
        for obj in db_objs:
            self.db.refresh(obj)
        return db_objs

    def get_results(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        detector_type: Optional[str] = None,
        is_anomalous: Optional[bool] = None,
        status: Optional[str] = None,
    ) -> List[AnomalyResultDB]:
        """Query anomaly results with filtering and pagination."""
        query = self.db.query(AnomalyResultDB)

        if entity_type:
            query = query.filter(AnomalyResultDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(AnomalyResultDB.entity_id == entity_id)
        if detector_type:
            query = query.filter(AnomalyResultDB.detector_type == detector_type.upper())
        if is_anomalous is not None:
            query = query.filter(AnomalyResultDB.is_anomalous == is_anomalous)
        if status:
            query = query.filter(AnomalyResultDB.status == status.upper())

        return query.order_by(desc(AnomalyResultDB.timestamp)).offset(skip).limit(limit).all()

    def get_by_result_id(self, result_id: str) -> Optional[AnomalyResultDB]:
        """Retrieve specific anomaly result by UUID."""
        return self.db.query(AnomalyResultDB).filter(AnomalyResultDB.result_id == result_id).first()
