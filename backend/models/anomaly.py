"""SQLAlchemy ORM model for storing anomaly detection results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import (
    Column,
    Integer,
    Float,
    String,
    Boolean,
    DateTime,
    JSON,
    Index,
)
from backend.db.base import Base

if TYPE_CHECKING:
    from backend.detection.schemas import (
        StatisticalAnomalyResult,
        IsolationForestAnomalyResult,
        BehavioralClusteringAnomalyResult,
    )


class AnomalyResultDB(Base):
    """Database table storing anomaly detection evidence and results across detectors."""

    __tablename__ = "anomaly_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    result_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    detector_type = Column(String(32), index=True, nullable=False, default="STATISTICAL_ZSCORE")
    entity_type = Column(String(32), index=True, nullable=False)
    entity_id = Column(String(128), index=True, nullable=False)
    snapshot_id = Column(String(64), index=True, nullable=False)
    window_seconds = Column(Integer, index=True, nullable=False)
    feature_name = Column(String(64), index=True, nullable=False)
    current_value = Column(Float, nullable=False)
    baseline_mean = Column(Float, nullable=True)
    baseline_stddev = Column(Float, nullable=True)
    sample_count = Column(Integer, default=0, nullable=False)
    signed_z_score = Column(Float, nullable=True)
    absolute_z_score = Column(Float, nullable=True)
    is_anomalous = Column(Boolean, index=True, default=False, nullable=False)
    anomaly_score = Column(Float, default=0.0, nullable=False)
    explanation = Column(String, nullable=False)
    status = Column(String(32), index=True, default="NORMAL", nullable=False)
    details = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_anomaly_entity_time", "entity_type", "entity_id", "timestamp"),
        Index("ix_anomaly_detector_status", "detector_type", "is_anomalous", "timestamp"),
    )

    @classmethod
    def from_schema(cls, result: "StatisticalAnomalyResult") -> "AnomalyResultDB":
        """Convert a StatisticalAnomalyResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        return cls(
            result_id=result.result_id,
            timestamp=result.timestamp,
            detector_type=result.detector_type,
            entity_type=str(et),
            entity_id=result.entity_id,
            snapshot_id=result.snapshot_id,
            window_seconds=result.window_seconds,
            feature_name=result.feature_name,
            current_value=float(result.current_value),
            baseline_mean=float(result.baseline_mean) if result.baseline_mean is not None else None,
            baseline_stddev=float(result.baseline_stddev) if result.baseline_stddev is not None else None,
            sample_count=int(result.sample_count),
            signed_z_score=float(result.signed_z_score) if result.signed_z_score is not None else None,
            absolute_z_score=float(result.absolute_z_score) if result.absolute_z_score is not None else None,
            is_anomalous=bool(result.is_anomalous),
            anomaly_score=float(result.anomaly_score),
            explanation=str(result.explanation),
            status=str(result.status),
            details=result.details or {},
        )

    def to_schema(self) -> "StatisticalAnomalyResult":
        """Convert this database ORM instance back into a StatisticalAnomalyResult Pydantic model."""
        from backend.detection.schemas import StatisticalAnomalyResult
        from backend.features.schemas import EntityType

        return StatisticalAnomalyResult(
            result_id=self.result_id,
            timestamp=self.timestamp,
            detector_type=self.detector_type,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            snapshot_id=self.snapshot_id,
            window_seconds=self.window_seconds,
            feature_name=self.feature_name,
            current_value=self.current_value,
            baseline_mean=self.baseline_mean,
            baseline_stddev=self.baseline_stddev,
            sample_count=self.sample_count,
            signed_z_score=self.signed_z_score,
            absolute_z_score=self.absolute_z_score,
            is_anomalous=self.is_anomalous,
            anomaly_score=self.anomaly_score,
            explanation=self.explanation,
            status=self.status,
            details=self.details or {},
        )

    @classmethod
    def from_isolation_forest_schema(
        cls, result: "IsolationForestAnomalyResult"
    ) -> "AnomalyResultDB":
        """Convert an IsolationForestAnomalyResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        details = dict(result.details or {})
        details["top_feature_deviations"] = [
            dev.model_dump() for dev in result.top_feature_deviations
        ]
        details["raw_decision_score"] = float(result.raw_decision_score)
        details["raw_prediction"] = int(result.raw_prediction)
        details["normalized_anomaly_score"] = float(result.normalized_anomaly_score)

        return cls(
            result_id=result.result_id,
            timestamp=result.timestamp,
            detector_type=result.detector_type,
            entity_type=str(et),
            entity_id=result.entity_id,
            snapshot_id=result.snapshot_id,
            window_seconds=result.window_seconds,
            feature_name=result.feature_name,
            current_value=float(result.raw_decision_score),
            baseline_mean=None,
            baseline_stddev=None,
            sample_count=details.get("training_sample_count", 0),
            signed_z_score=None,
            absolute_z_score=None,
            is_anomalous=bool(result.is_anomalous),
            anomaly_score=float(result.normalized_anomaly_score),
            explanation=str(result.explanation),
            status=str(result.status),
            details=details,
        )

    def to_isolation_forest_schema(self) -> "IsolationForestAnomalyResult":
        """Convert this database ORM instance back into an IsolationForestAnomalyResult."""
        from backend.detection.schemas import (
            IsolationForestAnomalyResult,
            TopFeatureDeviation,
        )
        from backend.features.schemas import EntityType

        details = self.details or {}
        raw_score = details.get("raw_decision_score", self.current_value)
        raw_pred = details.get("raw_prediction", -1 if self.is_anomalous else 1)
        norm_score = details.get("normalized_anomaly_score", self.anomaly_score)

        raw_deviations = details.get("top_feature_deviations", [])
        deviations = [
            TopFeatureDeviation(**d) if isinstance(d, dict) else d
            for d in raw_deviations
        ]

        return IsolationForestAnomalyResult(
            result_id=self.result_id,
            timestamp=self.timestamp,
            detector_type=self.detector_type,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            snapshot_id=self.snapshot_id,
            window_seconds=self.window_seconds,
            feature_name=self.feature_name,
            raw_decision_score=float(raw_score),
            raw_prediction=int(raw_pred),
            normalized_anomaly_score=float(norm_score),
            is_anomalous=self.is_anomalous,
            anomaly_score=self.anomaly_score,
            explanation=self.explanation,
            status=self.status,
            top_feature_deviations=deviations,
            details=details,
        )

    @classmethod
    def from_clustering_schema(
        cls, result: "BehavioralClusteringAnomalyResult"
    ) -> "AnomalyResultDB":
        """Convert a BehavioralClusteringAnomalyResult Pydantic schema to an ORM entity."""
        et = result.entity_type
        if hasattr(et, "value"):
            et = et.value

        details = dict(result.details or {})
        details["assigned_cluster_id"] = int(result.assigned_cluster_id)
        details["cluster_distance"] = float(result.cluster_distance)
        details["threshold_distance"] = float(result.threshold_distance)
        details["distance_ratio"] = float(result.distance_ratio)
        details["normalized_anomaly_score"] = float(result.normalized_anomaly_score)
        details["cluster_characteristics"] = list(result.cluster_characteristics)
        details["pca_coordinates"] = list(result.pca_coordinates) if result.pca_coordinates else None
        details["top_feature_deviations"] = [
            dev.model_dump() for dev in result.top_feature_deviations
        ]

        return cls(
            result_id=result.result_id,
            timestamp=result.timestamp,
            detector_type=result.detector_type,
            entity_type=str(et),
            entity_id=result.entity_id,
            snapshot_id=result.snapshot_id,
            window_seconds=result.window_seconds,
            feature_name=result.feature_name,
            current_value=float(result.cluster_distance),
            baseline_mean=float(result.threshold_distance),
            baseline_stddev=None,
            sample_count=details.get("training_sample_count", 0),
            signed_z_score=None,
            absolute_z_score=float(result.distance_ratio),
            is_anomalous=bool(result.is_anomalous),
            anomaly_score=float(result.normalized_anomaly_score),
            explanation=str(result.explanation),
            status=str(result.status),
            details=details,
        )

    def to_clustering_schema(self) -> "BehavioralClusteringAnomalyResult":
        """Convert this database ORM instance back into a BehavioralClusteringAnomalyResult."""
        from backend.detection.schemas import (
            BehavioralClusteringAnomalyResult,
            ClusterFeatureDeviation,
        )
        from backend.features.schemas import EntityType

        details = self.details or {}
        cluster_id = details.get("assigned_cluster_id", 0)
        dist = details.get("cluster_distance", self.current_value)
        thresh = details.get("threshold_distance", self.baseline_mean or 0.0)
        ratio = details.get("distance_ratio", self.absolute_z_score or 0.0)
        norm_score = details.get("normalized_anomaly_score", self.anomaly_score)
        characteristics = details.get("cluster_characteristics", [])
        pca_coords = details.get("pca_coordinates")

        raw_deviations = details.get("top_feature_deviations", [])
        deviations = [
            ClusterFeatureDeviation(**d) if isinstance(d, dict) else d
            for d in raw_deviations
        ]

        return BehavioralClusteringAnomalyResult(
            result_id=self.result_id,
            timestamp=self.timestamp,
            detector_type=self.detector_type,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            snapshot_id=self.snapshot_id,
            window_seconds=self.window_seconds,
            feature_name=self.feature_name,
            assigned_cluster_id=int(cluster_id),
            cluster_distance=float(dist),
            threshold_distance=float(thresh),
            distance_ratio=float(ratio),
            is_anomalous=self.is_anomalous,
            anomaly_score=self.anomaly_score,
            normalized_anomaly_score=float(norm_score),
            explanation=self.explanation,
            status=self.status,
            top_feature_deviations=deviations,
            cluster_characteristics=characteristics,
            pca_coordinates=pca_coords,
            details=details,
        )
