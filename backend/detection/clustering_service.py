"""Behavioral clustering service for model management, training, and evidence scoring in Sh4d0w_St4lk3r."""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
from sqlalchemy.orm import Session

from backend.config import settings
from backend.detection.behavioral_clustering import BehavioralClusteringDetector
from backend.detection.schemas import (
    BehavioralClusteringAnomalyResult,
    BehavioralClusteringModelStatus,
    BehavioralClusteringTrainResponse,
)
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import (
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    extract_feature_vector,
)
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.anomaly_repository import AnomalyRepository

logger = logging.getLogger(__name__)


class BehavioralClusteringService:
    """Service layer managing the lifecycle of the Behavioral Clustering detector."""

    def __init__(self, model_dir: Optional[str] = None, model_file: Optional[str] = None) -> None:
        self.model_dir = Path(model_dir or settings.CLUSTERING_MODEL_DIR)
        self.model_file = model_file or settings.CLUSTERING_MODEL_FILE
        self.model_path = self.model_dir / self.model_file

        self.detector: Optional[BehavioralClusteringDetector] = None

    @property
    def is_ready(self) -> bool:
        """Check if the clustering detector is fitted and available for inference."""
        return self.detector is not None and self.detector.is_fitted

    def get_status(self) -> BehavioralClusteringModelStatus:
        """Return structured model readiness and clustering metadata status."""
        if self.is_ready and self.detector is not None:
            return BehavioralClusteringModelStatus(
                is_ready=True,
                status="READY",
                message="Behavioral Clustering model is fitted and ready for inference.",
                model_path=str(self.model_path),
                trained_at=self.detector.trained_at,
                training_sample_count=self.detector.training_sample_count,
                n_clusters=self.detector.n_clusters,
                threshold_distance=self.detector.threshold_distance,
                feature_schema_version=self.detector.feature_schema_version,
                feature_count=FEATURE_COUNT,
                clusters=self.detector.cluster_profiles,
            )

        return BehavioralClusteringModelStatus(
            is_ready=False,
            status="NOT_READY",
            message=(
                f"Behavioral Clustering model is not trained or loaded. "
                f"Requires at least {settings.CLUSTERING_MIN_TRAINING_SAMPLES} normal training snapshots."
            ),
            model_path=str(self.model_path),
            trained_at=None,
            training_sample_count=0,
            n_clusters=settings.CLUSTERING_N_CLUSTERS,
            threshold_distance=0.0,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_count=FEATURE_COUNT,
            clusters=[],
        )

    def try_load_model(self) -> bool:
        """Attempt to load existing model artifact from disk on application startup.
        
        Gracefully handles missing or uninitialized artifacts without throwing exceptions.
        """
        if not self.model_path.exists():
            logger.info(
                "Behavioral Clustering artifact not found at %s. Detector starting in NOT_READY state.",
                self.model_path,
            )
            return False

        try:
            state = joblib.load(self.model_path)
            detector = BehavioralClusteringDetector()
            detector.set_state(state)
            self.detector = detector
            logger.info(
                "Behavioral Clustering artifact loaded from %s (k=%d, samples=%d, thresh=%.4f).",
                self.model_path,
                detector.n_clusters,
                detector.training_sample_count,
                detector.threshold_distance,
            )
            return True
        except Exception as e:
            logger.warning("Failed to load Behavioral Clustering artifact from %s: %s", self.model_path, e)
            return False

    def save_model(self) -> None:
        """Persist current fitted clustering detector to joblib artifact file."""
        if not self.is_ready or self.detector is None:
            raise RuntimeError("Cannot save unfitted Behavioral Clustering model.")

        self.model_dir.mkdir(parents=True, exist_ok=True)
        state = self.detector.get_state()
        joblib.dump(state, self.model_path)
        logger.info("Saved Behavioral Clustering artifact to %s", self.model_path)

    def train(
        self,
        db: Session,
        n_clusters: Optional[int] = None,
        min_samples: Optional[int] = None,
        target_samples: Optional[int] = None,
        random_seed: Optional[int] = None,
        distance_percentile: Optional[float] = None,
        window_seconds: Optional[int] = None,
    ) -> BehavioralClusteringTrainResponse:
        """Train Behavioral Clustering detector using normal FeatureSnapshot records from database.
        
        Cold-Start Safety:
        If fewer than min_samples exist in the database, returns an INSUFFICIENT_DATA status
        without fabricating synthetic data or fake anomaly scores.
        """
        k = n_clusters or settings.CLUSTERING_N_CLUSTERS
        min_req = min_samples or settings.CLUSTERING_MIN_TRAINING_SAMPLES
        target_cnt = target_samples or settings.CLUSTERING_TARGET_TRAINING_SAMPLES
        seed = random_seed or settings.CLUSTERING_RANDOM_SEED
        percentile = distance_percentile or settings.CLUSTERING_DISTANCE_PERCENTILE

        # 1. Query persisted normal feature snapshots
        query = db.query(FeatureSnapshotDB)
        if window_seconds is not None:
            query = query.filter(FeatureSnapshotDB.window_seconds == window_seconds)

        snapshots = (
            query.order_by(FeatureSnapshotDB.timestamp.asc())
            .limit(target_cnt)
            .all()
        )

        sample_count = len(snapshots)
        if sample_count < max(min_req, k):
            logger.warning(
                "Insufficient training data for Behavioral Clustering: found %d snapshots, required >= %d",
                sample_count,
                max(min_req, k),
            )
            return BehavioralClusteringTrainResponse(
                status="INSUFFICIENT_DATA",
                message=(
                    f"Insufficient normal training data. Found {sample_count} snapshots, "
                    f"minimum required {max(min_req, k)}. Cold-start active: model remains in NOT_READY state."
                ),
                training_sample_count=sample_count,
                n_clusters=k,
                threshold_distance=0.0,
                clusters=[],
                feature_count=FEATURE_COUNT,
                trained_at=None,
                model_path=str(self.model_path),
            )

        # 2. Construct 21-D feature matrix
        matrix_rows: List[List[float]] = []
        for snap in snapshots:
            features_dict = snap.features or {}
            vector = extract_feature_vector(features_dict)
            matrix_rows.append(vector)

        X = np.array(matrix_rows, dtype=float)

        # 3. Fit detector
        detector = BehavioralClusteringDetector(
            n_clusters=k,
            random_seed=seed,
            distance_percentile=percentile,
        )
        detector.fit(X)

        # 4. Update service state and persist
        self.detector = detector
        self.save_model()

        return BehavioralClusteringTrainResponse(
            status="SUCCESS",
            message=f"Behavioral Clustering model trained successfully on {sample_count} snapshots across {k} clusters.",
            training_sample_count=sample_count,
            n_clusters=k,
            threshold_distance=detector.threshold_distance,
            clusters=detector.cluster_profiles,
            feature_count=FEATURE_COUNT,
            trained_at=detector.trained_at,
            model_path=str(self.model_path),
        )

    def evaluate_snapshot(
        self,
        snapshot: FeatureSnapshot,
        db: Optional[Session] = None,
        persist: bool = True,
    ) -> BehavioralClusteringAnomalyResult:
        """Evaluate a feature snapshot and optionally persist the anomaly result."""
        if not self.is_ready or self.detector is None:
            raise RuntimeError(
                "Behavioral Clustering model is not ready (NOT_READY / INSUFFICIENT_DATA). "
                "Train the detector on baseline traffic before evaluating snapshots."
            )

        result = self.detector.evaluate_snapshot(snapshot)

        if persist and db is not None:
            repo = AnomalyRepository(db)
            repo.create_clustering_result(result)

        return result

    def evaluate_active(
        self,
        db: Session,
        window_seconds: Optional[int] = None,
        limit: int = 20,
    ) -> List[BehavioralClusteringAnomalyResult]:
        """Evaluate the most recent active feature snapshots from the database."""
        if not self.is_ready or self.detector is None:
            raise RuntimeError(
                "Behavioral Clustering model is not ready. Train detector first."
            )

        query = db.query(FeatureSnapshotDB)
        if window_seconds is not None:
            query = query.filter(FeatureSnapshotDB.window_seconds == window_seconds)

        recent_snapshots = (
            query.order_by(FeatureSnapshotDB.timestamp.desc())
            .limit(limit)
            .all()
        )

        results: List[BehavioralClusteringAnomalyResult] = []
        for snap_db in recent_snapshots:
            snapshot = snap_db.to_schema()
            res = self.evaluate_snapshot(snapshot, db=db, persist=True)
            results.append(res)

        return results


# Global singleton instance
behavioral_clustering_service = BehavioralClusteringService()
