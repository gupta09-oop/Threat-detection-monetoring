"""Isolation Forest model management and scoring service for Sh4d0w_St4lk3r.

Responsible for:
- Gathering historical normal feature snapshots from database
- Constructing the 21-D training feature matrix
- Fitting StandardScaler and IsolationForest
- Persisting and loading model artifacts with joblib
- Managing model status, cold start, and post-hoc evaluation
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
from sqlalchemy.orm import Session

from backend.config import settings
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.schemas import (
    IsolationForestAnomalyResult,
    IsolationForestModelStatus,
    IsolationForestTrainResponse,
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


class IsolationForestService:
    """Service layer managing the lifecycle of the Isolation Forest detector."""

    def __init__(self, model_dir: Optional[str] = None, model_file: Optional[str] = None) -> None:
        self.model_dir = Path(model_dir or settings.ISOLATION_FOREST_MODEL_DIR)
        self.model_file = model_file or settings.ISOLATION_FOREST_MODEL_FILE
        self.model_path = self.model_dir / self.model_file

        self.detector: Optional[IsolationForestDetector] = None

    @property
    def is_ready(self) -> bool:
        """Check if the model is fitted and available for inference."""
        return self.detector is not None and self.detector.is_fitted

    def get_status(self) -> IsolationForestModelStatus:
        """Return structured model readiness and metadata status."""
        if self.is_ready and self.detector is not None:
            return IsolationForestModelStatus(
                is_ready=True,
                status="READY",
                message="Isolation Forest model is fitted and ready for behavioral inference.",
                model_path=str(self.model_path),
                trained_at=self.detector.trained_at,
                training_sample_count=self.detector.training_sample_count,
                contamination=self.detector.contamination,
                random_seed=self.detector.random_seed,
                n_estimators=self.detector.n_estimators,
                feature_schema_version=self.detector.feature_schema_version,
                feature_count=FEATURE_COUNT,
            )

        return IsolationForestModelStatus(
            is_ready=False,
            status="NOT_READY",
            message=(
                f"Isolation Forest model is not trained or loaded. "
                f"Requires at least {settings.ISOLATION_FOREST_MIN_TRAINING_SAMPLES} normal training snapshots."
            ),
            model_path=str(self.model_path),
            trained_at=None,
            training_sample_count=0,
            contamination=settings.ISOLATION_FOREST_CONTAMINATION,
            random_seed=settings.ISOLATION_FOREST_RANDOM_SEED,
            n_estimators=settings.ISOLATION_FOREST_N_ESTIMATORS,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_count=FEATURE_COUNT,
        )

    def try_load_model(self) -> bool:
        """Attempt to load existing model artifact from disk on application startup.
        
        Handles missing or corrupted artifacts gracefully without raising exceptions.
        """
        if not self.model_path.exists():
            logger.info(
                "Isolation Forest model artifact not found at %s. Detector starting in NOT_READY state.",
                self.model_path,
            )
            return False

        try:
            state = joblib.load(self.model_path)
            detector = IsolationForestDetector()
            detector.set_state(state)
            self.detector = detector
            logger.info(
                "Isolation Forest model artifact loaded successfully from %s (trained on %d samples).",
                self.model_path,
                detector.training_sample_count,
            )
            return True
        except Exception as e:
            logger.warning("Failed to load Isolation Forest artifact from %s: %s", self.model_path, e)
            return False

    def save_model(self) -> None:
        """Persist current fitted model state to joblib artifact file."""
        if not self.is_ready or self.detector is None:
            raise RuntimeError("Cannot save unfitted Isolation Forest model.")

        self.model_dir.mkdir(parents=True, exist_ok=True)
        state = self.detector.get_state()
        joblib.dump(state, self.model_path)
        logger.info("Saved Isolation Forest model artifact to %s", self.model_path)

    def train(
        self,
        db: Session,
        min_samples: Optional[int] = None,
        target_samples: Optional[int] = None,
        contamination: Optional[float] = None,
        random_seed: Optional[int] = None,
        n_estimators: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> IsolationForestTrainResponse:
        """Train Isolation Forest detector using normal FeatureSnapshot records from database.
        
        Cold-Start Safety:
        If fewer than min_samples exist in the database, returns an INSUFFICIENT_DATA status
        without fabricating synthetic data or fake anomaly scores.
        """
        min_req = min_samples or settings.ISOLATION_FOREST_MIN_TRAINING_SAMPLES
        target_cnt = target_samples or settings.ISOLATION_FOREST_TARGET_TRAINING_SAMPLES
        contam = contamination or settings.ISOLATION_FOREST_CONTAMINATION
        seed = random_seed or settings.ISOLATION_FOREST_RANDOM_SEED
        n_trees = n_estimators or settings.ISOLATION_FOREST_N_ESTIMATORS

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
        if sample_count < min_req:
            logger.warning(
                "Insufficient training data for Isolation Forest: found %d snapshots, required %d",
                sample_count,
                min_req,
            )
            return IsolationForestTrainResponse(
                status="INSUFFICIENT_DATA",
                message=(
                    f"Insufficient normal training data. Found {sample_count} snapshots, "
                    f"minimum required {min_req}. Cold-start active: model remains in NOT_READY state."
                ),
                training_sample_count=sample_count,
                contamination=contam,
                random_seed=seed,
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
        detector = IsolationForestDetector(
            contamination=contam,
            random_seed=seed,
            n_estimators=n_trees,
        )
        detector.fit(X)

        # 4. Update service state and persist
        self.detector = detector
        self.save_model()

        return IsolationForestTrainResponse(
            status="SUCCESS",
            message=f"Isolation Forest model trained successfully on {sample_count} normal snapshots.",
            training_sample_count=sample_count,
            contamination=contam,
            random_seed=seed,
            feature_count=FEATURE_COUNT,
            trained_at=detector.trained_at,
            model_path=str(self.model_path),
        )

    def evaluate_snapshot(
        self,
        snapshot: FeatureSnapshot,
        db: Optional[Session] = None,
        persist: bool = True,
    ) -> IsolationForestAnomalyResult:
        """Evaluate a feature snapshot and optionally persist the anomaly result."""
        if not self.is_ready or self.detector is None:
            raise RuntimeError(
                "Isolation Forest model is not ready (NOT_READY / INSUFFICIENT_DATA). "
                "Train the detector on baseline traffic before evaluating snapshots."
            )

        result = self.detector.evaluate_snapshot(snapshot)

        if persist and db is not None:
            repo = AnomalyRepository(db)
            repo.create_isolation_forest_result(result)

        return result

    def evaluate_active(
        self,
        db: Session,
        window_seconds: Optional[int] = None,
        limit: int = 20,
    ) -> List[IsolationForestAnomalyResult]:
        """Evaluate the most recent active feature snapshots from the database."""
        if not self.is_ready or self.detector is None:
            raise RuntimeError(
                "Isolation Forest model is not ready. Train detector first."
            )

        query = db.query(FeatureSnapshotDB)
        if window_seconds is not None:
            query = query.filter(FeatureSnapshotDB.window_seconds == window_seconds)

        recent_snapshots = (
            query.order_by(FeatureSnapshotDB.timestamp.desc())
            .limit(limit)
            .all()
        )

        results: List[IsolationForestAnomalyResult] = []
        for snap_db in recent_snapshots:
            snapshot = snap_db.to_schema()
            res = self.evaluate_snapshot(snapshot, db=db, persist=True)
            results.append(res)

        return results


# Global singleton instance
isolation_forest_service = IsolationForestService()
