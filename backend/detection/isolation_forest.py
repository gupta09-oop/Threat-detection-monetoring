"""Core Isolation Forest Behavioral Anomaly Detector for Sh4d0w_St4lk3r.

Consumes 21-dimensional behavioral feature vectors from Phase 3,
normalizes with StandardScaler fitted strictly on normal baseline data,
and detects multidimensional structural anomalies via Isolation Forest.
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.features.vector import (
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    extract_feature_vector,
)
from backend.detection.schemas import (
    IsolationForestAnomalyResult,
    TopFeatureDeviation,
)
from backend.features.schemas import EntityType, FeatureSnapshot


class IsolationForestDetector:
    """Independent unsupervised Isolation Forest anomaly detector.
    
    Adheres strictly to the platform blueprint:
    - Independent detection evidence (not combined here with Phase 4 z-score)
    - StandardScaler fitted ONLY on normal baseline feature windows
    - Contamination = 0.05 by default
    - Deterministic random state for reproducible trees
    - 0-100 normalized behavioral anomaly score
    - Post-hoc top feature deviations for explainability
    """

    def __init__(
        self,
        contamination: float = 0.05,
        random_seed: int = 42,
        n_estimators: int = 100,
    ) -> None:
        self.contamination = contamination
        self.random_seed = random_seed
        self.n_estimators = n_estimators

        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.feature_names: List[str] = list(CANONICAL_FEATURE_NAMES)
        self.feature_schema_version: str = FEATURE_SCHEMA_VERSION

        self.training_sample_count: int = 0
        self.trained_at: Optional[datetime] = None
        self.is_fitted: bool = False

    def fit(self, feature_matrix: np.ndarray) -> "IsolationForestDetector":
        """Fit StandardScaler and IsolationForest on normal feature matrix.
        
        Args:
            feature_matrix: 2D numpy array of shape (n_samples, 21)
        """
        if feature_matrix.ndim != 2 or feature_matrix.shape[1] != FEATURE_COUNT:
            raise ValueError(
                f"Expected feature matrix with shape (N, {FEATURE_COUNT}), got {feature_matrix.shape}"
            )

        n_samples = feature_matrix.shape[0]
        if n_samples < 2:
            raise ValueError(f"Insufficient samples to fit Isolation Forest: {n_samples}")

        # 1. Fit StandardScaler on normal baseline feature vectors
        self.scaler = StandardScaler()
        scaled_matrix = self.scaler.fit_transform(feature_matrix)

        # 2. Fit IsolationForest on scaled normal features
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_seed,
            n_jobs=-1,
        )
        self.model.fit(scaled_matrix)

        self.training_sample_count = n_samples
        self.trained_at = datetime.now(timezone.utc)
        self.is_fitted = True

        return self

    @staticmethod
    def normalize_score(raw_decision_score: float) -> float:
        """Convert raw Isolation Forest decision score into a 0–100 behavioral anomaly score.
        
        Mathematical Transformation:
        Scikit-learn's decision_function s is centered around 0.0:
          - s >= 0.0 indicates normal behavior (inlier)
          - s < 0.0 indicates anomalous behavior (outlier/isolated point)
        
        We apply a smooth, strictly monotonic sigmoid mapping centered at the decision boundary:
          normalized_score = 100.0 / (1.0 + exp(10.0 * s))
        
        Properties:
          - At decision boundary (s = 0.0): normalized_score = 50.0
          - Inliers (s > 0.0): normalized_score < 50.0 (e.g. s = 0.1 -> 26.89, s = 0.2 -> 11.92)
          - Outliers (s < 0.0): normalized_score > 50.0 (e.g. s = -0.1 -> 73.11, s = -0.2 -> 88.08)
          - Strictly bounded in [0.0, 100.0]
          - Lower = more normal, higher = more anomalous
        """
        # Clamp exponent to avoid math overflow
        k = 10.0
        clamped_exp = max(-50.0, min(50.0, k * raw_decision_score))
        score = 100.0 / (1.0 + math.exp(clamped_exp))
        return round(float(score), 2)

    def compute_feature_deviations(
        self,
        raw_vector: np.ndarray,
        top_k: int = 5,
    ) -> List[TopFeatureDeviation]:
        """Compute post-hoc feature deviations against the normal training distribution.
        
        Compares the snapshot feature vector against the fitted StandardScaler
        baseline parameters (mean_ and scale_). Ranks features by magnitude of z-deviation.
        
        Note: These represent descriptive post-hoc deviations associated with the anomaly signal,
        not mathematical causal proof of tree isolation.
        """
        if not self.is_fitted or self.scaler is None:
            return []

        means = self.scaler.mean_
        scales = self.scaler.scale_

        deviations: List[TopFeatureDeviation] = []

        for i, name in enumerate(self.feature_names):
            val = float(raw_vector[i])
            m = float(means[i])
            s = float(scales[i]) if scales[i] > 1e-6 else 1e-6

            z_score = (val - m) / s
            abs_z = abs(z_score)
            direction = "HIGH" if z_score >= 0 else "LOW"

            deviations.append(
                TopFeatureDeviation(
                    feature_name=name,
                    feature_value=round(val, 4),
                    baseline_mean=round(m, 4),
                    baseline_stddev=round(s, 4),
                    deviation_score=round(abs_z, 2),
                    direction=direction,
                )
            )

        # Rank descending by deviation magnitude
        deviations.sort(key=lambda d: d.deviation_score, reverse=True)
        return deviations[:top_k]

    def evaluate_vector(
        self,
        vector: List[float],
        entity_type: EntityType,
        entity_id: str,
        snapshot_id: str,
        window_seconds: int,
        timestamp: Optional[datetime] = None,
    ) -> IsolationForestAnomalyResult:
        """Evaluate a 21-dimensional feature vector and produce an anomaly result."""
        if not self.is_fitted or self.model is None or self.scaler is None:
            raise RuntimeError("Isolation Forest detector is not fitted. Cannot evaluate vector.")

        ts = timestamp or datetime.now(timezone.utc)
        raw_arr = np.array(vector, dtype=float).reshape(1, -1)

        # Preprocessing: transform using training-fitted scaler only
        scaled_arr = self.scaler.transform(raw_arr)

        # Raw detector outputs
        raw_pred = int(self.model.predict(scaled_arr)[0])  # 1 or -1
        raw_score = float(self.model.decision_function(scaled_arr)[0])

        is_anomalous = (raw_pred == -1)
        status = "ANOMALOUS" if is_anomalous else "NORMAL"
        norm_score = self.normalize_score(raw_score)

        # Post-hoc explainability
        deviations = self.compute_feature_deviations(raw_arr[0], top_k=5)

        if is_anomalous:
            top_dev_str = ", ".join(
                f"{d.feature_name} ({d.direction} {d.deviation_score}x σ)"
                for d in deviations[:3]
            )
            explanation = (
                f"Isolation Forest behavioral anomaly detected (behavioral score: {norm_score}/100, "
                f"decision: ANOMALOUS). Top feature deviations associated with the anomaly signal: "
                f"{top_dev_str}. Note: Post-hoc feature deviation analysis relative to normal baseline."
            )
        else:
            explanation = (
                f"Isolation Forest evaluation indicates normal baseline behavior "
                f"(behavioral score: {norm_score}/100, decision: NORMAL)."
            )

        details = {
            "raw_decision_score": round(raw_score, 4),
            "raw_prediction": raw_pred,
            "normalized_anomaly_score": norm_score,
            "feature_schema_version": self.feature_schema_version,
            "training_sample_count": self.training_sample_count,
            "contamination": self.contamination,
            "random_seed": self.random_seed,
            "feature_vector": {
                name: round(val, 4)
                for name, val in zip(self.feature_names, vector)
            },
        }

        return IsolationForestAnomalyResult(
            timestamp=ts,
            detector_type="ISOLATION_FOREST",
            entity_type=entity_type,
            entity_id=entity_id,
            snapshot_id=snapshot_id,
            window_seconds=window_seconds,
            feature_name="BEHAVIORAL_VECTOR_21D",
            raw_decision_score=round(raw_score, 4),
            raw_prediction=raw_pred,
            normalized_anomaly_score=norm_score,
            is_anomalous=is_anomalous,
            anomaly_score=norm_score,
            explanation=explanation,
            status=status,
            top_feature_deviations=deviations,
            details=details,
        )

    def evaluate_snapshot(self, snapshot: FeatureSnapshot) -> IsolationForestAnomalyResult:
        """Extract canonical 21-D vector from snapshot and evaluate."""
        vector = extract_feature_vector(snapshot.features)
        return self.evaluate_vector(
            vector=vector,
            entity_type=snapshot.entity_type,
            entity_id=snapshot.entity_id,
            snapshot_id=snapshot.snapshot_id,
            window_seconds=snapshot.window_seconds,
            timestamp=snapshot.timestamp,
        )

    def get_state(self) -> Dict[str, Any]:
        """Export internal state for joblib persistence."""
        if not self.is_fitted:
            raise RuntimeError("Cannot export state from unfitted detector.")

        return {
            "model": self.model,
            "scaler": self.scaler,
            "contamination": self.contamination,
            "random_seed": self.random_seed,
            "n_estimators": self.n_estimators,
            "feature_names": self.feature_names,
            "feature_schema_version": self.feature_schema_version,
            "training_sample_count": self.training_sample_count,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
        }

    def set_state(self, state: Dict[str, Any]) -> "IsolationForestDetector":
        """Restore internal state from loaded joblib dictionary."""
        self.model = state["model"]
        self.scaler = state["scaler"]
        self.contamination = state.get("contamination", self.contamination)
        self.random_seed = state.get("random_seed", self.random_seed)
        self.n_estimators = state.get("n_estimators", self.n_estimators)
        self.feature_names = state.get("feature_names", list(CANONICAL_FEATURE_NAMES))
        self.feature_schema_version = state.get("feature_schema_version", FEATURE_SCHEMA_VERSION)
        self.training_sample_count = state.get("training_sample_count", 0)

        trained_at_raw = state.get("trained_at")
        if trained_at_raw:
            if isinstance(trained_at_raw, str):
                self.trained_at = datetime.fromisoformat(trained_at_raw)
            elif isinstance(trained_at_raw, datetime):
                self.trained_at = trained_at_raw
        else:
            self.trained_at = None

        self.is_fitted = True
        return self
