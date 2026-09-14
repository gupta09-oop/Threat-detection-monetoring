"""Statistical anomaly detector and Z-score deviation evaluation engine."""

from datetime import datetime, timezone
import logging
import math
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy.orm import Session

from backend.config import settings
from backend.detection.schemas import StatisticalAnomalyResult, StatisticalBaseline
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.models.baseline import StatisticalBaselineDB
from backend.repositories.anomaly_repository import AnomalyRepository
from backend.repositories.baseline_repository import BaselineRepository

logger = logging.getLogger(__name__)


class StatisticalDetector:
    """Evaluates behavioral feature snapshots against historical baselines using z-score deviation."""

    def __init__(
        self,
        min_samples_to_score: int = settings.STATISTICAL_MIN_SAMPLES_TO_SCORE,
        min_entity_samples: int = settings.STATISTICAL_MIN_ENTITY_SAMPLES,
        z_threshold: float = settings.STATISTICAL_Z_THRESHOLD,
        max_contribution: float = settings.STATISTICAL_MAX_CONTRIBUTION,
    ):
        self.min_samples_to_score = min_samples_to_score
        self.min_entity_samples = min_entity_samples
        self.z_threshold = z_threshold
        self.max_contribution = max_contribution

    def score_feature(
        self,
        snapshot_id: str,
        entity_type: EntityType,
        entity_id: str,
        window_seconds: int,
        feature_name: str,
        current_value: float,
        baseline: Optional[StatisticalBaseline],
        is_fallback: bool = False,
    ) -> StatisticalAnomalyResult:
        """Score a single feature against a baseline, respecting cold-start and safety rules."""
        # 1. Cold-start rule: fewer than min_samples_to_score -> ABSTAIN
        sample_count = baseline.sample_count if baseline else 0
        if not baseline or sample_count < self.min_samples_to_score:
            return StatisticalAnomalyResult(
                result_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                detector_type="STATISTICAL_ZSCORE",
                entity_type=entity_type,
                entity_id=entity_id,
                snapshot_id=snapshot_id,
                window_seconds=window_seconds,
                feature_name=feature_name,
                current_value=current_value,
                baseline_mean=baseline.mean if baseline else None,
                baseline_stddev=baseline.stddev if baseline else None,
                sample_count=sample_count,
                signed_z_score=None,
                absolute_z_score=None,
                is_anomalous=False,
                anomaly_score=0.0,
                status="ABSTAIN",
                explanation=(
                    f"Insufficient historical samples ({sample_count} < {self.min_samples_to_score}). "
                    f"Statistical detector abstains from scoring '{feature_name}'."
                ),
                details={"cold_start": True, "min_samples_required": self.min_samples_to_score},
            )

        mean = float(baseline.mean)
        stddev = float(baseline.stddev)
        diff = float(current_value) - mean

        # 2. Division-by-zero & zero standard deviation safety
        if stddev <= 0.0:
            if abs(diff) < 1e-9:
                signed_z = 0.0
            else:
                # Invariant historical baseline observed with a distinct shift
                signed_z = 10.0 if diff > 0 else -10.0
        else:
            signed_z = diff / stddev

        # Sanitize any unexpected non-finite floats
        if math.isnan(signed_z) or math.isinf(signed_z):
            signed_z = 0.0

        signed_z = round(signed_z, 4)
        abs_z = round(abs(signed_z), 4)

        # 3. Anomaly evaluation against threshold (|z| > 3.0)
        is_anomalous = abs_z > self.z_threshold
        status_label = "ANOMALOUS" if is_anomalous else "NORMAL"

        # 4. Contribution cap calculation
        if is_anomalous:
            # Scaled contribution up to max_contribution
            excess = abs_z - self.z_threshold
            scaled = (excess / self.z_threshold) * self.max_contribution
            anomaly_score = round(min(self.max_contribution, max(0.1, scaled)), 4)
        else:
            anomaly_score = 0.0

        # 5. Transparent security explanation
        fallback_note = " (evaluated via GLOBAL population baseline)" if is_fallback else ""
        if is_anomalous:
            direction = "positive" if signed_z > 0 else "negative"
            explanation = (
                f"Statistical deviation detected{fallback_note}: '{feature_name}' = {current_value:.4f} "
                f"exhibits elevated evidence strength (z-score: {signed_z:+.2f}, |z| = {abs_z:.2f} > {self.z_threshold:.1f}) "
                f"relative to baseline mean {mean:.4f} (stddev {stddev:.4f}, n={sample_count}, {direction} deviation)."
            )
        else:
            explanation = (
                f"Normal behavior{fallback_note}: '{feature_name}' = {current_value:.4f} "
                f"is within expected statistical bounds (z-score: {signed_z:+.2f}, |z| = {abs_z:.2f} <= {self.z_threshold:.1f}, "
                f"baseline mean: {mean:.4f}, stddev: {stddev:.4f}, n={sample_count})."
            )

        return StatisticalAnomalyResult(
            result_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            detector_type="STATISTICAL_ZSCORE",
            entity_type=entity_type,
            entity_id=entity_id,
            snapshot_id=snapshot_id,
            window_seconds=window_seconds,
            feature_name=feature_name,
            current_value=current_value,
            baseline_mean=mean,
            baseline_stddev=stddev,
            sample_count=sample_count,
            signed_z_score=signed_z,
            absolute_z_score=abs_z,
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            status=status_label,
            explanation=explanation,
            details={
                "z_threshold": self.z_threshold,
                "max_contribution": self.max_contribution,
                "is_fallback": is_fallback,
            },
        )

    def score_snapshot(
        self,
        snapshot: FeatureSnapshot,
        baselines: Dict[str, StatisticalBaseline],
        global_baselines: Optional[Dict[str, StatisticalBaseline]] = None,
    ) -> List[StatisticalAnomalyResult]:
        """Score all features in a FeatureSnapshot against available baselines in memory."""
        results: List[StatisticalAnomalyResult] = []
        global_baselines = global_baselines or {}

        for feat_name, feat_val in snapshot.features.items():
            if not isinstance(feat_val, (int, float)) or math.isnan(feat_val) or math.isinf(feat_val):
                continue

            baseline = baselines.get(feat_name)
            is_fallback = False

            # Cold-start fallback: if entity baseline has < 20 samples and GLOBAL baseline has >= 5 samples
            entity_samples = baseline.sample_count if baseline else 0
            if snapshot.entity_type != EntityType.GLOBAL and entity_samples < self.min_entity_samples:
                global_base = global_baselines.get(feat_name)
                if global_base and global_base.sample_count >= self.min_samples_to_score:
                    baseline = global_base
                    is_fallback = True

            res = self.score_feature(
                snapshot_id=snapshot.snapshot_id,
                entity_type=snapshot.entity_type,
                entity_id=snapshot.entity_id,
                window_seconds=snapshot.window_seconds,
                feature_name=feat_name,
                current_value=float(feat_val),
                baseline=baseline,
                is_fallback=is_fallback,
            )
            results.append(res)

        return results

    def score_snapshot_with_db(
        self,
        db: Session,
        snapshot: FeatureSnapshot,
        persist: bool = True,
    ) -> List[StatisticalAnomalyResult]:
        """Score a snapshot by querying baselines from SQLite, and optionally persist the results."""
        baseline_repo = BaselineRepository(db)

        # 1. Fetch entity baselines
        et = snapshot.entity_type
        if hasattr(et, "value"):
            et = et.value
        db_entity_baselines = baseline_repo.get_baselines_for_entity(
            entity_type=str(et),
            entity_id=snapshot.entity_id,
            window_seconds=snapshot.window_seconds,
        )
        entity_baselines = {b.feature_name: b.to_schema() for b in db_entity_baselines}

        # 2. Fetch global baselines for fallback if needed
        global_baselines: Dict[str, StatisticalBaseline] = {}
        if snapshot.entity_type != EntityType.GLOBAL:
            db_global = baseline_repo.get_baselines_for_entity(
                entity_type="GLOBAL",
                entity_id="GLOBAL",
                window_seconds=snapshot.window_seconds,
            )
            global_baselines = {b.feature_name: b.to_schema() for b in db_global}

        # 3. Score snapshot
        results = self.score_snapshot(
            snapshot=snapshot,
            baselines=entity_baselines,
            global_baselines=global_baselines,
        )

        # 4. Persist results
        if persist and results:
            anomaly_repo = AnomalyRepository(db)
            anomaly_repo.create_batch_results(results)
            logger.debug(
                "Persisted %d statistical anomaly results for snapshot %s.",
                len(results),
                snapshot.snapshot_id,
            )

        return results


# Global detector instance
statistical_detector = StatisticalDetector()
