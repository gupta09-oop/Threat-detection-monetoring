"""Baseline generation service calculating empirical mean and stddev from FeatureSnapshots."""

from collections import defaultdict
from datetime import datetime, timezone
import logging
import math
from typing import Dict, List, Optional, Tuple
import uuid
from sqlalchemy.orm import Session

from backend.detection.schemas import StatisticalBaseline
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.baseline_repository import BaselineRepository

logger = logging.getLogger(__name__)


class BaselineService:
    """Calculates statistical baselines from historical feature snapshots."""

    def build_baselines_from_snapshots(
        self,
        snapshots: List[FeatureSnapshot],
    ) -> List[StatisticalBaseline]:
        """Compute mean and standard deviation per (entity_type, entity_id, window_seconds, feature)."""
        if not snapshots:
            return []

        # Group snapshots by (entity_type, entity_id, window_seconds)
        grouped_snapshots: Dict[Tuple[str, str, int], List[FeatureSnapshot]] = defaultdict(list)
        for s in snapshots:
            et = s.entity_type
            if hasattr(et, "value"):
                et = et.value
            key = (str(et), s.entity_id, s.window_seconds)
            grouped_snapshots[key].append(s)

        baselines: List[StatisticalBaseline] = []

        for (entity_type_str, entity_id, window_sec), group in grouped_snapshots.items():
            # Collect all feature values
            feature_values: Dict[str, List[float]] = defaultdict(list)
            for snap in group:
                for feat_name, feat_val in snap.features.items():
                    if isinstance(feat_val, (int, float)) and not math.isnan(feat_val) and not math.isinf(feat_val):
                        feature_values[feat_name].append(float(feat_val))

            for feat_name, values in feature_values.items():
                n = len(values)
                if n == 0:
                    continue

                mean = sum(values) / n
                if n > 1:
                    # Unbiased sample variance
                    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
                    stddev = math.sqrt(variance)
                else:
                    stddev = 0.0

                baseline = StatisticalBaseline(
                    baseline_id=str(uuid.uuid4()),
                    entity_type=EntityType(entity_type_str),
                    entity_id=entity_id,
                    window_seconds=window_sec,
                    feature_name=feat_name,
                    mean=round(mean, 6),
                    stddev=round(stddev, 6),
                    sample_count=n,
                    updated_at=datetime.now(timezone.utc),
                )
                baselines.append(baseline)

        return baselines

    def build_and_persist_from_db(
        self,
        db: Session,
        max_samples: int = 1000,
        window_seconds: Optional[int] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
    ) -> List[StatisticalBaseline]:
        """Query historical FeatureSnapshot records in SQLite, compute baselines, and persist them."""
        query = db.query(FeatureSnapshotDB)

        if window_seconds is not None:
            query = query.filter(FeatureSnapshotDB.window_seconds == window_seconds)
        if entity_type:
            query = query.filter(FeatureSnapshotDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(FeatureSnapshotDB.entity_id == entity_id)

        db_snapshots = query.order_by(FeatureSnapshotDB.timestamp.desc()).limit(max_samples).all()
        snapshots = [s.to_schema() for s in db_snapshots]

        baselines = self.build_baselines_from_snapshots(snapshots)
        if baselines:
            repo = BaselineRepository(db)
            repo.batch_upsert_baselines(baselines)
            logger.info("Computed and persisted %d statistical baselines.", len(baselines))

        return baselines


# Global service instance
baseline_service = BaselineService()
