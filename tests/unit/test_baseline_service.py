"""Unit tests for statistical baseline calculation from FeatureSnapshots."""

from datetime import datetime, timezone
import math
import pytest
from backend.detection.baseline_service import BaselineService
from backend.features.schemas import EntityType, FeatureSnapshot


def test_baseline_calculation_mean_and_stddev():
    """Verify mean and sample standard deviation calculations across feature snapshots."""
    now = datetime.now(timezone.utc)
    # 5 snapshots with known values for 'login_frequency': [2.0, 4.0, 4.0, 4.0, 6.0]
    # sum = 20, mean = 4.0
    # squared diffs: (2-4)^2=4, (4-4)^2=0*3=0, (6-4)^2=4 -> sum = 8
    # sample variance = 8 / (5 - 1) = 2.0
    # sample stddev = sqrt(2.0) = 1.414214
    snapshots = [
        FeatureSnapshot(
            window_seconds=60,
            window_start=now,
            window_end=now,
            entity_type=EntityType.USER,
            entity_id="test_user",
            features={"login_frequency": val, "failed_login_rate": 0.0},
        )
        for val in [2.0, 4.0, 4.0, 4.0, 6.0]
    ]

    service = BaselineService()
    baselines = service.build_baselines_from_snapshots(snapshots)

    freq_base = next(b for b in baselines if b.feature_name == "login_frequency")
    assert freq_base.sample_count == 5
    assert freq_base.mean == 4.0
    assert math.isclose(freq_base.stddev, 1.414214, rel_tol=1e-4)


def test_single_snapshot_baseline_stddev_zero():
    """Verify 1 snapshot produces mean equal to value and stddev equal to 0.0."""
    now = datetime.now(timezone.utc)
    snapshot = FeatureSnapshot(
        window_seconds=60,
        window_start=now,
        window_end=now,
        entity_type=EntityType.GLOBAL,
        entity_id="GLOBAL",
        features={"success_rate": 0.95},
    )

    service = BaselineService()
    baselines = service.build_baselines_from_snapshots([snapshot])

    assert len(baselines) == 1
    assert baselines[0].sample_count == 1
    assert baselines[0].mean == 0.95
    assert baselines[0].stddev == 0.0


def test_baseline_grouping_by_entity_and_window():
    """Verify snapshots are grouped independently by entity and window size."""
    now = datetime.now(timezone.utc)
    snapshots = [
        FeatureSnapshot(window_seconds=60, window_start=now, window_end=now, entity_type=EntityType.USER, entity_id="alice", features={"rate": 1.0}),
        FeatureSnapshot(window_seconds=60, window_start=now, window_end=now, entity_type=EntityType.USER, entity_id="alice", features={"rate": 3.0}),
        FeatureSnapshot(window_seconds=300, window_start=now, window_end=now, entity_type=EntityType.USER, entity_id="alice", features={"rate": 10.0}),
        FeatureSnapshot(window_seconds=60, window_start=now, window_end=now, entity_type=EntityType.IP, entity_id="10.0.0.1", features={"rate": 5.0}),
    ]

    service = BaselineService()
    baselines = service.build_baselines_from_snapshots(snapshots)

    # 3 distinct groups: (USER, alice, 60s), (USER, alice, 300s), (IP, 10.0.0.1, 60s)
    assert len(baselines) == 3
    alice_60 = next(b for b in baselines if b.entity_id == "alice" and b.window_seconds == 60)
    assert alice_60.sample_count == 2
    assert alice_60.mean == 2.0
