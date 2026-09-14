"""Unit tests for StatisticalDetector, Z-score mathematics, cold-start rules, and thresholds."""

from datetime import datetime, timezone
import pytest

from backend.detection.schemas import StatisticalBaseline
from backend.detection.statistical_detector import StatisticalDetector
from backend.features.schemas import EntityType, FeatureSnapshot


def test_z_score_positive_anomaly():
    """Verify specification example: mean=10, std=2, current=18 -> z=4.0 > 3 -> anomalous."""
    detector = StatisticalDetector(z_threshold=3.0)
    baseline = StatisticalBaseline(
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="login_frequency",
        mean=10.0,
        stddev=2.0,
        sample_count=25,
    )

    result = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="login_frequency",
        current_value=18.0,
        baseline=baseline,
    )

    assert result.signed_z_score == 4.0
    assert result.absolute_z_score == 4.0
    assert result.is_anomalous is True
    assert result.status == "ANOMALOUS"
    assert result.anomaly_score > 0.0
    assert "positive deviation" in result.explanation
    assert "Statistical deviation detected" in result.explanation


def test_z_score_negative_anomaly():
    """Verify negative deviation: mean=10, std=2, current=2 -> z=-4.0 -> anomalous."""
    detector = StatisticalDetector(z_threshold=3.0)
    baseline = StatisticalBaseline(
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="success_rate",
        mean=10.0,
        stddev=2.0,
        sample_count=25,
    )

    result = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="success_rate",
        current_value=2.0,
        baseline=baseline,
    )

    assert result.signed_z_score == -4.0
    assert result.absolute_z_score == 4.0
    assert result.is_anomalous is True
    assert result.status == "ANOMALOUS"
    assert "negative deviation" in result.explanation


def test_z_score_normal_behavior():
    """Verify specification example: mean=10, std=2, current=12 -> z=1.0 <= 3 -> normal."""
    detector = StatisticalDetector(z_threshold=3.0)
    baseline = StatisticalBaseline(
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="login_frequency",
        mean=10.0,
        stddev=2.0,
        sample_count=25,
    )

    result = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="login_frequency",
        current_value=12.0,
        baseline=baseline,
    )

    assert result.signed_z_score == 1.0
    assert result.absolute_z_score == 1.0
    assert result.is_anomalous is False
    assert result.status == "NORMAL"
    assert result.anomaly_score == 0.0
    assert "Normal behavior" in result.explanation


def test_z_score_zero_deviation():
    """Verify current value equal to baseline mean yields z=0.0."""
    detector = StatisticalDetector()
    baseline = StatisticalBaseline(
        entity_type=EntityType.GLOBAL,
        entity_id="GLOBAL",
        window_seconds=60,
        feature_name="port_diversity",
        mean=0.5,
        stddev=0.1,
        sample_count=50,
    )

    result = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.GLOBAL,
        entity_id="GLOBAL",
        window_seconds=60,
        feature_name="port_diversity",
        current_value=0.5,
        baseline=baseline,
    )

    assert result.signed_z_score == 0.0
    assert result.absolute_z_score == 0.0
    assert result.is_anomalous is False


def test_zero_standard_deviation_safety():
    """Verify invariant baseline (stddev=0) does not cause division by zero or NaN."""
    detector = StatisticalDetector()
    baseline = StatisticalBaseline(
        entity_type=EntityType.USER,
        entity_id="bob",
        window_seconds=60,
        feature_name="failed_login_rate",
        mean=0.0,
        stddev=0.0,
        sample_count=10,
    )

    # 1. Current value matches invariant mean -> z=0.0
    res_match = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.USER,
        entity_id="bob",
        window_seconds=60,
        feature_name="failed_login_rate",
        current_value=0.0,
        baseline=baseline,
    )
    assert res_match.signed_z_score == 0.0
    assert res_match.is_anomalous is False

    # 2. Current value shifts from invariant mean -> safe capped z, anomalous
    res_shift = detector.score_feature(
        snapshot_id="snap_2",
        entity_type=EntityType.USER,
        entity_id="bob",
        window_seconds=60,
        feature_name="failed_login_rate",
        current_value=0.8,
        baseline=baseline,
    )
    assert res_shift.signed_z_score == 10.0
    assert res_shift.is_anomalous is True


def test_cold_start_under_five_samples_abstains():
    """Verify fewer than 5 historical samples causes detector to ABSTAIN."""
    detector = StatisticalDetector(min_samples_to_score=5)
    baseline = StatisticalBaseline(
        entity_type=EntityType.USER,
        entity_id="new_user",
        window_seconds=60,
        feature_name="login_frequency",
        mean=10.0,
        stddev=1.0,
        sample_count=4,  # < 5 samples
    )

    result = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.USER,
        entity_id="new_user",
        window_seconds=60,
        feature_name="login_frequency",
        current_value=100.0,  # Extreme value, but detector must abstain
        baseline=baseline,
    )

    assert result.status == "ABSTAIN"
    assert result.is_anomalous is False
    assert result.signed_z_score is None
    assert result.anomaly_score == 0.0
    assert "abstains" in result.explanation.lower()


def test_cold_start_entity_fallback_to_global():
    """Verify entity with < 20 samples falls back to GLOBAL baseline when available."""
    detector = StatisticalDetector(min_samples_to_score=5, min_entity_samples=20)
    now = datetime.now(timezone.utc)

    # Entity baseline has 10 samples (< 20 threshold)
    entity_baselines = {
        "login_frequency": StatisticalBaseline(
            entity_type=EntityType.USER,
            entity_id="junior_analyst",
            window_seconds=60,
            feature_name="login_frequency",
            mean=2.0,
            stddev=0.5,
            sample_count=10,
        )
    }

    # GLOBAL baseline has 100 samples
    global_baselines = {
        "login_frequency": StatisticalBaseline(
            entity_type=EntityType.GLOBAL,
            entity_id="GLOBAL",
            window_seconds=60,
            feature_name="login_frequency",
            mean=5.0,
            stddev=1.0,
            sample_count=100,
        )
    }

    snapshot = FeatureSnapshot(
        snapshot_id="test_snap",
        window_seconds=60,
        window_start=now,
        window_end=now,
        entity_type=EntityType.USER,
        entity_id="junior_analyst",
        features={"login_frequency": 5.0},
    )

    results = detector.score_snapshot(
        snapshot=snapshot,
        baselines=entity_baselines,
        global_baselines=global_baselines,
    )

    assert len(results) == 1
    freq_res = results[0]
    # Scored against GLOBAL mean=5.0 instead of entity mean=2.0
    assert freq_res.baseline_mean == 5.0
    assert freq_res.signed_z_score == 0.0
    assert freq_res.details["is_fallback"] is True
    assert "GLOBAL population baseline" in freq_res.explanation


def test_contribution_cap():
    """Verify anomaly score respects the configurable max contribution cap."""
    detector = StatisticalDetector(z_threshold=3.0, max_contribution=1.0)
    baseline = StatisticalBaseline(
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="failed_login_rate",
        mean=0.0,
        stddev=0.01,
        sample_count=30,
    )

    # Massive shift: current = 1.0 -> z = 100
    res = detector.score_feature(
        snapshot_id="snap_1",
        entity_type=EntityType.USER,
        entity_id="alice",
        window_seconds=60,
        feature_name="failed_login_rate",
        current_value=1.0,
        baseline=baseline,
    )

    assert res.is_anomalous is True
    assert res.anomaly_score <= 1.0  # Capped at max_contribution
