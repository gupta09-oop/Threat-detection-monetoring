"""Unit tests for the core Isolation Forest anomaly detector, scaler, scoring, and explainability."""

import numpy as np
import pytest

from backend.detection.isolation_forest import IsolationForestDetector
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import (
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    extract_feature_vector,
)


@pytest.fixture
def normal_training_data() -> np.ndarray:
    """Generate 200 normal behavioral feature vectors with tight baseline variation."""
    rng = np.random.RandomState(42)
    # Features roughly in typical baseline ranges
    means = np.array([
        0.05, 0.95, 1.0, 1.0, 0.2, 0.2, 0.1, 0.1, 0.05, 0.5,  # Auth
        2.0, 0.1, 0.1, 0.2, 0.01, 0.3,                          # Net
        1.0, 1.0, 0.05, 0.1, 0.2                                # Cross
    ])
    stds = np.maximum(means * 0.1, 0.01)
    matrix = rng.normal(loc=means, scale=stds, size=(200, FEATURE_COUNT))
    return np.maximum(0.0, matrix)


def test_detector_fit_and_scaler(normal_training_data):
    """Detector fits StandardScaler and IsolationForest on 21-D matrix."""
    detector = IsolationForestDetector(contamination=0.05, random_seed=42, n_estimators=50)
    assert not detector.is_fitted

    detector.fit(normal_training_data)
    assert detector.is_fitted
    assert detector.training_sample_count == 200
    assert detector.scaler is not None
    assert len(detector.scaler.mean_) == FEATURE_COUNT
    assert len(detector.scaler.scale_) == FEATURE_COUNT
    assert detector.model is not None


def test_unfitted_detector_raises():
    """Attempting to evaluate before fitting must raise RuntimeError."""
    detector = IsolationForestDetector()
    with pytest.raises(RuntimeError, match="not fitted"):
        detector.evaluate_vector(
            vector=[0.0] * 21,
            entity_type=EntityType.USER,
            entity_id="test_user",
            snapshot_id="snap_1",
            window_seconds=60,
        )


def test_score_normalization_properties():
    """Verify monotonic 0-100 normalization mapping."""
    # At decision boundary s=0: exactly 50.0
    assert IsolationForestDetector.normalize_score(0.0) == 50.0

    # Inliers (s > 0): score < 50.0
    score_normal = IsolationForestDetector.normalize_score(0.2)
    assert 0.0 <= score_normal < 50.0

    # Outliers (s < 0): score > 50.0
    score_anom = IsolationForestDetector.normalize_score(-0.2)
    assert 50.0 < score_anom <= 100.0

    # Monotonicity check
    s_values = [-0.5, -0.3, -0.1, 0.0, 0.1, 0.3, 0.5]
    scores = [IsolationForestDetector.normalize_score(s) for s in s_values]
    for i in range(len(scores) - 1):
        assert scores[i] >= scores[i + 1]


def test_normal_vector_evaluation(normal_training_data):
    """Evaluating a point close to training mean yields NORMAL decision."""
    detector = IsolationForestDetector(contamination=0.05, random_seed=42, n_estimators=50)
    detector.fit(normal_training_data)

    # Evaluate point at the exact mean of the training data
    mean_vec = list(detector.scaler.mean_)
    result = detector.evaluate_vector(
        vector=mean_vec,
        entity_type=EntityType.USER,
        entity_id="alice",
        snapshot_id="snap_alice_1",
        window_seconds=60,
    )

    assert result.detector_type == "ISOLATION_FOREST"
    assert result.entity_type == EntityType.USER
    assert result.raw_prediction == 1
    assert result.is_anomalous is False
    assert result.status == "NORMAL"
    assert result.normalized_anomaly_score < 50.0
    assert "normal" in result.explanation.lower()


def test_anomalous_vector_and_explainability(normal_training_data):
    """Evaluating an extreme multi-feature outlier triggers ANOMALOUS with ranked deviations."""
    detector = IsolationForestDetector(contamination=0.05, random_seed=42, n_estimators=50)
    detector.fit(normal_training_data)

    # Create an extreme multi-dimensional attack pattern:
    extreme_vec = list(detector.scaler.mean_)
    for i in range(len(extreme_vec)):
        extreme_vec[i] += 5.0 * detector.scaler.scale_[i]
    # Extra strong spikes on specific attack indicators
    extreme_vec[0] += 50.0 * detector.scaler.scale_[0]  # failed_login_rate
    extreme_vec[2] += 30.0 * detector.scaler.scale_[2]  # unique_accounts_targeted

    result = detector.evaluate_vector(
        vector=extreme_vec,
        entity_type=EntityType.IP,
        entity_id="192.168.1.100",
        snapshot_id="snap_atk_1",
        window_seconds=60,
    )

    assert result.raw_prediction == -1
    assert result.is_anomalous is True
    assert result.status == "ANOMALOUS"
    assert result.normalized_anomaly_score > 50.0

    # Verify explainability layer
    assert len(result.top_feature_deviations) > 0
    top_dev = result.top_feature_deviations[0]
    assert top_dev.feature_name == "failed_login_rate"
    assert top_dev.direction == "HIGH"
    assert top_dev.deviation_score >= 40.0

    # Ensure ranked in descending order
    dev_scores = [d.deviation_score for d in result.top_feature_deviations]
    assert dev_scores == sorted(dev_scores, reverse=True)

    # Verify explanation contains non-causal disclaimer
    assert "Top feature deviations associated with the anomaly signal" in result.explanation
    assert "Post-hoc" in result.explanation


def test_detector_determinism(normal_training_data):
    """Identical random seeds must yield identical predictions and scores."""
    d1 = IsolationForestDetector(contamination=0.05, random_seed=99, n_estimators=30).fit(normal_training_data)
    d2 = IsolationForestDetector(contamination=0.05, random_seed=99, n_estimators=30).fit(normal_training_data)

    test_vec = list(normal_training_data[10])
    res1 = d1.evaluate_vector(test_vec, EntityType.USER, "u1", "s1", 60)
    res2 = d2.evaluate_vector(test_vec, EntityType.USER, "u1", "s1", 60)

    assert res1.raw_prediction == res2.raw_prediction
    assert res1.raw_decision_score == res2.raw_decision_score
    assert res1.normalized_anomaly_score == res2.normalized_anomaly_score


def test_state_export_and_import(normal_training_data):
    """Detector state can be serialized and deserialized restoring full functionality."""
    d1 = IsolationForestDetector(contamination=0.05, random_seed=42, n_estimators=30).fit(normal_training_data)
    state = d1.get_state()

    d2 = IsolationForestDetector()
    d2.set_state(state)

    assert d2.is_fitted
    assert d2.training_sample_count == d1.training_sample_count
    assert d2.contamination == d1.contamination

    test_vec = list(normal_training_data[5])
    r1 = d1.evaluate_vector(test_vec, EntityType.USER, "u", "s", 60)
    r2 = d2.evaluate_vector(test_vec, EntityType.USER, "u", "s", 60)

    assert r1.raw_prediction == r2.raw_prediction
    assert r1.normalized_anomaly_score == r2.normalized_anomaly_score
