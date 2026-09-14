"""Unit tests for Behavioral Clustering detector, KMeans, StandardScaler, PCA, and explainability."""

import numpy as np
import pytest

from backend.detection.behavioral_clustering import BehavioralClusteringDetector
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import (
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    extract_feature_vector,
)


@pytest.fixture
def normal_training_data() -> np.ndarray:
    """Generate 200 normal behavioral feature vectors clustered in 3 natural modes."""
    rng = np.random.RandomState(42)
    # Mode 1: regular web users
    m1 = rng.normal(loc=0.05, scale=0.01, size=(80, FEATURE_COUNT))
    # Mode 2: internal developers / higher port & connection activity
    m2 = rng.normal(loc=0.15, scale=0.02, size=(70, FEATURE_COUNT))
    # Mode 3: automated system tasks / lower login frequency, stable connections
    m3 = rng.normal(loc=0.08, scale=0.01, size=(50, FEATURE_COUNT))

    matrix = np.vstack([m1, m2, m3])
    return np.maximum(0.0, matrix)


def test_detector_fit_scaler_kmeans_and_pca(normal_training_data):
    """Detector fits StandardScaler, KMeans (k=5), and PCA (n=2) on 21-D matrix."""
    detector = BehavioralClusteringDetector(n_clusters=5, random_seed=42)
    assert not detector.is_fitted

    detector.fit(normal_training_data)
    assert detector.is_fitted
    assert detector.training_sample_count == 200
    assert detector.n_clusters == 5

    # Scaler verification
    assert detector.scaler is not None
    assert len(detector.scaler.mean_) == FEATURE_COUNT
    assert len(detector.scaler.scale_) == FEATURE_COUNT

    # KMeans verification
    assert detector.kmeans is not None
    assert detector.kmeans.cluster_centers_.shape == (5, FEATURE_COUNT)

    # PCA verification
    assert detector.pca is not None
    assert detector.pca.components_.shape == (2, FEATURE_COUNT)

    # 95th percentile threshold verification
    assert detector.threshold_distance > 0.0
    assert len(detector.cluster_profiles) == 5


def test_unfitted_detector_raises():
    """Attempting to evaluate before fitting must raise RuntimeError."""
    detector = BehavioralClusteringDetector()
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
    threshold = 4.0

    # At centroid (d = 0): exactly 0.0
    assert BehavioralClusteringDetector.normalize_score(0.0, threshold) == 0.0

    # At threshold (d = threshold): exactly 50.0
    assert BehavioralClusteringDetector.normalize_score(threshold, threshold) == 50.0

    # Inliers (d < threshold): score < 50.0
    score_inlier = BehavioralClusteringDetector.normalize_score(2.0, threshold)
    assert 0.0 < score_inlier < 50.0
    assert score_inlier == 25.0

    # Outliers (d > threshold): score > 50.0
    score_outlier = BehavioralClusteringDetector.normalize_score(8.0, threshold)
    assert 50.0 < score_outlier <= 100.0

    # Monotonicity check
    d_values = [0.0, 1.0, 2.0, 4.0, 6.0, 10.0, 20.0, 50.0]
    scores = [BehavioralClusteringDetector.normalize_score(d, threshold) for d in d_values]
    for i in range(len(scores) - 1):
        assert scores[i] <= scores[i + 1]


def test_normal_vector_evaluation(normal_training_data):
    """Evaluating a point close to training distribution yields NORMAL decision with score <= 50."""
    detector = BehavioralClusteringDetector(n_clusters=5, random_seed=42)
    detector.fit(normal_training_data)

    test_vec = list(normal_training_data[10])
    result = detector.evaluate_vector(
        vector=test_vec,
        entity_type=EntityType.USER,
        entity_id="bob",
        snapshot_id="snap_bob_1",
        window_seconds=60,
    )

    assert result.detector_type == "BEHAVIORAL_CLUSTERING"
    assert result.entity_type == EntityType.USER
    assert 0 <= result.assigned_cluster_id < 5
    assert result.cluster_distance <= result.threshold_distance or result.distance_ratio <= 1.05
    assert result.is_anomalous is False
    assert result.status == "NORMAL"
    assert result.normalized_anomaly_score <= 55.0
    assert result.pca_coordinates is not None
    assert len(result.pca_coordinates) == 2


def test_anomalous_outlier_vector(normal_training_data):
    """Evaluating an extreme outlier triggers ANOMALOUS decision with score > 50 and ranked deviations."""
    detector = BehavioralClusteringDetector(n_clusters=5, random_seed=42)
    detector.fit(normal_training_data)

    # Construct an extreme behavioral outlier
    outlier_vec = [10.0] * FEATURE_COUNT
    outlier_vec[0] = 50.0  # massive failed login rate
    outlier_vec[2] = 200.0  # massive accounts targeted

    result = detector.evaluate_vector(
        vector=outlier_vec,
        entity_type=EntityType.IP,
        entity_id="192.168.1.99",
        snapshot_id="snap_outlier_1",
        window_seconds=60,
    )

    assert result.cluster_distance > detector.threshold_distance
    assert result.is_anomalous is True
    assert result.status == "ANOMALOUS"
    assert result.normalized_anomaly_score > 50.0

    # Verify explainability
    assert len(result.top_feature_deviations) > 0
    top_dev = result.top_feature_deviations[0]
    assert top_dev.scaled_deviation > 0.0
    assert top_dev.direction in ("HIGH", "LOW")

    # Verify explanation contains non-causal attribution disclaimer
    assert "Behavioral clustering anomaly detected" in result.explanation
    assert "Top feature deviations associated with the clustering signal" in result.explanation
    assert "not causal proof" in result.explanation


def test_detector_determinism(normal_training_data):
    """Identical random seeds must yield identical cluster assignments, centroids, and scores."""
    d1 = BehavioralClusteringDetector(n_clusters=4, random_seed=42).fit(normal_training_data)
    d2 = BehavioralClusteringDetector(n_clusters=4, random_seed=42).fit(normal_training_data)

    test_vec = list(normal_training_data[25])
    r1 = d1.evaluate_vector(test_vec, EntityType.USER, "u1", "s1", 60)
    r2 = d2.evaluate_vector(test_vec, EntityType.USER, "u1", "s1", 60)

    assert r1.assigned_cluster_id == r2.assigned_cluster_id
    assert r1.cluster_distance == r2.cluster_distance
    assert r1.normalized_anomaly_score == r2.normalized_anomaly_score
    assert r1.pca_coordinates == r2.pca_coordinates


def test_state_export_and_import(normal_training_data):
    """Detector state can be serialized and restored preserving complete inference behavior."""
    d1 = BehavioralClusteringDetector(n_clusters=5, random_seed=42).fit(normal_training_data)
    state = d1.get_state()

    d2 = BehavioralClusteringDetector()
    d2.set_state(state)

    assert d2.is_fitted
    assert d2.n_clusters == d1.n_clusters
    assert d2.threshold_distance == d1.threshold_distance
    assert len(d2.cluster_profiles) == 5

    test_vec = list(normal_training_data[30])
    r1 = d1.evaluate_vector(test_vec, EntityType.USER, "u", "s", 60)
    r2 = d2.evaluate_vector(test_vec, EntityType.USER, "u", "s", 60)

    assert r1.assigned_cluster_id == r2.assigned_cluster_id
    assert r1.cluster_distance == r2.cluster_distance
    assert r1.normalized_anomaly_score == r2.normalized_anomaly_score
