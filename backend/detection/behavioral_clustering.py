"""Core Behavioral Clustering Anomaly Detector for Sh4d0w_St4lk3r.

Consumes canonical 21-dimensional behavioral feature vectors,
scales with StandardScaler fitted strictly on normal baseline data,
fits KMeans clustering to group behavioral profiles, and establishes
a 95th-percentile cluster-distance anomaly threshold with 2D PCA projections.
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from backend.detection.schemas import (
    BehavioralClusteringAnomalyResult,
    ClusterFeatureDeviation,
    ClusterProfile,
)
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import (
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    extract_feature_vector,
)


class BehavioralClusteringDetector:
    """Unsupervised KMeans behavioral clustering detector.
    
    Adheres strictly to the platform blueprint:
    - Independent detection evidence (not combined here with Isolation Forest or Z-Score)
    - StandardScaler fitted ONLY on normal baseline feature windows
    - Configurable K (default 5), stable deterministic initialization (random_state=42)
    - 95th percentile within-cluster distance anomaly decision threshold
    - 0-100 normalized behavioral clustering anomaly score
    - 2D PCA projection for future SOC visualization
    - Post-hoc top feature deviations against assigned cluster centroid
    """

    def __init__(
        self,
        n_clusters: int = 5,
        random_seed: int = 42,
        distance_percentile: float = 95.0,
    ) -> None:
        self.n_clusters = max(2, n_clusters)
        self.random_seed = random_seed
        self.distance_percentile = distance_percentile

        self.scaler: Optional[StandardScaler] = None
        self.kmeans: Optional[KMeans] = None
        self.pca: Optional[PCA] = None

        self.threshold_distance: float = 0.0
        self.cluster_profiles: List[ClusterProfile] = []
        self.training_sample_count: int = 0
        self.trained_at: Optional[datetime] = None
        self.feature_names: List[str] = list(CANONICAL_FEATURE_NAMES)
        self.feature_schema_version: str = FEATURE_SCHEMA_VERSION
        self.is_fitted: bool = False

    def _derive_cluster_characteristics(
        self,
        centroid_unscaled: np.ndarray,
        centroid_scaled: np.ndarray,
    ) -> List[str]:
        """Generate behavioral description for a cluster centroid based on relative feature elevation."""
        traits: List[str] = []
        feat_map = {name: float(val) for name, val in zip(self.feature_names, centroid_unscaled)}
        scaled_map = {name: float(val) for name, val in zip(self.feature_names, centroid_scaled)}

        if feat_map.get("failed_login_rate", 0.0) > 0.3 or scaled_map.get("failed_login_rate", 0.0) > 1.5:
            traits.append("Elevated authentication failure rate")
        if feat_map.get("unique_accounts_targeted", 0.0) > 5 or scaled_map.get("unique_accounts_targeted", 0.0) > 1.5:
            traits.append("Broad account targeting")
        if feat_map.get("connection_rate", 0.0) > 5.0 or scaled_map.get("connection_rate", 0.0) > 1.5:
            traits.append("High connection frequency")
        if feat_map.get("port_diversity", 0.0) > 0.5 or scaled_map.get("port_diversity", 0.0) > 1.5:
            traits.append("High destination port dispersion")
        if feat_map.get("temporal_concentration", 0.0) > 0.7 or scaled_map.get("temporal_concentration", 0.0) > 1.5:
            traits.append("Temporal event clustering / burstiness")
        if feat_map.get("distributed_attempt_score", 0.0) > 0.5 or scaled_map.get("distributed_attempt_score", 0.0) > 1.5:
            traits.append("Distributed multi-source coordination")

        if not traits:
            traits.append("Nominal baseline telemetry activity")

        return traits

    def fit(self, feature_matrix: np.ndarray) -> "BehavioralClusteringDetector":
        """Fit StandardScaler, KMeans, and 2D PCA on normal baseline feature vectors.
        
        Args:
            feature_matrix: 2D numpy array of shape (n_samples, 21)
        """
        if feature_matrix.ndim != 2 or feature_matrix.shape[1] != FEATURE_COUNT:
            raise ValueError(
                f"Expected feature matrix with shape (N, {FEATURE_COUNT}), got {feature_matrix.shape}"
            )

        n_samples = feature_matrix.shape[0]
        if n_samples < self.n_clusters:
            raise ValueError(
                f"Insufficient samples ({n_samples}) to fit {self.n_clusters} clusters. "
                f"Sample count must be >= n_clusters."
            )

        # 1. Fit StandardScaler on normal baseline vectors
        self.scaler = StandardScaler()
        scaled_matrix = self.scaler.fit_transform(feature_matrix)

        # 2. Fit KMeans on scaled normal vectors
        self.kmeans = KMeans(
            n_clusters=self.n_clusters,
            random_state=self.random_seed,
            n_init=10,
        )
        labels = self.kmeans.fit_predict(scaled_matrix)

        # 3. Fit PCA (n_components=2) for visualization projection
        self.pca = PCA(n_components=2, random_state=self.random_seed)
        self.pca.fit(scaled_matrix)

        # 4. Calculate distances from each training sample to its assigned centroid
        centroids_scaled = self.kmeans.cluster_centers_  # shape: (k, 21)
        sample_centroids = centroids_scaled[labels]
        training_distances = np.linalg.norm(scaled_matrix - sample_centroids, axis=1)

        # 5. Determine 95th percentile distance threshold
        self.threshold_distance = float(
            np.percentile(training_distances, self.distance_percentile)
        )
        # Protect against degenerate zero-threshold case
        if self.threshold_distance <= 1e-6:
            self.threshold_distance = float(np.mean(training_distances) + 1e-3)

        # 6. Build cluster profiles
        centroids_unscaled = self.scaler.inverse_transform(centroids_scaled)
        self.cluster_profiles = []

        for c_id in range(self.n_clusters):
            mask = (labels == c_id)
            c_size = int(np.sum(mask))
            proportion = float(c_size / n_samples) if n_samples > 0 else 0.0

            if c_size > 0:
                c_distances = training_distances[mask]
                mean_dist = float(np.mean(c_distances))
                max_dist = float(np.max(c_distances))
            else:
                mean_dist = 0.0
                max_dist = 0.0

            centroid_dict = {
                name: round(float(val), 4)
                for name, val in zip(self.feature_names, centroids_unscaled[c_id])
            }

            characteristics = self._derive_cluster_characteristics(
                centroids_unscaled[c_id],
                centroids_scaled[c_id],
            )

            self.cluster_profiles.append(
                ClusterProfile(
                    cluster_id=c_id,
                    size=c_size,
                    proportion=round(proportion, 4),
                    mean_distance=round(mean_dist, 4),
                    max_distance=round(max_dist, 4),
                    centroid=centroid_dict,
                    characteristics=characteristics,
                )
            )

        self.training_sample_count = n_samples
        self.trained_at = datetime.now(timezone.utc)
        self.is_fitted = True

        return self

    @staticmethod
    def normalize_score(distance: float, threshold: float) -> float:
        """Convert centroid distance into a normalized 0–100 behavioral clustering anomaly score.
        
        Mathematical Transformation:
        The learned threshold represents the 95th percentile of normal distances.
        We establish a piecewise continuous, strictly monotonic mapping centered at the threshold:
        
        1. If distance <= threshold:
           normalized_score = 50.0 * (distance / threshold)
           - Points at centroid (d = 0.0) receive 0.0.
           - Normal points within baseline receive scores from 0.0 to 50.0.
        
        2. If distance > threshold:
           normalized_score = 50.0 + 50.0 * (1.0 - exp(-1.0 * (distance - threshold) / threshold))
           - Points crossing threshold receive > 50.0.
           - Extreme outliers smoothly asymptote toward 100.0 without hard clipping.
        
        Properties:
        - At decision threshold (d = threshold): normalized_score = 50.0
        - Inliers (d <= threshold): normalized_score <= 50.0
        - Outliers (d > threshold): normalized_score > 50.0
        - Strictly bounded in [0.0, 100.0]
        - Lower = more normal, higher = more anomalous
        """
        thresh = max(1e-6, threshold)
        dist = max(0.0, distance)

        if dist <= thresh:
            score = 50.0 * (dist / thresh)
        else:
            excess = dist - thresh
            score = 50.0 + 50.0 * (1.0 - math.exp(-1.0 * excess / thresh))

        return round(float(min(100.0, max(0.0, score))), 2)

    def compute_feature_deviations(
        self,
        scaled_vector: np.ndarray,
        cluster_id: int,
        raw_vector: np.ndarray,
        top_k: int = 5,
    ) -> List[ClusterFeatureDeviation]:
        """Compute feature deviations between snapshot and assigned cluster centroid."""
        if not self.is_fitted or self.kmeans is None or self.scaler is None:
            return []

        centroid_scaled = self.kmeans.cluster_centers_[cluster_id]
        centroid_unscaled = self.scaler.inverse_transform(centroid_scaled.reshape(1, -1))[0]

        deviations: List[ClusterFeatureDeviation] = []

        for i, name in enumerate(self.feature_names):
            val_raw = float(raw_vector[i])
            c_raw = float(centroid_unscaled[i])
            val_scaled = float(scaled_vector[i])
            c_scaled = float(centroid_scaled[i])

            diff_scaled = val_scaled - c_scaled
            abs_diff = abs(diff_scaled)
            direction = "HIGH" if diff_scaled >= 0 else "LOW"

            deviations.append(
                ClusterFeatureDeviation(
                    feature_name=name,
                    feature_value=round(val_raw, 4),
                    centroid_value=round(c_raw, 4),
                    scaled_deviation=round(abs_diff, 2),
                    direction=direction,
                )
            )

        # Sort descending by deviation magnitude in normalized space
        deviations.sort(key=lambda d: d.scaled_deviation, reverse=True)
        return deviations[:top_k]

    def evaluate_vector(
        self,
        vector: List[float],
        entity_type: EntityType,
        entity_id: str,
        snapshot_id: str,
        window_seconds: int,
        timestamp: Optional[datetime] = None,
    ) -> BehavioralClusteringAnomalyResult:
        """Evaluate a 21-dimensional feature vector against learned KMeans behavioral clusters."""
        if not self.is_fitted or self.kmeans is None or self.scaler is None or self.pca is None:
            raise RuntimeError(
                "Behavioral Clustering detector is not fitted. Cannot evaluate vector."
            )

        ts = timestamp or datetime.now(timezone.utc)
        raw_arr = np.array(vector, dtype=float).reshape(1, -1)

        # 1. Scale incoming feature vector
        scaled_arr = self.scaler.transform(raw_arr)

        # 2. Assign nearest cluster and compute Euclidean distance
        cluster_id = int(self.kmeans.predict(scaled_arr)[0])
        centroid_scaled = self.kmeans.cluster_centers_[cluster_id]
        distance = float(np.linalg.norm(scaled_arr[0] - centroid_scaled))

        # 3. 2D PCA projection for SOC visualization
        pca_coords = [
            round(float(coord), 4)
            for coord in self.pca.transform(scaled_arr)[0]
        ]

        # 4. Determine anomaly state against 95th percentile threshold
        is_anomalous = (distance > self.threshold_distance)
        status = "ANOMALOUS" if is_anomalous else "NORMAL"
        norm_score = self.normalize_score(distance, self.threshold_distance)
        dist_ratio = round(distance / max(1e-6, self.threshold_distance), 2)

        # 5. Explainability deviations
        deviations = self.compute_feature_deviations(
            scaled_vector=scaled_arr[0],
            cluster_id=cluster_id,
            raw_vector=raw_arr[0],
            top_k=5,
        )

        cluster_profile = (
            self.cluster_profiles[cluster_id]
            if cluster_id < len(self.cluster_profiles)
            else None
        )
        characteristics = cluster_profile.characteristics if cluster_profile else []

        if is_anomalous:
            top_dev_str = ", ".join(
                f"{d.feature_name} ({d.direction} {d.scaled_deviation}σ from centroid)"
                for d in deviations[:3]
            )
            explanation = (
                f"Behavioral clustering anomaly detected (cluster: {cluster_id}, "
                f"distance: {round(distance, 4)} vs 95th percentile threshold {round(self.threshold_distance, 4)}, "
                f"anomaly score: {norm_score}/100, decision: ANOMALOUS). "
                f"Top feature deviations associated with the clustering signal: {top_dev_str}. "
                f"Note: Post-hoc feature deviation analysis relative to cluster centroid, not causal proof."
            )
        else:
            explanation = (
                f"Behavioral clustering evaluation indicates expected normal pattern "
                f"(cluster: {cluster_id}, distance: {round(distance, 4)} <= threshold {round(self.threshold_distance, 4)}, "
                f"anomaly score: {norm_score}/100, decision: NORMAL)."
            )

        details = {
            "assigned_cluster_id": cluster_id,
            "cluster_distance": round(distance, 4),
            "threshold_distance": round(self.threshold_distance, 4),
            "distance_ratio": dist_ratio,
            "normalized_anomaly_score": norm_score,
            "cluster_characteristics": characteristics,
            "pca_coordinates": pca_coords,
            "feature_schema_version": self.feature_schema_version,
            "training_sample_count": self.training_sample_count,
            "n_clusters": self.n_clusters,
            "random_seed": self.random_seed,
            "feature_vector": {
                name: round(val, 4)
                for name, val in zip(self.feature_names, vector)
            },
        }

        return BehavioralClusteringAnomalyResult(
            timestamp=ts,
            detector_type="BEHAVIORAL_CLUSTERING",
            entity_type=entity_type,
            entity_id=entity_id,
            snapshot_id=snapshot_id,
            window_seconds=window_seconds,
            feature_name="BEHAVIORAL_VECTOR_21D",
            assigned_cluster_id=cluster_id,
            cluster_distance=round(distance, 4),
            threshold_distance=round(self.threshold_distance, 4),
            distance_ratio=dist_ratio,
            is_anomalous=is_anomalous,
            anomaly_score=norm_score,
            normalized_anomaly_score=norm_score,
            explanation=explanation,
            status=status,
            top_feature_deviations=deviations,
            cluster_characteristics=characteristics,
            pca_coordinates=pca_coords,
            details=details,
        )

    def evaluate_snapshot(self, snapshot: FeatureSnapshot) -> BehavioralClusteringAnomalyResult:
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
            "scaler": self.scaler,
            "kmeans": self.kmeans,
            "pca": self.pca,
            "n_clusters": self.n_clusters,
            "random_seed": self.random_seed,
            "distance_percentile": self.distance_percentile,
            "threshold_distance": self.threshold_distance,
            "cluster_profiles": [p.model_dump() for p in self.cluster_profiles],
            "feature_names": self.feature_names,
            "feature_schema_version": self.feature_schema_version,
            "training_sample_count": self.training_sample_count,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
        }

    def set_state(self, state: Dict[str, Any]) -> "BehavioralClusteringDetector":
        """Restore internal state from loaded joblib dictionary."""
        self.scaler = state["scaler"]
        self.kmeans = state["kmeans"]
        self.pca = state["pca"]
        self.n_clusters = state.get("n_clusters", self.n_clusters)
        self.random_seed = state.get("random_seed", self.random_seed)
        self.distance_percentile = state.get("distance_percentile", self.distance_percentile)
        self.threshold_distance = float(state["threshold_distance"])

        raw_profiles = state.get("cluster_profiles", [])
        self.cluster_profiles = [
            ClusterProfile(**p) if isinstance(p, dict) else p
            for p in raw_profiles
        ]

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
