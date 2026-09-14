"""Pydantic schemas for statistical baselines and anomaly detection results."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from backend.features.schemas import EntityType


class StatisticalBaseline(BaseModel):
    """Statistical baseline representing learned normal behavior for an entity and feature."""
    model_config = ConfigDict(extra="ignore")

    baseline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Entity identifier (username, IP, or GLOBAL)")
    window_seconds: int = Field(..., description="Time window in seconds (60, 300, 900)")
    feature_name: str = Field(..., description="Name of the numerical behavioral feature")
    mean: float = Field(..., description="Sample mean of historical feature values")
    stddev: float = Field(..., description="Sample standard deviation of historical feature values")
    sample_count: int = Field(..., ge=0, description="Total historical feature snapshots analyzed")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StatisticalAnomalyResult(BaseModel):
    """Transparent statistical deviation result for a feature snapshot."""
    model_config = ConfigDict(extra="ignore")

    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detector_type: str = Field(default="STATISTICAL_ZSCORE", description="Detection algorithm identifier")
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Entity identifier")
    snapshot_id: str = Field(..., description="Reference to evaluated feature snapshot")
    window_seconds: int = Field(..., description="Time window in seconds")
    feature_name: str = Field(..., description="Evaluated feature name")
    current_value: float = Field(..., description="Feature value in current snapshot")
    baseline_mean: Optional[float] = Field(default=None, description="Historical baseline mean")
    baseline_stddev: Optional[float] = Field(default=None, description="Historical baseline standard deviation")
    sample_count: int = Field(default=0, description="Historical sample count")
    signed_z_score: Optional[float] = Field(default=None, description="Directional statistical deviation (positive/negative)")
    absolute_z_score: Optional[float] = Field(default=None, description="Magnitude of statistical deviation |z|")
    is_anomalous: bool = Field(default=False, description="Whether |z| exceeds statistical anomaly threshold")
    anomaly_score: float = Field(default=0.0, description="Normalized, capped statistical contribution signal")
    explanation: str = Field(..., description="Transparent analyst explanation for deviation or abstention")
    status: str = Field(default="NORMAL", description="Evaluation outcome: NORMAL, ANOMALOUS, or ABSTAIN")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic and contextual metadata")


class TopFeatureDeviation(BaseModel):
    """Post-hoc explanation item ranking a feature's deviation relative to normal baseline."""
    feature_name: str = Field(..., description="Canonical feature name")
    feature_value: float = Field(..., description="Observed feature value in evaluated snapshot")
    baseline_mean: float = Field(..., description="Fitted StandardScaler mean from training distribution")
    baseline_stddev: float = Field(..., description="Fitted StandardScaler scale from training distribution")
    deviation_score: float = Field(..., description="Absolute z-deviation magnitude relative to normal training data")
    direction: str = Field(..., description="Direction of deviation: HIGH or LOW")


class IsolationForestAnomalyResult(BaseModel):
    """Unsupervised Isolation Forest behavioral anomaly detection result."""
    model_config = ConfigDict(extra="ignore")

    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detector_type: str = Field(default="ISOLATION_FOREST", description="Detection algorithm identifier")
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Entity identifier")
    snapshot_id: str = Field(..., description="Reference to evaluated feature snapshot")
    window_seconds: int = Field(..., description="Time window in seconds")
    feature_name: str = Field(default="BEHAVIORAL_VECTOR_21D", description="Evaluated feature or vector scope")
    raw_decision_score: float = Field(..., description="Native sklearn IsolationForest decision_function output")
    raw_prediction: int = Field(..., description="Native sklearn prediction: 1 (normal) or -1 (anomaly)")
    normalized_anomaly_score: float = Field(..., ge=0.0, le=100.0, description="Normalized behavioral anomaly score (0-100, higher=more anomalous)")
    is_anomalous: bool = Field(default=False, description="True if raw_prediction == -1 (detector decision)")
    anomaly_score: float = Field(default=0.0, description="Mirror of normalized_anomaly_score for unified anomaly_results storage")
    explanation: str = Field(..., description="Post-hoc explanation highlighting top feature deviations")
    status: str = Field(default="NORMAL", description="Evaluation outcome: NORMAL or ANOMALOUS")
    top_feature_deviations: list[TopFeatureDeviation] = Field(default_factory=list, description="Top post-hoc feature deviations")
    details: Dict[str, Any] = Field(default_factory=dict, description="Model metadata, feature vector, and diagnostic context")


class IsolationForestTrainRequest(BaseModel):
    """Request payload to train or retrain the Isolation Forest detector."""
    min_samples: Optional[int] = Field(default=None, description="Minimum normal samples required to fit")
    target_samples: Optional[int] = Field(default=None, description="Target training sample count from DB")
    contamination: Optional[float] = Field(default=None, description="Expected proportion of outliers (default 0.05)")
    random_seed: Optional[int] = Field(default=None, description="Random state for reproducible trees (default 42)")
    n_estimators: Optional[int] = Field(default=None, description="Number of isolation trees (default 100)")
    window_seconds: Optional[int] = Field(default=None, description="Filter training snapshots by window duration")


class IsolationForestTrainResponse(BaseModel):
    """Response returned upon training attempt."""
    status: str = Field(..., description="Outcome: SUCCESS, INSUFFICIENT_DATA, or ERROR")
    message: str = Field(..., description="Descriptive status message")
    training_sample_count: int = Field(default=0, description="Number of normal snapshots used to fit model")
    contamination: float = Field(default=0.05)
    random_seed: int = Field(default=42)
    feature_count: int = Field(default=21)
    trained_at: Optional[datetime] = Field(default=None)
    model_path: Optional[str] = Field(default=None)


class IsolationForestModelStatus(BaseModel):
    """Status metadata for the Isolation Forest detector model."""
    is_ready: bool = Field(..., description="Whether model and scaler are fitted and ready for inference")
    status: str = Field(..., description="READY, NOT_READY, or INSUFFICIENT_DATA")
    message: str = Field(..., description="Status summary")
    model_path: Optional[str] = Field(default=None)
    trained_at: Optional[datetime] = Field(default=None)
    training_sample_count: int = Field(default=0)
    contamination: float = Field(default=0.05)
    random_seed: int = Field(default=42)
    n_estimators: int = Field(default=100)
    feature_schema_version: str = Field(default="1.0.0")
    feature_count: int = Field(default=21)


class ClusterFeatureDeviation(BaseModel):
    """Deviation of an evaluated feature dimension relative to assigned cluster centroid."""
    feature_name: str = Field(..., description="Canonical feature name")
    feature_value: float = Field(..., description="Observed feature value in snapshot")
    centroid_value: float = Field(..., description="Cluster centroid feature value in original feature units")
    scaled_deviation: float = Field(..., description="Absolute distance in StandardScaler-normalized space")
    direction: str = Field(..., description="Direction of deviation: HIGH or LOW")


class ClusterProfile(BaseModel):
    """Statistical summary of a learned behavioral cluster."""
    cluster_id: int = Field(..., description="Cluster integer identifier (0..k-1)")
    size: int = Field(..., description="Number of normal training snapshots in cluster")
    proportion: float = Field(..., description="Fraction of training samples in this cluster")
    mean_distance: float = Field(..., description="Mean Euclidean distance of training points to centroid")
    max_distance: float = Field(..., description="Maximum distance observed during training")
    centroid: Dict[str, float] = Field(default_factory=dict, description="Cluster centroid in original feature space")
    characteristics: List[str] = Field(default_factory=list, description="Descriptive behavioral patterns / unusual indicators")


class BehavioralClusteringAnomalyResult(BaseModel):
    """Unsupervised KMeans behavioral clustering anomaly detection result."""
    model_config = ConfigDict(extra="ignore")

    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detector_type: str = Field(default="BEHAVIORAL_CLUSTERING", description="Detection algorithm identifier")
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Entity identifier")
    snapshot_id: str = Field(..., description="Reference to evaluated feature snapshot")
    window_seconds: int = Field(..., description="Time window in seconds")
    feature_name: str = Field(default="BEHAVIORAL_VECTOR_21D", description="Evaluated feature or vector scope")
    assigned_cluster_id: int = Field(..., description="Nearest KMeans cluster ID")
    cluster_distance: float = Field(..., description="Euclidean distance to nearest cluster centroid in scaled space")
    threshold_distance: float = Field(..., description="Learned 95th percentile distance threshold from normal training")
    distance_ratio: float = Field(..., description="Ratio of distance to threshold (d / threshold)")
    is_anomalous: bool = Field(default=False, description="True if cluster_distance > threshold_distance")
    anomaly_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Normalized clustering anomaly score (0-100, higher=more anomalous)")
    normalized_anomaly_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Alias for unified anomaly_results storage")
    explanation: str = Field(..., description="Post-hoc clustering explanation with distance and top deviations")
    status: str = Field(default="NORMAL", description="Evaluation outcome: NORMAL or ANOMALOUS")
    top_feature_deviations: List[ClusterFeatureDeviation] = Field(default_factory=list, description="Top feature deviations from centroid")
    cluster_characteristics: List[str] = Field(default_factory=list, description="Descriptive behavioral traits of assigned cluster")
    pca_coordinates: Optional[List[float]] = Field(default=None, description="2D PCA projection [x, y] for SoC visualization")
    details: Dict[str, Any] = Field(default_factory=dict, description="Clustering diagnostics and metadata")


class BehavioralClusteringTrainRequest(BaseModel):
    """Request payload to train or retrain the Behavioral Clustering detector."""
    n_clusters: Optional[int] = Field(default=None, ge=2, le=20, description="Number of clusters K (default 5)")
    min_samples: Optional[int] = Field(default=None, description="Minimum normal samples required to fit")
    target_samples: Optional[int] = Field(default=None, description="Target training sample count from DB")
    random_seed: Optional[int] = Field(default=None, description="Random seed for KMeans initialization (default 42)")
    distance_percentile: Optional[float] = Field(default=None, ge=50.0, le=99.9, description="Percentile threshold for anomaly (default 95.0)")
    window_seconds: Optional[int] = Field(default=None, description="Filter training snapshots by window duration")


class BehavioralClusteringTrainResponse(BaseModel):
    """Response returned upon clustering training attempt."""
    status: str = Field(..., description="Outcome: SUCCESS, INSUFFICIENT_DATA, or ERROR")
    message: str = Field(..., description="Descriptive status message")
    training_sample_count: int = Field(default=0, description="Number of normal snapshots used to fit model")
    n_clusters: int = Field(default=5)
    threshold_distance: float = Field(default=0.0, description="Learned 95th percentile distance threshold")
    clusters: List[ClusterProfile] = Field(default_factory=list, description="Learned cluster profiles and centroids")
    feature_count: int = Field(default=21)
    trained_at: Optional[datetime] = Field(default=None)
    model_path: Optional[str] = Field(default=None)


class BehavioralClusteringModelStatus(BaseModel):
    """Status metadata for the Behavioral Clustering model."""
    is_ready: bool = Field(..., description="Whether model and scaler are fitted and ready for inference")
    status: str = Field(..., description="READY, NOT_READY, or INSUFFICIENT_DATA")
    message: str = Field(..., description="Status summary")
    model_path: Optional[str] = Field(default=None)
    trained_at: Optional[datetime] = Field(default=None)
    training_sample_count: int = Field(default=0)
    n_clusters: int = Field(default=5)
    threshold_distance: float = Field(default=0.0)
    feature_schema_version: str = Field(default="1.0.0")
    feature_count: int = Field(default=21)
    clusters: List[ClusterProfile] = Field(default_factory=list)


class EvidenceStrength(str, Enum):
    """Independent detector agreement strength level."""
    LOW = "LOW"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    CONCLUSIVE = "CONCLUSIVE"


class FusionDetectorEvidence(BaseModel):
    """Normalized evidence contribution from an independent detection method."""
    model_config = ConfigDict(extra="ignore")

    detector_type: str = Field(..., description="Detection method: STATISTICAL_BASELINE, ISOLATION_FOREST, BEHAVIORAL_CLUSTERING, DETERMINISTIC_RULE")
    detector_status: str = Field(default="NORMAL", description="Status reported by detector: NORMAL, ANOMALOUS, or ABSTAIN")
    detector_score: float = Field(default=0.0, description="Detector-specific raw or normalized anomaly score")
    is_anomalous: bool = Field(default=False, description="Whether this detector flagged behavior as anomalous")
    explanation: str = Field(default="", description="Detector-specific evidence explanation")
    source_result_id: Optional[str] = Field(default=None, description="Reference to source anomaly_results record or rule ID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of evidence")
    entity_type: Optional[EntityType] = Field(default=None, description="Entity type: USER, IP, HOST, GLOBAL")
    entity_id: Optional[str] = Field(default=None, description="Entity identifier")
    feature_name: Optional[str] = Field(default=None, description="Feature or vector scope evaluated")
    window_seconds: Optional[int] = Field(default=None, description="Time window in seconds")
    snapshot_id: Optional[str] = Field(default=None, description="Reference to feature snapshot")
    rule_id: Optional[str] = Field(default=None, description="Deterministic rule identifier if applicable")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional detector-specific diagnostic metadata")


class DeterministicRuleEvidence(BaseModel):
    """Extensible interface for future deterministic rule evidence without hardcoded rules."""
    model_config = ConfigDict(extra="ignore")

    detector_type: str = Field(default="DETERMINISTIC_RULE", description="Identifier for rule detection layer")
    rule_id: str = Field(..., description="Unique rule identifier (e.g. RULE-AUTH-DIST-001)")
    is_anomalous: bool = Field(default=True, description="Whether rule conditions triggered anomaly evidence")
    score: float = Field(default=0.0, description="Rule-specific severity or weight contribution")
    explanation: str = Field(..., description="Human-readable rule match explanation")
    timestamp: Optional[datetime] = Field(default=None, description="Timestamp of rule evaluation")
    entity_type: Optional[EntityType] = Field(default=None, description="Entity type evaluated")
    entity_id: Optional[str] = Field(default=None, description="Entity identifier evaluated")
    snapshot_id: Optional[str] = Field(default=None, description="Optional snapshot identifier")
    window_seconds: Optional[int] = Field(default=None, description="Optional window duration")
    details: Dict[str, Any] = Field(default_factory=dict, description="Rule diagnostic parameters and telemetry context")

    def to_detector_evidence(self) -> FusionDetectorEvidence:
        """Convert deterministic rule evidence into canonical FusionDetectorEvidence format."""
        return FusionDetectorEvidence(
            detector_type="DETERMINISTIC_RULE",
            detector_status="ANOMALOUS" if self.is_anomalous else "NORMAL",
            detector_score=float(self.score),
            is_anomalous=self.is_anomalous,
            explanation=self.explanation,
            source_result_id=self.rule_id,
            timestamp=self.timestamp or datetime.now(timezone.utc),
            entity_type=self.entity_type,
            entity_id=self.entity_id,
            feature_name="DETERMINISTIC_RULE",
            window_seconds=self.window_seconds,
            snapshot_id=self.snapshot_id,
            rule_id=self.rule_id,
            details=self.details,
        )


class FusionResult(BaseModel):
    """Result of combining independent detection evidence within a temporal correlation window."""
    model_config = ConfigDict(extra="ignore")

    fusion_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique fusion evaluation identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp")
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Entity identifier")
    snapshot_id: Optional[str] = Field(default=None, description="Reference feature snapshot if correlated to a snapshot")
    window_seconds: Optional[int] = Field(default=None, description="Time window duration in seconds")
    independent_detector_count: int = Field(default=0, description="Number of independent detection methods evaluated")
    anomalous_detector_count: int = Field(default=0, description="Number of independent detection methods flagging anomalous")
    evidence_strength: EvidenceStrength = Field(default=EvidenceStrength.LOW, description="Evidence strength: LOW, MODERATE, STRONG, CONCLUSIVE")
    contributing_detectors: List[str] = Field(default_factory=list, description="Detector types reporting anomalous evidence")
    detector_results: List[FusionDetectorEvidence] = Field(default_factory=list, description="Preserved individual detector evidence entries")
    fusion_explanation: str = Field(..., description="Transparent analyst explanation detailing independent detector agreement")
    correlation_window_seconds: int = Field(default=300, description="Temporal window used for detector correlation")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic and contextual metadata")


class FusionEvaluateRequest(BaseModel):
    """Request payload to perform anomaly fusion evaluation."""
    snapshot_id: Optional[str] = Field(default=None, description="Evaluate all detector results linked to this snapshot")
    entity_type: Optional[EntityType] = Field(default=None, description="Target entity type")
    entity_id: Optional[str] = Field(default=None, description="Target entity identifier")
    window_seconds: Optional[int] = Field(default=None, description="Time window in seconds")
    detector_evidence: Optional[List[FusionDetectorEvidence]] = Field(default=None, description="Explicit detector evidence entries")
    rule_evidence: Optional[List[DeterministicRuleEvidence]] = Field(default=None, description="Optional deterministic rule evidence entries")
    correlation_window_seconds: Optional[int] = Field(default=None, description="Override temporal correlation window in seconds")
    persist: bool = Field(default=True, description="Whether to persist fusion result in fusion_results table")


class FusionActiveEvaluateRequest(BaseModel):
    """Request payload to evaluate recent active entities and snapshots."""
    window_seconds: Optional[int] = Field(default=None, description="Optional window filter")
    limit: int = Field(default=20, ge=1, le=100, description="Maximum number of active snapshots to evaluate")
    correlation_window_seconds: Optional[int] = Field(default=None, description="Override temporal correlation window in seconds")
