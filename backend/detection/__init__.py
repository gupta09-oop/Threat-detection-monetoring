"""Detection package for Sh4d0w_St4lk3r anomaly and threat detection engines."""

from backend.detection.schemas import (
    StatisticalBaseline,
    StatisticalAnomalyResult,
    IsolationForestAnomalyResult,
    TopFeatureDeviation,
    IsolationForestModelStatus,
    IsolationForestTrainRequest,
    IsolationForestTrainResponse,
    ClusterFeatureDeviation,
    ClusterProfile,
    BehavioralClusteringAnomalyResult,
    BehavioralClusteringTrainRequest,
    BehavioralClusteringTrainResponse,
    BehavioralClusteringModelStatus,
    EvidenceStrength,
    FusionDetectorEvidence,
    DeterministicRuleEvidence,
    FusionResult,
    FusionEvaluateRequest,
    FusionActiveEvaluateRequest,
)
from backend.detection.baseline_service import (
    BaselineService,
    baseline_service,
)
from backend.detection.statistical_detector import (
    StatisticalDetector,
    statistical_detector,
)
from backend.detection.isolation_forest import (
    IsolationForestDetector,
)
from backend.detection.isolation_forest_service import (
    IsolationForestService,
    isolation_forest_service,
)
from backend.detection.behavioral_clustering import (
    BehavioralClusteringDetector,
)
from backend.detection.clustering_service import (
    BehavioralClusteringService,
    behavioral_clustering_service,
)
from backend.detection.fusion_service import (
    AnomalyFusionService,
    anomaly_fusion_service,
)

__all__ = [
    "StatisticalBaseline",
    "StatisticalAnomalyResult",
    "IsolationForestAnomalyResult",
    "TopFeatureDeviation",
    "IsolationForestModelStatus",
    "IsolationForestTrainRequest",
    "IsolationForestTrainResponse",
    "ClusterFeatureDeviation",
    "ClusterProfile",
    "BehavioralClusteringAnomalyResult",
    "BehavioralClusteringTrainRequest",
    "BehavioralClusteringTrainResponse",
    "BehavioralClusteringModelStatus",
    "EvidenceStrength",
    "FusionDetectorEvidence",
    "DeterministicRuleEvidence",
    "FusionResult",
    "FusionEvaluateRequest",
    "FusionActiveEvaluateRequest",
    "BaselineService",
    "baseline_service",
    "StatisticalDetector",
    "statistical_detector",
    "IsolationForestDetector",
    "IsolationForestService",
    "isolation_forest_service",
    "BehavioralClusteringDetector",
    "BehavioralClusteringService",
    "behavioral_clustering_service",
    "AnomalyFusionService",
    "anomaly_fusion_service",
]
