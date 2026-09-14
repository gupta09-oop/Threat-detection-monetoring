"""Pydantic schemas and models for Explainable Risk Scoring.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from backend.detection.schemas import (
    DeterministicRuleEvidence,
    EvidenceStrength,
    FusionDetectorEvidence,
)
from backend.features.schemas import EntityType


class RiskSeverity(str, Enum):
    """Platform risk score severity classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StatisticalContributor(BaseModel):
    """Explainable evidence contribution from Statistical Baseline Z-score detector."""
    model_config = ConfigDict(extra="ignore")

    score: float = Field(default=0.0, description="Risk contribution (0 to 25)")
    maximum: float = Field(default=25.0, description="Maximum component contribution cap")
    evidence: str = Field(default="NORMAL", description="Status: NORMAL, ANOMALOUS, or ABSTAIN")
    evaluated_feature_count: int = Field(default=0, description="Total statistical features scored")
    anomalous_feature_count: int = Field(default=0, description="Statistical features exceeding z-threshold")
    features: List[Dict[str, Any]] = Field(default_factory=list, description="Per-feature statistical deviation details")
    explanation: str = Field(default="", description="Human-readable contributor explanation")


class IsolationForestContributor(BaseModel):
    """Explainable evidence contribution from Isolation Forest behavioral detector."""
    model_config = ConfigDict(extra="ignore")

    score: float = Field(default=0.0, description="Risk contribution (0 to 25)")
    maximum: float = Field(default=25.0, description="Maximum component contribution cap")
    evidence: str = Field(default="NORMAL", description="Status: NORMAL or ANOMALOUS")
    raw_decision_score: Optional[float] = Field(default=None, description="Raw Isolation Forest decision function score")
    normalized_anomaly_score: Optional[float] = Field(default=None, description="Normalized anomaly score (0-100)")
    explanation: str = Field(default="", description="Detector explanation")
    top_feature_deviations: List[Dict[str, Any]] = Field(default_factory=list, description="Top deviating behavioral features")


class ClusteringContributor(BaseModel):
    """Explainable evidence contribution from Behavioral Clustering detector."""
    model_config = ConfigDict(extra="ignore")

    score: float = Field(default=0.0, description="Risk contribution (0 to 20)")
    maximum: float = Field(default=20.0, description="Maximum component contribution cap")
    evidence: str = Field(default="NORMAL", description="Status: NORMAL or ANOMALOUS")
    assigned_cluster_id: Optional[int] = Field(default=None, description="Fitted cluster assignment")
    cluster_distance: Optional[float] = Field(default=None, description="Euclidean distance to cluster centroid")
    threshold_distance: Optional[float] = Field(default=None, description="95th percentile normal cluster boundary")
    distance_ratio: Optional[float] = Field(default=None, description="Distance to threshold ratio")
    explanation: str = Field(default="", description="Detector explanation")
    top_feature_deviations: List[Dict[str, Any]] = Field(default_factory=list, description="Top deviating cluster features")
    cluster_characteristics: List[Any] = Field(default_factory=list, description="Cluster profile characteristics")
    pca_coordinates: Optional[List[float]] = Field(default=None, description="2D PCA projection coordinates")


class DeterministicRulesContributor(BaseModel):
    """Explainable evidence contribution from Deterministic Rule detections."""
    model_config = ConfigDict(extra="ignore")

    score: float = Field(default=0.0, description="Aggregated risk contribution (0 to 20)")
    maximum: float = Field(default=20.0, description="Maximum component contribution cap")
    rule_count: int = Field(default=0, description="Number of triggered deterministic rules")
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed list of triggered rule matches")
    explanation: str = Field(default="", description="Aggregated rule evidence explanation")


class CorrelationContributor(BaseModel):
    """Explainable evidence contribution from Independent Multi-Detector Correlation."""
    model_config = ConfigDict(extra="ignore")

    score: float = Field(default=0.0, description="Correlation agreement bonus (0 to 10)")
    maximum: float = Field(default=10.0, description="Maximum component contribution cap")
    evidence_strength: str = Field(default="LOW", description="Agreement level: LOW, MODERATE, STRONG, CONCLUSIVE")
    anomalous_detector_count: int = Field(default=0, description="Independent detector families flagging anomalous")
    independent_detector_count: int = Field(default=0, description="Independent detector families evaluated")
    explanation: str = Field(default="", description="Correlation explanation")


class ContributorBreakdown(BaseModel):
    """Comprehensive explainable breakdown across all 5 risk dimensions."""
    model_config = ConfigDict(extra="ignore")

    statistical: StatisticalContributor = Field(default_factory=StatisticalContributor)
    isolation_forest: IsolationForestContributor = Field(default_factory=IsolationForestContributor)
    behavioral_clustering: ClusteringContributor = Field(default_factory=ClusteringContributor)
    deterministic_rules: DeterministicRulesContributor = Field(default_factory=DeterministicRulesContributor)
    cross_entity_correlation: CorrelationContributor = Field(default_factory=CorrelationContributor)
    final_score: float = Field(default=0.0, description="Composite Threat Risk Score (0 to 100)")
    severity: RiskSeverity = Field(default=RiskSeverity.LOW, description="Severity: LOW, MEDIUM, HIGH, CRITICAL")


class RiskScoreResult(BaseModel):
    """Persisted platform-level explainable Threat Risk Score result."""
    model_config = ConfigDict(extra="ignore")

    risk_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique risk score UUID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp")
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Entity identifier")
    snapshot_id: Optional[str] = Field(default=None, description="Associated feature snapshot UUID")
    window_seconds: Optional[int] = Field(default=None, description="Evaluation window duration in seconds")
    final_score: float = Field(..., description="Final bounded Threat Risk Score (0.0 to 100.0)")
    severity: RiskSeverity = Field(..., description="Severity category: LOW, MEDIUM, HIGH, CRITICAL")
    statistical_contribution: float = Field(default=0.0, description="Statistical component score (0-25)")
    isolation_forest_contribution: float = Field(default=0.0, description="Isolation forest component score (0-25)")
    clustering_contribution: float = Field(default=0.0, description="Behavioral clustering component score (0-20)")
    rules_contribution: float = Field(default=0.0, description="Deterministic rules component score (0-20)")
    correlation_contribution: float = Field(default=0.0, description="Cross-entity correlation component score (0-10)")
    evidence_strength: str = Field(default="LOW", description="Fusion evidence agreement strength")
    contributor_breakdown: ContributorBreakdown = Field(..., description="Detailed per-contributor evidence breakdown")
    explanation: str = Field(..., description="Human-readable security rationale explaining risk drivers")
    source_fusion_id: Optional[str] = Field(default=None, description="Associated fusion evaluation UUID if applicable")
    details: Dict[str, Any] = Field(default_factory=dict, description="Contextual diagnostic metadata")


class RiskEvaluateRequest(BaseModel):
    """Request payload to evaluate platform Threat Risk Score."""
    snapshot_id: Optional[str] = Field(default=None, description="Evaluate detector results linked to this snapshot")
    fusion_id: Optional[str] = Field(default=None, description="Evaluate risk score from an existing FusionResult")
    entity_type: Optional[EntityType] = Field(default=None, description="Entity type: USER, IP, HOST, GLOBAL")
    entity_id: Optional[str] = Field(default=None, description="Entity identifier")
    window_seconds: Optional[int] = Field(default=None, description="Evaluation window in seconds")
    detector_evidence: Optional[List[FusionDetectorEvidence]] = Field(default=None, description="Direct detector evidence items")
    rule_evidence: Optional[List[DeterministicRuleEvidence]] = Field(default=None, description="Direct deterministic rule evidence items")
    correlation_window_seconds: Optional[int] = Field(default=None, description="Correlation window in seconds")
    persist: bool = Field(default=True, description="Whether to persist the risk score in the database")


class RiskActiveEvaluateRequest(BaseModel):
    """Request payload to evaluate recent active entities and snapshots."""
    window_seconds: Optional[int] = Field(default=None, description="Optional window duration filter")
    limit: int = Field(default=20, ge=1, le=100, description="Maximum number of active snapshots to evaluate")
    correlation_window_seconds: Optional[int] = Field(default=None, description="Temporal correlation window in seconds")
