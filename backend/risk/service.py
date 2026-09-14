"""Explainable Risk Scoring Service for Sh4d0w_St4lk3r.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Converts independent detection evidence and anomaly fusion evaluations into a
bounded, transparent 0–100 Threat Risk Score with full contributor breakdown,
severity classification, and clear analyst security explanations.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.orm import Session

from backend.config import settings
from backend.detection.fusion_service import (
    DETECTOR_CLUSTERING,
    DETECTOR_DETERMINISTIC_RULE,
    DETECTOR_ISOLATION_FOREST,
    DETECTOR_STATISTICAL,
    anomaly_fusion_service,
    canonical_detector_type,
)
from backend.detection.schemas import (
    DeterministicRuleEvidence,
    FusionDetectorEvidence,
    FusionResult,
)
from backend.features.schemas import EntityType
from backend.models.fusion import FusionResultDB
from backend.repositories.fusion_repository import FusionRepository
from backend.repositories.risk_repository import RiskRepository
from backend.risk.schemas import (
    ClusteringContributor,
    ContributorBreakdown,
    CorrelationContributor,
    DeterministicRulesContributor,
    IsolationForestContributor,
    RiskScoreResult,
    RiskSeverity,
    StatisticalContributor,
)

logger = logging.getLogger(__name__)


def determine_risk_severity(score: float) -> RiskSeverity:
    """Classify Threat Risk Score into blueprint severity categories.

    Thresholds:
    - LOW:      0.0  to 39.0 (score < 40.0)
    - MEDIUM:   40.0 to 64.0 (40.0 <= score < 65.0)
    - HIGH:     65.0 to 84.0 (65.0 <= score < 85.0)
    - CRITICAL: 85.0 to 100.0 (score >= 85.0)
    """
    if score >= 85.0:
        return RiskSeverity.CRITICAL
    elif score >= 65.0:
        return RiskSeverity.HIGH
    elif score >= 40.0:
        return RiskSeverity.MEDIUM
    else:
        return RiskSeverity.LOW


def format_risk_explanation(
    final_score: float,
    severity: RiskSeverity,
    contributor_breakdown: ContributorBreakdown,
) -> str:
    """Generate human-readable security explanation detailing risk drivers."""
    if final_score <= 0.0:
        return (
            "Threat Risk Score 0.0/100 (LOW). All evaluated detection methods report "
            "normal behavior with no anomalous evidence."
        )

    drivers: List[str] = []
    cb = contributor_breakdown

    if cb.statistical.score > 0:
        drivers.append(f"statistical baseline deviation ({cb.statistical.score:.1f} pts)")
    if cb.isolation_forest.score > 0:
        drivers.append(f"Isolation Forest behavioral anomaly ({cb.isolation_forest.score:.1f} pts)")
    if cb.behavioral_clustering.score > 0:
        drivers.append(f"behavioral clustering deviation ({cb.behavioral_clustering.score:.1f} pts)")
    if cb.deterministic_rules.score > 0:
        drivers.append(f"deterministic rule matches ({cb.deterministic_rules.score:.1f} pts)")
    if cb.cross_entity_correlation.score > 0:
        drivers.append(f"independent detector correlation agreement ({cb.cross_entity_correlation.score:.1f} pts)")

    if drivers:
        drivers_text = ", ".join(drivers)
        return (
            f"Threat Risk Score {final_score:.1f}/100 ({severity.value}). "
            f"Risk is driven by {drivers_text}."
        )
    else:
        return f"Threat Risk Score {final_score:.1f}/100 ({severity.value}). Baseline normal behavior."


class RiskScoringService:
    """Reusable service for calculating transparent platform-level Threat Risk Scores."""

    def __init__(
        self,
        statistical_max: Optional[float] = None,
        isolation_forest_max: Optional[float] = None,
        clustering_max: Optional[float] = None,
        rules_max: Optional[float] = None,
        correlation_max: Optional[float] = None,
        correlation_map: Optional[Dict[int, float]] = None,
    ):
        self.statistical_max = (
            statistical_max
            if statistical_max is not None
            else getattr(settings, "RISK_STATISTICAL_MAX", 25.0)
        )
        self.isolation_forest_max = (
            isolation_forest_max
            if isolation_forest_max is not None
            else getattr(settings, "RISK_ISOLATION_FOREST_MAX", 25.0)
        )
        self.clustering_max = (
            clustering_max
            if clustering_max is not None
            else getattr(settings, "RISK_CLUSTERING_MAX", 20.0)
        )
        self.rules_max = (
            rules_max
            if rules_max is not None
            else getattr(settings, "RISK_RULES_MAX", 20.0)
        )
        self.correlation_max = (
            correlation_max
            if correlation_max is not None
            else getattr(settings, "RISK_CORRELATION_MAX", 10.0)
        )
        self.correlation_map = (
            correlation_map
            if correlation_map is not None
            else getattr(settings, "RISK_CORRELATION_MAP", {0: 0.0, 1: 0.0, 2: 5.0, 3: 8.0, 4: 10.0})
        )

    def calculate_statistical_contribution(
        self, evidences: List[FusionDetectorEvidence]
    ) -> StatisticalContributor:
        """Calculate statistical component without double-counting multiple features.

        Max contribution: 25.0 points.
        Normal evidence produces 0.0 points.
        """
        stat_evs = [
            ev for ev in evidences
            if canonical_detector_type(ev.detector_type) == DETECTOR_STATISTICAL
        ]

        if not stat_evs:
            return StatisticalContributor(
                score=0.0,
                maximum=self.statistical_max,
                evidence="NORMAL",
                evaluated_feature_count=0,
                anomalous_feature_count=0,
                features=[],
                explanation="No statistical baseline evidence available.",
            )

        anomalous_stat_evs = [ev for ev in stat_evs if ev.is_anomalous]
        feature_details: List[Dict[str, Any]] = [
            {
                "feature_name": ev.feature_name,
                "score": ev.detector_score,
                "is_anomalous": ev.is_anomalous,
                "status": ev.detector_status,
                "explanation": ev.explanation,
                "details": ev.details,
            }
            for ev in stat_evs
        ]

        if not anomalous_stat_evs:
            # Check if cold start / abstain
            any_abstain = any(ev.detector_status == "ABSTAIN" for ev in stat_evs)
            ev_status = "ABSTAIN" if any_abstain else "NORMAL"
            return StatisticalContributor(
                score=0.0,
                maximum=self.statistical_max,
                evidence=ev_status,
                evaluated_feature_count=len(stat_evs),
                anomalous_feature_count=0,
                features=feature_details,
                explanation=f"All {len(stat_evs)} statistical feature(s) within normal baseline bounds.",
            )

        # Multiple statistical features: take peak anomaly severity to prevent double counting
        peak_score = 0.0
        for ev in anomalous_stat_evs:
            raw_score = float(ev.detector_score)
            if 0.0 < raw_score <= 1.0:
                norm_score = raw_score * 100.0
            else:
                norm_score = min(100.0, max(0.0, raw_score))
            if norm_score > peak_score:
                peak_score = norm_score

        pts = (peak_score / 100.0) * self.statistical_max
        pts = round(min(self.statistical_max, max(0.0, pts)), 1)

        expl = (
            f"Statistical deviation detected across {len(anomalous_stat_evs)} of "
            f"{len(stat_evs)} evaluated feature(s) (peak normalized severity: {peak_score:.1f}/100)."
        )

        return StatisticalContributor(
            score=pts,
            maximum=self.statistical_max,
            evidence="ANOMALOUS",
            evaluated_feature_count=len(stat_evs),
            anomalous_feature_count=len(anomalous_stat_evs),
            features=feature_details,
            explanation=expl,
        )

    def calculate_isolation_forest_contribution(
        self, evidences: List[FusionDetectorEvidence]
    ) -> IsolationForestContributor:
        """Calculate Isolation Forest component.

        Max contribution: 25.0 points.
        Normal evidence produces 0.0 points.
        """
        if_evs = [
            ev for ev in evidences
            if canonical_detector_type(ev.detector_type) == DETECTOR_ISOLATION_FOREST
        ]

        if not if_evs:
            return IsolationForestContributor(
                score=0.0,
                maximum=self.isolation_forest_max,
                evidence="NORMAL",
                explanation="No Isolation Forest evidence available.",
            )

        # Primary IF evidence
        primary = if_evs[0]
        details = primary.details or {}
        raw_score = details.get("raw_decision_score")
        top_devs = details.get("top_feature_deviations", [])

        if not primary.is_anomalous:
            return IsolationForestContributor(
                score=0.0,
                maximum=self.isolation_forest_max,
                evidence="NORMAL",
                raw_decision_score=raw_score,
                normalized_anomaly_score=float(primary.detector_score),
                explanation=primary.explanation or "Isolation Forest indicates normal behavioral distribution.",
                top_feature_deviations=top_devs,
            )

        norm_score = float(details.get("normalized_anomaly_score", primary.detector_score))
        norm_score = min(100.0, max(0.0, norm_score))

        pts = (norm_score / 100.0) * self.isolation_forest_max
        pts = round(min(self.isolation_forest_max, max(0.0, pts)), 1)

        return IsolationForestContributor(
            score=pts,
            maximum=self.isolation_forest_max,
            evidence="ANOMALOUS",
            raw_decision_score=raw_score,
            normalized_anomaly_score=norm_score,
            explanation=primary.explanation or "Isolation Forest detected anomalous behavioral vector.",
            top_feature_deviations=top_devs,
        )

    def calculate_clustering_contribution(
        self, evidences: List[FusionDetectorEvidence]
    ) -> ClusteringContributor:
        """Calculate Behavioral Clustering component.

        Max contribution: 20.0 points.
        Normal evidence produces 0.0 points.
        """
        cl_evs = [
            ev for ev in evidences
            if canonical_detector_type(ev.detector_type) == DETECTOR_CLUSTERING
        ]

        if not cl_evs:
            return ClusteringContributor(
                score=0.0,
                maximum=self.clustering_max,
                evidence="NORMAL",
                explanation="No Behavioral Clustering evidence available.",
            )

        primary = cl_evs[0]
        details = primary.details or {}
        cluster_id = details.get("assigned_cluster_id")
        cluster_dist = details.get("cluster_distance")
        thresh_dist = details.get("threshold_distance")
        dist_ratio = details.get("distance_ratio")
        top_devs = details.get("top_feature_deviations", [])
        cluster_chars = details.get("cluster_characteristics", [])
        pca_coords = details.get("pca_coordinates")

        if not primary.is_anomalous:
            return ClusteringContributor(
                score=0.0,
                maximum=self.clustering_max,
                evidence="NORMAL",
                assigned_cluster_id=cluster_id,
                cluster_distance=cluster_dist,
                threshold_distance=thresh_dist,
                distance_ratio=dist_ratio,
                explanation=primary.explanation or "Behavioral clustering indicates normal cluster membership.",
                top_feature_deviations=top_devs,
                cluster_characteristics=cluster_chars,
                pca_coordinates=pca_coords,
            )

        norm_score = float(details.get("normalized_anomaly_score", primary.detector_score))
        norm_score = min(100.0, max(0.0, norm_score))

        pts = (norm_score / 100.0) * self.clustering_max
        pts = round(min(self.clustering_max, max(0.0, pts)), 1)

        return ClusteringContributor(
            score=pts,
            maximum=self.clustering_max,
            evidence="ANOMALOUS",
            assigned_cluster_id=cluster_id,
            cluster_distance=cluster_dist,
            threshold_distance=thresh_dist,
            distance_ratio=dist_ratio,
            explanation=primary.explanation or "Behavioral clustering detected significant centroid distance deviation.",
            top_feature_deviations=top_devs,
            cluster_characteristics=cluster_chars,
            pca_coordinates=pca_coords,
        )

    def calculate_rules_contribution(
        self,
        evidences: List[FusionDetectorEvidence],
        rule_evidence: Optional[List[DeterministicRuleEvidence]] = None,
    ) -> DeterministicRulesContributor:
        """Calculate Deterministic Rules component.

        Max contribution: 20.0 points.
        Supports multiple rules while strictly capping the total at 20 points.
        Normal rules produce 0.0 points.
        """
        all_rules: List[Dict[str, Any]] = []

        # Process direct rule evidence objects
        if rule_evidence:
            for r in rule_evidence:
                all_rules.append({
                    "rule_id": r.rule_id,
                    "score": float(r.score),
                    "is_anomalous": r.is_anomalous,
                    "explanation": r.explanation,
                    "details": r.details,
                })

        # Process rule evidence in FusionDetectorEvidence list
        for ev in evidences:
            if canonical_detector_type(ev.detector_type) == DETECTOR_DETERMINISTIC_RULE:
                rule_id = ev.rule_id or ev.source_result_id or "RULE-UNKNOWN"
                # Avoid duplicate rules if already added
                if not any(item["rule_id"] == rule_id for item in all_rules):
                    all_rules.append({
                        "rule_id": rule_id,
                        "score": float(ev.detector_score),
                        "is_anomalous": ev.is_anomalous,
                        "explanation": ev.explanation,
                        "details": ev.details,
                    })

        anomalous_rules = [r for r in all_rules if r["is_anomalous"]]

        if not anomalous_rules:
            return DeterministicRulesContributor(
                score=0.0,
                maximum=self.rules_max,
                rule_count=len(all_rules),
                rules=all_rules,
                explanation="No deterministic rule matches triggered.",
            )

        total_pts = sum(float(r["score"]) for r in anomalous_rules)
        total_pts = round(min(self.rules_max, max(0.0, total_pts)), 1)
        expl = f"{len(anomalous_rules)} deterministic security rule(s) triggered."

        return DeterministicRulesContributor(
            score=total_pts,
            maximum=self.rules_max,
            rule_count=len(anomalous_rules),
            rules=anomalous_rules,
            explanation=expl,
        )

    def calculate_correlation_contribution(
        self,
        anomalous_detector_count: int,
        independent_detector_count: int,
        evidence_strength: str,
    ) -> CorrelationContributor:
        """Calculate independent detector agreement correlation bonus.

        Max contribution: 10.0 points.
        Transparent mapping:
        - 0 anomalous: 0.0 pts
        - 1 anomalous: 0.0 pts
        - 2 anomalous: 5.0 pts
        - 3 anomalous: 8.0 pts
        - 4+ anomalous: 10.0 pts
        """
        if anomalous_detector_count in self.correlation_map:
            score = self.correlation_map[anomalous_detector_count]
        elif anomalous_detector_count >= 4:
            score = self.correlation_max
        else:
            score = 0.0

        score = round(min(self.correlation_max, max(0.0, score)), 1)

        if anomalous_detector_count >= 3:
            expl = (
                f"Conclusive multi-detector correlation: {anomalous_detector_count} "
                f"independent detection methods concurrently identified anomalous behavior."
            )
        elif anomalous_detector_count == 2:
            expl = (
                f"Strong multi-detector correlation: 2 independent detection methods "
                f"concurrently identified anomalous behavior."
            )
        elif anomalous_detector_count == 1:
            expl = (
                "Single detector flagged anomalous behavior; no multi-detector correlation bonus applied."
            )
        else:
            expl = "No anomalous detectors identified; correlation contribution is zero."

        return CorrelationContributor(
            score=score,
            maximum=self.correlation_max,
            evidence_strength=evidence_strength,
            anomalous_detector_count=anomalous_detector_count,
            independent_detector_count=independent_detector_count,
            explanation=expl,
        )

    def score_from_fusion_result(
        self,
        fusion_result: FusionResult,
        rule_evidence: Optional[List[DeterministicRuleEvidence]] = None,
        persist: bool = False,
        db: Optional[Session] = None,
    ) -> RiskScoreResult:
        """Compute platform Threat Risk Score from a Phase 7 FusionResult."""
        evidences = fusion_result.detector_results

        # 1. Component contributions
        stat_contrib = self.calculate_statistical_contribution(evidences)
        if_contrib = self.calculate_isolation_forest_contribution(evidences)
        cl_contrib = self.calculate_clustering_contribution(evidences)
        rules_contrib = self.calculate_rules_contribution(evidences, rule_evidence=rule_evidence)
        corr_contrib = self.calculate_correlation_contribution(
            anomalous_detector_count=fusion_result.anomalous_detector_count,
            independent_detector_count=fusion_result.independent_detector_count,
            evidence_strength=str(
                fusion_result.evidence_strength.value
                if hasattr(fusion_result.evidence_strength, "value")
                else fusion_result.evidence_strength
            ),
        )

        # 2. Composite score calculation with strict clamping
        raw_final = (
            stat_contrib.score
            + if_contrib.score
            + cl_contrib.score
            + rules_contrib.score
            + corr_contrib.score
        )
        final_score = round(min(100.0, max(0.0, raw_final)), 1)

        # 3. Centralized severity categorization
        severity = determine_risk_severity(final_score)

        # 4. Contributor breakdown
        breakdown = ContributorBreakdown(
            statistical=stat_contrib,
            isolation_forest=if_contrib,
            behavioral_clustering=cl_contrib,
            deterministic_rules=rules_contrib,
            cross_entity_correlation=corr_contrib,
            final_score=final_score,
            severity=severity,
        )

        # 5. Explainable security rationale
        explanation = format_risk_explanation(final_score, severity, breakdown)

        evidence_strength_str = str(
            fusion_result.evidence_strength.value
            if hasattr(fusion_result.evidence_strength, "value")
            else fusion_result.evidence_strength
        )

        risk_result = RiskScoreResult(
            risk_id=str(uuid.uuid4()),
            timestamp=fusion_result.timestamp or datetime.now(timezone.utc),
            entity_type=fusion_result.entity_type,
            entity_id=fusion_result.entity_id,
            snapshot_id=fusion_result.snapshot_id,
            window_seconds=fusion_result.window_seconds,
            final_score=final_score,
            severity=severity,
            statistical_contribution=stat_contrib.score,
            isolation_forest_contribution=if_contrib.score,
            clustering_contribution=cl_contrib.score,
            rules_contribution=rules_contrib.score,
            correlation_contribution=corr_contrib.score,
            evidence_strength=evidence_strength_str,
            contributor_breakdown=breakdown,
            explanation=explanation,
            source_fusion_id=fusion_result.fusion_id,
            details={
                "anomalous_detector_count": fusion_result.anomalous_detector_count,
                "independent_detector_count": fusion_result.independent_detector_count,
                "contributing_detectors": fusion_result.contributing_detectors,
                "correlation_window_seconds": fusion_result.correlation_window_seconds,
            },
        )

        if persist and db is not None:
            repo = RiskRepository(db)
            repo.create_score(risk_result)

        return risk_result

    def evaluate_evidence(
        self,
        evidence_list: List[FusionDetectorEvidence],
        rule_evidence: Optional[List[DeterministicRuleEvidence]] = None,
        entity_type: Optional[EntityType] = None,
        entity_id: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        window_seconds: Optional[int] = None,
        correlation_window_seconds: Optional[int] = None,
        reference_time: Optional[datetime] = None,
        db: Optional[Session] = None,
        persist: bool = False,
    ) -> RiskScoreResult:
        """Run Phase 7 fusion on evidence and produce a Threat Risk Score."""
        fusion_res = anomaly_fusion_service.evaluate_evidence(
            evidence_list=evidence_list,
            rule_evidence=rule_evidence,
            entity_type=entity_type,
            entity_id=entity_id,
            snapshot_id=snapshot_id,
            window_seconds=window_seconds,
            correlation_window_seconds=correlation_window_seconds,
            reference_time=reference_time,
            db=db,
            persist=persist,
        )

        return self.score_from_fusion_result(
            fusion_result=fusion_res,
            rule_evidence=rule_evidence,
            persist=persist,
            db=db,
        )

    def evaluate_snapshot(
        self,
        db: Session,
        snapshot_id: str,
        rule_evidence: Optional[List[DeterministicRuleEvidence]] = None,
        correlation_window_seconds: Optional[int] = None,
        persist: bool = True,
    ) -> RiskScoreResult:
        """Evaluate Threat Risk Score for a feature snapshot using persisted detector results."""
        fusion_res = anomaly_fusion_service.evaluate_snapshot(
            db=db,
            snapshot_id=snapshot_id,
            rule_evidence=rule_evidence,
            correlation_window_seconds=correlation_window_seconds,
            persist=persist,
        )

        return self.score_from_fusion_result(
            fusion_result=fusion_res,
            rule_evidence=rule_evidence,
            persist=persist,
            db=db,
        )

    def evaluate_fusion_by_id(
        self,
        db: Session,
        fusion_id: str,
        persist: bool = True,
    ) -> RiskScoreResult:
        """Evaluate Threat Risk Score directly from an existing FusionResult in database."""
        fusion_repo = FusionRepository(db)
        fusion_db = fusion_repo.get_by_fusion_id(fusion_id)
        if not fusion_db:
            raise ValueError(f"FusionResult with ID '{fusion_id}' not found.")

        fusion_schema = fusion_db.to_schema()
        return self.score_from_fusion_result(
            fusion_result=fusion_schema,
            persist=persist,
            db=db,
        )

    def evaluate_active(
        self,
        db: Session,
        window_seconds: Optional[int] = None,
        limit: int = 20,
        correlation_window_seconds: Optional[int] = None,
    ) -> List[RiskScoreResult]:
        """Batch evaluate Threat Risk Scores across recent active snapshots."""
        fusion_results = anomaly_fusion_service.evaluate_active(
            db=db,
            window_seconds=window_seconds,
            limit=limit,
            correlation_window_seconds=correlation_window_seconds,
        )

        risk_results: List[RiskScoreResult] = []
        for fres in fusion_results:
            try:
                res = self.score_from_fusion_result(
                    fusion_result=fres,
                    persist=True,
                    db=db,
                )
                risk_results.append(res)
            except Exception as e:
                logger.error("Failed to evaluate risk score for snapshot %s: %s", fres.snapshot_id, e)

        return risk_results


# Global singleton instance
risk_scoring_service = RiskScoringService()
