"""Unit tests for Phase 8: Explainable Risk Scoring Service.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Verifies:
- Component contribution calculations & exact blueprint caps
- Normal detector gating (0.0 points when normal)
- Single detector, two-detector, three-detector, and rule scenarios
- Anti-double-counting across multiple statistical features
- Centralized severity function & exact boundary tests (39, 40, 64, 65, 84, 85, 100)
- Score clamping [0.0, 100.0]
- Determinism (reproducibility)
- Contributor breakdown and transparent explanation generation
- Absence of prohibited terminology
- Database persistence via RiskRepository
"""

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.orm import Session

from backend.detection.schemas import (
    DeterministicRuleEvidence,
    EvidenceStrength,
    FusionDetectorEvidence,
    FusionResult,
)
from backend.features.schemas import EntityType
from backend.repositories.risk_repository import RiskRepository
from backend.risk.schemas import RiskSeverity
from backend.risk.service import (
    RiskScoringService,
    determine_risk_severity,
    risk_scoring_service,
)


@pytest.fixture
def base_timestamp() -> datetime:
    return datetime.now(timezone.utc)


def test_severity_boundaries():
    """Verify exact blueprint severity boundary requirements:
    39.0 -> LOW
    40.0 -> MEDIUM
    64.0 -> MEDIUM
    65.0 -> HIGH
    84.0 -> HIGH
    85.0 -> CRITICAL
    100.0 -> CRITICAL
    """
    assert determine_risk_severity(0.0) == RiskSeverity.LOW
    assert determine_risk_severity(39.0) == RiskSeverity.LOW
    assert determine_risk_severity(39.9) == RiskSeverity.LOW
    assert determine_risk_severity(40.0) == RiskSeverity.MEDIUM
    assert determine_risk_severity(64.0) == RiskSeverity.MEDIUM
    assert determine_risk_severity(64.9) == RiskSeverity.MEDIUM
    assert determine_risk_severity(65.0) == RiskSeverity.HIGH
    assert determine_risk_severity(84.0) == RiskSeverity.HIGH
    assert determine_risk_severity(84.9) == RiskSeverity.HIGH
    assert determine_risk_severity(85.0) == RiskSeverity.CRITICAL
    assert determine_risk_severity(100.0) == RiskSeverity.CRITICAL


def test_normal_detectors_contribute_zero(base_timestamp):
    """Detectors reporting normal behavior must contribute 0.0 points regardless of numeric scores."""
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="NORMAL",
            detector_score=0.45,
            is_anomalous=False,
            explanation="Normal baseline",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="alice",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="NORMAL",
            detector_score=38.0,
            is_anomalous=False,
            explanation="Normal tree depth",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="alice",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="NORMAL",
            detector_score=42.0,
            is_anomalous=False,
            explanation="Within normal cluster",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="alice",
        ),
    ]

    res = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.USER,
        entity_id="alice",
    )

    assert res.final_score == 0.0
    assert res.severity == RiskSeverity.LOW
    assert res.statistical_contribution == 0.0
    assert res.isolation_forest_contribution == 0.0
    assert res.clustering_contribution == 0.0
    assert res.rules_contribution == 0.0
    assert res.correlation_contribution == 0.0
    assert res.contributor_breakdown.statistical.evidence in ("NORMAL", "NORMAL")
    assert "0.0/100 (LOW)" in res.explanation


def test_single_detector_contribution(base_timestamp):
    """A single anomalous detector contributes proportionally to its cap with zero correlation bonus."""
    # Isolation Forest: score 90.0 out of 100 -> (90 / 100) * 25 = 22.5 points
    evidences = [
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=90.0,
            is_anomalous=True,
            explanation="Unusual behavioral vector isolated",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="bob",
            details={
                "normalized_anomaly_score": 90.0,
                "raw_decision_score": -0.25,
                "top_feature_deviations": [{"feature_name": "failed_logins", "deviation": 4.5}],
            },
        ),
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="NORMAL",
            detector_score=0.0,
            is_anomalous=False,
            explanation="Normal",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="bob",
        ),
    ]

    res = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.USER,
        entity_id="bob",
    )

    assert res.isolation_forest_contribution == 22.5
    assert res.statistical_contribution == 0.0
    assert res.clustering_contribution == 0.0
    assert res.rules_contribution == 0.0
    assert res.correlation_contribution == 0.0  # 1 anomalous detector -> 0 correlation bonus
    assert res.final_score == 22.5
    assert res.severity == RiskSeverity.LOW
    assert res.contributor_breakdown.isolation_forest.raw_decision_score == -0.25
    assert len(res.contributor_breakdown.isolation_forest.top_feature_deviations) == 1


def test_two_detectors_with_correlation(base_timestamp):
    """Two anomalous detectors trigger independent agreement correlation bonus (5.0 points)."""
    # Statistical: score 0.80 (0-1 scale) -> 80.0 -> (80 / 100) * 25 = 20.0 pts
    # Isolation Forest: score 80.0 -> (80 / 100) * 25 = 20.0 pts
    # Correlation: 2 anomalous detectors -> 5.0 pts
    # Total = 20.0 + 20.0 + 5.0 = 45.0 pts -> MEDIUM severity
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.80,
            is_anomalous=True,
            explanation="High request rate",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="charlie",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=80.0,
            is_anomalous=True,
            explanation="Anomalous sequence",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="charlie",
        ),
    ]

    res = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.USER,
        entity_id="charlie",
    )

    assert res.statistical_contribution == 20.0
    assert res.isolation_forest_contribution == 20.0
    assert res.clustering_contribution == 0.0
    assert res.correlation_contribution == 5.0
    assert res.final_score == 45.0
    assert res.severity == RiskSeverity.MEDIUM
    assert res.evidence_strength == "STRONG"


def test_three_detectors_conclusive(base_timestamp):
    """Three independent anomaly detectors produce strong/conclusive agreement (8.0 pts correlation)."""
    # Statistical: 100% -> 25.0
    # IF: 100% -> 25.0
    # Clustering: 100% -> 20.0
    # Correlation: 3 anomalous -> 8.0
    # Total = 25 + 25 + 20 + 8 = 78.0 -> HIGH severity
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=1.0,
            is_anomalous=True,
            explanation="Extreme z-score",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="david",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=100.0,
            is_anomalous=True,
            explanation="Outlier",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="david",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="ANOMALOUS",
            detector_score=100.0,
            is_anomalous=True,
            explanation="Centroid distance outlier",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="david",
            details={
                "assigned_cluster_id": 2,
                "cluster_distance": 9.4,
                "threshold_distance": 3.1,
                "distance_ratio": 3.03,
            },
        ),
    ]

    res = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.USER,
        entity_id="david",
    )

    assert res.statistical_contribution == 25.0
    assert res.isolation_forest_contribution == 25.0
    assert res.clustering_contribution == 20.0
    assert res.correlation_contribution == 8.0
    assert res.final_score == 78.0
    assert res.severity == RiskSeverity.HIGH
    assert res.evidence_strength == "CONCLUSIVE"
    assert res.contributor_breakdown.behavioral_clustering.assigned_cluster_id == 2


def test_deterministic_rules_aggregation_and_cap(base_timestamp):
    """Multiple deterministic rules aggregate their scores up to the strict 20.0 point cap."""
    rules = [
        DeterministicRuleEvidence(
            rule_id="RULE-001",
            score=12.0,
            is_anomalous=True,
            explanation="Brute force pattern",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="eve",
        ),
        DeterministicRuleEvidence(
            rule_id="RULE-002",
            score=15.0,
            is_anomalous=True,
            explanation="Impossible travel",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="eve",
        ),
        DeterministicRuleEvidence(
            rule_id="RULE-003",
            score=5.0,
            is_anomalous=False,  # Normal rule must NOT contribute points
            explanation="Normal user agent",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="eve",
        ),
    ]

    contrib = risk_scoring_service.calculate_rules_contribution([], rule_evidence=rules)

    # 12.0 + 15.0 = 27.0 -> capped at 20.0
    assert contrib.score == 20.0
    assert contrib.maximum == 20.0
    assert contrib.rule_count == 2
    assert len(contrib.rules) == 2


def test_anti_double_counting_statistical_features(base_timestamp):
    """Multiple anomalous statistical features must collapse into a single statistical family contribution <= 25."""
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.70,
            is_anomalous=True,
            feature_name="feature_a",
            explanation="Feature A elevated",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="frank",
        ),
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.90,
            is_anomalous=True,
            feature_name="feature_b",
            explanation="Feature B elevated",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="frank",
        ),
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.60,
            is_anomalous=True,
            feature_name="feature_c",
            explanation="Feature C elevated",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="frank",
        ),
    ]

    contrib = risk_scoring_service.calculate_statistical_contribution(evidences)

    # Highest score is 0.90 -> (90 / 100) * 25 = 22.5
    # NOT 0.70*25 + 0.90*25 + 0.60*25 = 55.0!
    assert contrib.score == 22.5
    assert contrib.maximum == 25.0
    assert contrib.evaluated_feature_count == 3
    assert contrib.anomalous_feature_count == 3
    assert len(contrib.features) == 3


def test_component_caps_enforced():
    """All components must strictly observe their maximum caps."""
    scorer = RiskScoringService()

    # Statistical cap: 25.0
    stat_ev = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=999.0,  # Extreme score
            is_anomalous=True,
        )
    ]
    assert scorer.calculate_statistical_contribution(stat_ev).score == 25.0

    # Isolation Forest cap: 25.0
    if_ev = [
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=250.0,
            is_anomalous=True,
        )
    ]
    assert scorer.calculate_isolation_forest_contribution(if_ev).score == 25.0

    # Clustering cap: 20.0
    cl_ev = [
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="ANOMALOUS",
            detector_score=300.0,
            is_anomalous=True,
        )
    ]
    assert scorer.calculate_clustering_contribution(cl_ev).score == 20.0

    # Rules cap: 20.0
    rules = [
        DeterministicRuleEvidence(rule_id="R1", score=100.0, is_anomalous=True, explanation="Rule 1"),
        DeterministicRuleEvidence(rule_id="R2", score=100.0, is_anomalous=True, explanation="Rule 2"),
    ]
    assert scorer.calculate_rules_contribution([], rule_evidence=rules).score == 20.0

    # Correlation cap: 10.0
    assert scorer.calculate_correlation_contribution(5, 5, "CONCLUSIVE").score == 10.0


def test_maximum_100_score_clamping(base_timestamp):
    """When all detectors, rules, and correlation hit maximum, final score equals exactly 100.0 and never exceeds."""
    # 25 (Statistical) + 25 (IF) + 20 (Clustering) + 20 (Rules) + 10 (Correlation) = 100.0
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=100.0,
            is_anomalous=True,
            explanation="Stat max",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="grace",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=100.0,
            is_anomalous=True,
            explanation="IF max",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="grace",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="ANOMALOUS",
            detector_score=100.0,
            is_anomalous=True,
            explanation="Clustering max",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="grace",
        ),
    ]

    rules = [
        DeterministicRuleEvidence(
            rule_id="RULE-MAX",
            score=25.0,  # Exceeds 20, should cap at 20
            is_anomalous=True,
            explanation="Critical rule match",
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="grace",
        )
    ]

    res = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        rule_evidence=rules,
        entity_type=EntityType.USER,
        entity_id="grace",
    )

    assert res.statistical_contribution == 25.0
    assert res.isolation_forest_contribution == 25.0
    assert res.clustering_contribution == 20.0
    assert res.rules_contribution == 20.0
    assert res.correlation_contribution == 10.0  # 4 anomalous detectors (3 + rule) -> 10.0
    assert res.final_score == 100.0
    assert res.severity == RiskSeverity.CRITICAL


def test_determinism(base_timestamp):
    """Identical evidence input must produce identical score, severity, and breakdown every time."""
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.92,
            is_anomalous=True,
            timestamp=base_timestamp,
            entity_type=EntityType.IP,
            entity_id="192.168.1.50",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=85.0,
            is_anomalous=True,
            timestamp=base_timestamp,
            entity_type=EntityType.IP,
            entity_id="192.168.1.50",
        ),
    ]

    res1 = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.IP,
        entity_id="192.168.1.50",
    )

    res2 = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.IP,
        entity_id="192.168.1.50",
    )

    assert res1.final_score == res2.final_score
    assert res1.severity == res2.severity
    assert res1.statistical_contribution == res2.statistical_contribution
    assert res1.isolation_forest_contribution == res2.isolation_forest_contribution
    assert res1.correlation_contribution == res2.correlation_contribution
    assert res1.explanation == res2.explanation


def test_prohibited_terminology_absence(base_timestamp):
    """Verify that explanations do NOT contain prohibited terms:
    - 'AI reasoning'
    - 'model confidence'
    - 'probability'
    - 'probability of compromise'
    """
    evidences = [
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=95.0,
            is_anomalous=True,
            timestamp=base_timestamp,
            entity_type=EntityType.USER,
            entity_id="heidi",
        ),
    ]

    res = risk_scoring_service.evaluate_evidence(
        evidence_list=evidences,
        entity_type=EntityType.USER,
        entity_id="heidi",
    )

    explanation_lower = res.explanation.lower()
    prohibited_terms = [
        "probability",
        "model confidence",
        "ai reasoning",
        "probability of compromise",
        "probability of attack",
    ]
    for term in prohibited_terms:
        assert term not in explanation_lower, f"Prohibited term '{term}' found in explanation"


def test_repository_persistence(base_timestamp):
    """Verify Threat Risk Score persistence and querying via RiskRepository."""
    from backend.db.session import SessionLocal

    db = SessionLocal()
    try:
        repo = RiskRepository(db)

        evidences = [
            FusionDetectorEvidence(
                detector_type="ISOLATION_FOREST",
                detector_status="ANOMALOUS",
                detector_score=80.0,
                is_anomalous=True,
                explanation="Unusual behavior",
                timestamp=base_timestamp,
                entity_type=EntityType.USER,
                entity_id="ivan",
            )
        ]

        score_result = risk_scoring_service.evaluate_evidence(
            evidence_list=evidences,
            entity_type=EntityType.USER,
            entity_id="ivan",
            db=db,
            persist=True,
        )

        # Lookup by risk_id
        saved = repo.get_by_risk_id(score_result.risk_id)
        assert saved is not None
        assert saved.entity_id == "ivan"
        assert saved.severity == score_result.severity.value
        assert saved.final_score == score_result.final_score

        # Lookup latest for entity
        latest = repo.get_by_entity("ivan")
        assert latest is not None
        assert latest.risk_id == score_result.risk_id

        # Lookup history
        history = repo.get_entity_history("ivan")
        assert len(history) >= 1
        assert history[0].risk_id == score_result.risk_id

        # Schema conversion round-trip
        schema_obj = saved.to_schema()
        assert schema_obj.risk_id == score_result.risk_id
        assert schema_obj.final_score == score_result.final_score
        assert schema_obj.contributor_breakdown.isolation_forest.score == score_result.isolation_forest_contribution
    finally:
        db.close()
