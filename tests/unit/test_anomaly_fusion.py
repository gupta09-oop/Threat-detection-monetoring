"""Unit tests for Anomaly Fusion engine and evidence correlation.

Tests:
- Independent detector evidence modeling
- Evidence strength mapping: LOW, MODERATE, STRONG, CONCLUSIVE
- Partial detector agreement scenarios
- Missing detector handling (no fabrication, transparent explanation)
- Temporal correlation window filtering
- Entity mismatch handling
- Extensible deterministic rule interface
- Feature aggregation under canonical detector family
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.detection.fusion_service import (
    AnomalyFusionService,
    canonical_detector_type,
    determine_evidence_strength,
)
from backend.detection.schemas import (
    DeterministicRuleEvidence,
    EvidenceStrength,
    FusionDetectorEvidence,
)
from backend.features.schemas import EntityType


@pytest.fixture
def fusion_service() -> AnomalyFusionService:
    return AnomalyFusionService(default_correlation_window_seconds=300)


def test_canonical_detector_type_normalization():
    """Verify detector aliases normalize to canonical detector families."""
    assert canonical_detector_type("STATISTICAL_ZSCORE") == "STATISTICAL_BASELINE"
    assert canonical_detector_type("STATISTICAL_BASELINE") == "STATISTICAL_BASELINE"
    assert canonical_detector_type("STATISTICAL") == "STATISTICAL_BASELINE"
    assert canonical_detector_type("ISOLATION_FOREST") == "ISOLATION_FOREST"
    assert canonical_detector_type("IF") == "ISOLATION_FOREST"
    assert canonical_detector_type("BEHAVIORAL_CLUSTERING") == "BEHAVIORAL_CLUSTERING"
    assert canonical_detector_type("CLUSTERING") == "BEHAVIORAL_CLUSTERING"
    assert canonical_detector_type("DETERMINISTIC_RULE") == "DETERMINISTIC_RULE"
    assert canonical_detector_type("RULE") == "DETERMINISTIC_RULE"


def test_evidence_strength_mapping():
    """Verify transparent deterministic mapping of anomalous detector count to strength."""
    assert determine_evidence_strength(0) == EvidenceStrength.LOW
    assert determine_evidence_strength(1) == EvidenceStrength.MODERATE
    assert determine_evidence_strength(2) == EvidenceStrength.STRONG
    assert determine_evidence_strength(3) == EvidenceStrength.CONCLUSIVE
    assert determine_evidence_strength(4) == EvidenceStrength.CONCLUSIVE


def test_zero_anomalous_detectors_all_normal(fusion_service: AnomalyFusionService):
    """Test scenario where all 3 detectors evaluate behavior as normal."""
    now = datetime.now(timezone.utc)
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="NORMAL",
            detector_score=0.12,
            is_anomalous=False,
            explanation="Within normal statistical baseline",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="alice",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="NORMAL",
            detector_score=15.0,
            is_anomalous=False,
            explanation="Normal behavioral vector",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="alice",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="NORMAL",
            detector_score=22.5,
            is_anomalous=False,
            explanation="Assigned to normal cluster",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="alice",
        ),
    ]

    result = fusion_service.evaluate_evidence(evidences)

    assert result.independent_detector_count == 3
    assert result.anomalous_detector_count == 0
    assert result.evidence_strength == EvidenceStrength.LOW
    assert result.contributing_detectors == []
    assert len(result.detector_results) == 3
    assert "reported normal behavior" in result.fusion_explanation


def test_single_anomalous_detector_moderate_strength(fusion_service: AnomalyFusionService):
    """Test scenario where exactly 1 detector detects an anomaly."""
    now = datetime.now(timezone.utc)
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.95,
            is_anomalous=True,
            explanation="Z-score exceeded threshold (z=3.8)",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="bob",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="NORMAL",
            detector_score=20.0,
            is_anomalous=False,
            explanation="Normal isolation score",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="bob",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="NORMAL",
            detector_score=25.0,
            is_anomalous=False,
            explanation="Within normal cluster distance",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="bob",
        ),
    ]

    result = fusion_service.evaluate_evidence(evidences)

    assert result.independent_detector_count == 3
    assert result.anomalous_detector_count == 1
    assert result.evidence_strength == EvidenceStrength.MODERATE
    assert result.contributing_detectors == ["STATISTICAL_BASELINE"]
    assert "One independent detection method identified anomalous behavior" in result.fusion_explanation


def test_two_anomalous_detectors_strong_evidence(fusion_service: AnomalyFusionService):
    """Test scenario with partial agreement (2 detectors agree on anomaly)."""
    now = datetime.now(timezone.utc)
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="NORMAL",
            detector_score=0.2,
            is_anomalous=False,
            explanation="Normal z-scores",
            timestamp=now,
            entity_type=EntityType.IP,
            entity_id="192.168.1.50",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=88.5,
            is_anomalous=True,
            explanation="Isolated early in tree ensemble",
            timestamp=now,
            entity_type=EntityType.IP,
            entity_id="192.168.1.50",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="ANOMALOUS",
            detector_score=85.0,
            is_anomalous=True,
            explanation="Exceeded 95th percentile cluster distance",
            timestamp=now,
            entity_type=EntityType.IP,
            entity_id="192.168.1.50",
        ),
    ]

    result = fusion_service.evaluate_evidence(evidences)

    assert result.independent_detector_count == 3
    assert result.anomalous_detector_count == 2
    assert result.evidence_strength == EvidenceStrength.STRONG
    assert set(result.contributing_detectors) == {"BEHAVIORAL_CLUSTERING", "ISOLATION_FOREST"}
    assert "Two independent detection methods identified anomalous behavior" in result.fusion_explanation


def test_three_anomalous_detectors_conclusive_evidence(fusion_service: AnomalyFusionService):
    """Test scenario where all 3 independent detectors agree on anomaly."""
    now = datetime.now(timezone.utc)
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.9,
            is_anomalous=True,
            explanation="Excessive failed login deviation",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="admin",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=94.0,
            is_anomalous=True,
            explanation="Highly isolated behavioral feature vector",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="admin",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="ANOMALOUS",
            detector_score=91.5,
            is_anomalous=True,
            explanation="Far from learned normal cluster centroids",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="admin",
        ),
    ]

    result = fusion_service.evaluate_evidence(evidences)

    assert result.independent_detector_count == 3
    assert result.anomalous_detector_count == 3
    assert result.evidence_strength == EvidenceStrength.CONCLUSIVE
    assert set(result.contributing_detectors) == {
        "BEHAVIORAL_CLUSTERING",
        "ISOLATION_FOREST",
        "STATISTICAL_BASELINE",
    }
    assert "Three independent detection methods identified anomalous behavior" in result.fusion_explanation


def test_missing_detector_handling_non_fabrication(fusion_service: AnomalyFusionService):
    """Verify that missing detector results are not treated as normal and not fabricated."""
    now = datetime.now(timezone.utc)
    # Only Statistical detector is available
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.88,
            is_anomalous=True,
            explanation="High connection count anomaly",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="charlie",
        ),
    ]

    result = fusion_service.evaluate_evidence(evidences)

    assert result.independent_detector_count == 1
    assert result.anomalous_detector_count == 1
    assert result.evidence_strength == EvidenceStrength.MODERATE
    assert result.contributing_detectors == ["STATISTICAL_BASELINE"]
    # Transparent note about missing detectors
    assert "Fusion based on 1 available detector evidence source" in result.fusion_explanation
    assert "ISOLATION_FOREST" in result.fusion_explanation
    assert "BEHAVIORAL_CLUSTERING" in result.fusion_explanation


def test_deterministic_rule_evidence_interface(fusion_service: AnomalyFusionService):
    """Verify extensible deterministic rule evidence can be integrated without hardcoding rules."""
    now = datetime.now(timezone.utc)
    evidences = [
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=91.0,
            is_anomalous=True,
            explanation="Outlier vector",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="dave",
        ),
        FusionDetectorEvidence(
            detector_type="BEHAVIORAL_CLUSTERING",
            detector_status="ANOMALOUS",
            detector_score=87.0,
            is_anomalous=True,
            explanation="Unusual cluster distance",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="dave",
        ),
    ]

    rules = [
        DeterministicRuleEvidence(
            rule_id="RULE-AUTH-DIST-001",
            is_anomalous=True,
            score=15.0,
            explanation="Distributed brute-force signature detected across 10+ source IPs",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="dave",
        )
    ]

    result = fusion_service.evaluate_evidence(evidences, rule_evidence=rules)

    # 3 independent detectors: ISOLATION_FOREST, BEHAVIORAL_CLUSTERING, DETERMINISTIC_RULE
    assert result.independent_detector_count == 3
    assert result.anomalous_detector_count == 3
    assert result.evidence_strength == EvidenceStrength.CONCLUSIVE
    assert "DETERMINISTIC_RULE" in result.contributing_detectors
    # Rule evidence retained in results list
    rule_results = [r for r in result.detector_results if r.detector_type == "DETERMINISTIC_RULE"]
    assert len(rule_results) == 1
    assert rule_results[0].rule_id == "RULE-AUTH-DIST-001"


def test_multiple_features_aggregated_into_single_statistical_detector(fusion_service: AnomalyFusionService):
    """Verify that multiple statistical feature deviations for one snapshot count as ONE detector method."""
    now = datetime.now(timezone.utc)
    evidences = [
        # Feature 1: normal
        FusionDetectorEvidence(
            detector_type="STATISTICAL_ZSCORE",
            detector_status="NORMAL",
            detector_score=0.1,
            is_anomalous=False,
            explanation="Failed logins normal",
            feature_name="failed_login_count",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="eve",
        ),
        # Feature 2: anomalous
        FusionDetectorEvidence(
            detector_type="STATISTICAL_ZSCORE",
            detector_status="ANOMALOUS",
            detector_score=0.9,
            is_anomalous=True,
            explanation="Port diversity z=4.2",
            feature_name="unique_destination_ports",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="eve",
        ),
        # Feature 3: anomalous
        FusionDetectorEvidence(
            detector_type="STATISTICAL_ZSCORE",
            detector_status="ANOMALOUS",
            detector_score=0.85,
            is_anomalous=True,
            explanation="Connection failure rate z=3.6",
            feature_name="connection_failure_rate",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="eve",
        ),
    ]

    result = fusion_service.evaluate_evidence(evidences)

    # All 3 features map to canonical STATISTICAL_BASELINE -> 1 independent detector
    assert result.independent_detector_count == 1
    assert result.anomalous_detector_count == 1
    assert result.evidence_strength == EvidenceStrength.MODERATE
    assert result.contributing_detectors == ["STATISTICAL_BASELINE"]
    # All 3 feature results preserved in detector_results
    assert len(result.detector_results) == 3


def test_temporal_correlation_window_filters_outdated_evidence(fusion_service: AnomalyFusionService):
    """Verify that evidence outside the correlation window is excluded."""
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(minutes=15)  # 15 mins ago, window is 5 mins

    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.9,
            is_anomalous=True,
            explanation="Recent statistical anomaly",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="frank",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=85.0,
            is_anomalous=True,
            explanation="Outdated isolation anomaly from 15 minutes ago",
            timestamp=old_time,
            entity_type=EntityType.USER,
            entity_id="frank",
        ),
    ]

    result = fusion_service.evaluate_evidence(
        evidences,
        reference_time=now,
        correlation_window_seconds=300,
    )

    # Old evidence was excluded
    assert result.independent_detector_count == 1
    assert result.anomalous_detector_count == 1
    assert result.contributing_detectors == ["STATISTICAL_BASELINE"]
    assert len(result.detector_results) == 1


def test_entity_mismatch_excluded(fusion_service: AnomalyFusionService):
    """Verify that evidence for a different entity is not mixed into the target fusion."""
    now = datetime.now(timezone.utc)
    evidences = [
        FusionDetectorEvidence(
            detector_type="STATISTICAL_BASELINE",
            detector_status="ANOMALOUS",
            detector_score=0.9,
            is_anomalous=True,
            explanation="Anomaly for target user",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="target_user",
        ),
        FusionDetectorEvidence(
            detector_type="ISOLATION_FOREST",
            detector_status="ANOMALOUS",
            detector_score=90.0,
            is_anomalous=True,
            explanation="Anomaly for unrelated user",
            timestamp=now,
            entity_type=EntityType.USER,
            entity_id="unrelated_user",
        ),
    ]

    result = fusion_service.evaluate_evidence(
        evidences,
        entity_id="target_user",
        entity_type=EntityType.USER,
    )

    assert result.entity_id == "target_user"
    assert len(result.detector_results) == 1
    assert result.detector_results[0].entity_id == "target_user"
