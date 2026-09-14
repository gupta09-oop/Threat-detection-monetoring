"""Comprehensive unit tests for Phase 10 Alerting, Deduplication, and Case Management.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.alerts.schemas import (
    AlertResult,
    AlertStatus,
    CaseResult,
    CaseStatus,
    TimelineItem,
)
from backend.alerts.service import AlertCaseService, alert_case_service
from backend.db.base import Base
from backend.features.schemas import EntityType
from backend.models.alert import AlertDB
from backend.models.case import CaseDB
from backend.models.risk import RiskScoreDB
from backend.repositories.alert_repository import AlertRepository
from backend.repositories.case_repository import CaseRepository
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


@pytest.fixture
def test_db():
    """In-memory SQLite session fixture for alert and case tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def create_sample_risk_result(
    score: float,
    entity_id: str = "account_001",
    entity_type: EntityType = EntityType.USER,
    severity: RiskSeverity = RiskSeverity.HIGH,
    timestamp: datetime = None,
    rule_id: str = None,
) -> RiskScoreResult:
    """Helper to generate a mock RiskScoreResult."""
    ts = timestamp or datetime.now(timezone.utc)
    rules_list = [{"rule_id": rule_id, "score": 20.0, "is_anomalous": True, "explanation": "Rule triggered"}] if rule_id else []

    breakdown = ContributorBreakdown(
        statistical=StatisticalContributor(
            score=20.0 if score > 30 else 0.0,
            maximum=25.0,
            evidence="ANOMALOUS" if score > 30 else "NORMAL",
            features=[{"feature_name": "unique_source_ips", "is_anomalous": True}] if score > 30 else [],
            explanation="Statistical anomaly",
        ),
        isolation_forest=IsolationForestContributor(
            score=20.0 if score > 50 else 0.0,
            maximum=25.0,
            evidence="ANOMALOUS" if score > 50 else "NORMAL",
            explanation="IF anomaly",
        ),
        behavioral_clustering=ClusteringContributor(
            score=15.0 if score > 70 else 0.0,
            maximum=20.0,
            evidence="ANOMALOUS" if score > 70 else "NORMAL",
            explanation="Clustering anomaly",
        ),
        deterministic_rules=DeterministicRulesContributor(
            score=20.0 if rule_id else 0.0,
            maximum=20.0,
            rule_count=len(rules_list),
            rules=rules_list,
            explanation="Rule match" if rule_id else "No rules",
        ),
        cross_entity_correlation=CorrelationContributor(
            score=5.0 if score > 60 else 0.0,
            maximum=10.0,
            evidence_strength="STRONG" if score > 60 else "LOW",
            anomalous_detector_count=2 if score > 60 else 0,
            independent_detector_count=3,
            explanation="Correlation agreement",
        ),
        final_score=score,
        severity=severity,
    )

    return RiskScoreResult(
        risk_id=f"risk-{score}-{entity_id}",
        timestamp=ts,
        entity_type=entity_type,
        entity_id=entity_id,
        snapshot_id="snap-test-01",
        window_seconds=300,
        final_score=score,
        severity=severity,
        statistical_contribution=breakdown.statistical.score,
        isolation_forest_contribution=breakdown.isolation_forest.score,
        clustering_contribution=breakdown.behavioral_clustering.score,
        rules_contribution=breakdown.deterministic_rules.score,
        correlation_contribution=breakdown.cross_entity_correlation.score,
        evidence_strength=breakdown.cross_entity_correlation.evidence_strength,
        contributor_breakdown=breakdown,
        explanation=f"Threat Risk Score {score:.1f}/100 ({severity.value}).",
        details={"source_ips": ["198.51.100.1"], "kill_chain_stage": "INITIAL_ACCESS"},
    )


def test_alert_threshold_boundary(test_db):
    """Test blueprint alert threshold: score >= 40 creates alert; score < 40 does not."""
    service = AlertCaseService(alert_risk_threshold=40.0)

    # 1. Score 39.0 -> No alert created
    risk_39 = create_sample_risk_result(39.0, severity=RiskSeverity.LOW)
    alert_39 = service.process_risk_score(risk_39, test_db)
    assert alert_39 is None

    # 2. Score 40.0 -> Alert created (MEDIUM)
    risk_40 = create_sample_risk_result(40.0, severity=RiskSeverity.MEDIUM)
    alert_40 = service.process_risk_score(risk_40, test_db)
    assert alert_40 is not None
    assert alert_40.risk_score == 40.0
    assert alert_40.severity == RiskSeverity.MEDIUM
    assert alert_40.status == AlertStatus.NEW

    # 3. Score 65.0 -> HIGH Alert
    risk_65 = create_sample_risk_result(65.0, entity_id="account_002", severity=RiskSeverity.HIGH)
    alert_65 = service.process_risk_score(risk_65, test_db)
    assert alert_65 is not None
    assert alert_65.severity == RiskSeverity.HIGH

    # 4. Score 85.0 -> CRITICAL Alert
    risk_85 = create_sample_risk_result(85.0, entity_id="account_003", severity=RiskSeverity.CRITICAL)
    alert_85 = service.process_risk_score(risk_85, test_db)
    assert alert_85 is not None
    assert alert_85.severity == RiskSeverity.CRITICAL

    # 5. Score 100.0 -> CRITICAL Alert
    risk_100 = create_sample_risk_result(100.0, entity_id="account_004", severity=RiskSeverity.CRITICAL)
    alert_100 = service.process_risk_score(risk_100, test_db)
    assert alert_100 is not None
    assert alert_100.severity == RiskSeverity.CRITICAL


def test_alert_deduplication(test_db):
    """Test deduplication: same entity + same evidence family within 5 minutes updates existing alert."""
    service = AlertCaseService(alert_risk_threshold=40.0, dedup_window_seconds=300)
    now = datetime.now(timezone.utc)

    # Initial alert
    risk1 = create_sample_risk_result(70.0, entity_id="target_user", timestamp=now)
    alert1 = service.process_risk_score(risk1, test_db)
    assert alert1.occurrence_count == 1
    alert_id = alert1.alert_id

    # Second event 60 seconds later (within 300s window)
    risk2 = create_sample_risk_result(75.0, entity_id="target_user", timestamp=now + timedelta(seconds=60))
    alert2 = service.process_risk_score(risk2, test_db)
    assert alert2.alert_id == alert_id  # Reused same alert
    assert alert2.occurrence_count == 2
    assert alert2.risk_score == 75.0

    # Third event 400 seconds later (outside 300s window) -> New alert
    risk3 = create_sample_risk_result(80.0, entity_id="target_user", timestamp=now + timedelta(seconds=400))
    alert3 = service.process_risk_score(risk3, test_db)
    assert alert3.alert_id != alert_id  # New alert
    assert alert3.occurrence_count == 1

    # Different entity -> Separate alert
    risk4 = create_sample_risk_result(70.0, entity_id="other_user", timestamp=now)
    alert4 = service.process_risk_score(risk4, test_db)
    assert alert4.alert_id != alert1.alert_id
    assert alert4.entity_id == "other_user"

    # Different evidence family -> Separate alert
    risk5 = create_sample_risk_result(70.0, entity_id="target_user", timestamp=now + timedelta(seconds=10), rule_id="RULE-AUTH-DIST-001")
    alert5 = service.process_risk_score(risk5, test_db)
    assert alert5.alert_id != alert1.alert_id


def test_alert_lifecycle_transitions(test_db):
    """Test strict state-machine validation for alert status transitions."""
    service = AlertCaseService()
    risk = create_sample_risk_result(80.0, entity_id="account_test")
    alert = service.process_risk_score(risk, test_db)
    aid = alert.alert_id

    # Valid: NEW -> ACKNOWLEDGED
    up1 = service.update_alert_status(test_db, aid, AlertStatus.ACKNOWLEDGED, notes="Investigating")
    assert up1.status == AlertStatus.ACKNOWLEDGED

    # Valid: ACKNOWLEDGED -> ESCALATED
    up2 = service.update_alert_status(test_db, aid, AlertStatus.ESCALATED, notes="Escalating to Tier 2")
    assert up2.status == AlertStatus.ESCALATED

    # Valid: ESCALATED -> CLOSED
    up3 = service.update_alert_status(test_db, aid, AlertStatus.CLOSED, notes="Incident contained")
    assert up3.status == AlertStatus.CLOSED

    # Invalid: CLOSED -> NEW (forbidden transition)
    with pytest.raises(ValueError, match="Invalid alert status transition"):
        service.update_alert_status(test_db, aid, AlertStatus.NEW)

    # Invalid: CLOSED -> ACKNOWLEDGED
    with pytest.raises(ValueError, match="Invalid alert status transition"):
        service.update_alert_status(test_db, aid, AlertStatus.ACKNOWLEDGED)


def test_case_correlation_and_scoring(test_db):
    """Test case correlation: multiple alerts join case; case score is bounded 0-100 (never summed)."""
    service = AlertCaseService(alert_risk_threshold=40.0, case_correlation_window_seconds=300)
    now = datetime.now(timezone.utc)

    # 1. Alert 1 creates Case
    risk1 = create_sample_risk_result(50.0, entity_id="victim_acc", timestamp=now)
    alert1 = service.process_risk_score(risk1, test_db)
    case_id = alert1.case_id
    assert case_id is not None

    repo = CaseRepository(test_db)
    case = repo.get_by_case_id(case_id)
    assert case.alert_count == 1
    assert case.total_risk_score == 50.0
    assert case.severity == "MEDIUM"

    # 2. Alert 2 on same entity with higher score joins same Case
    risk2 = create_sample_risk_result(80.0, entity_id="victim_acc", timestamp=now + timedelta(seconds=120), rule_id="RULE-AUTH-DIST-001")
    alert2 = service.process_risk_score(risk2, test_db)
    assert alert2.case_id == case_id

    case_updated = repo.get_by_case_id(case_id)
    assert case_updated.alert_count == 2
    # Total risk score is peak/current (80.0), NOT summed (50 + 80 = 130 is strictly avoided)
    assert case_updated.total_risk_score == 80.0
    assert case_updated.severity == "HIGH"
    assert case_updated.total_risk_score <= 100.0


def test_case_lifecycle_transitions(test_db):
    """Test strict state-machine validation for incident case status transitions."""
    service = AlertCaseService()
    risk = create_sample_risk_result(70.0, entity_id="account_case_test")
    alert = service.process_risk_score(risk, test_db)
    cid = alert.case_id

    # Valid: OPEN -> INVESTIGATING
    c1 = service.update_case_status(test_db, cid, CaseStatus.INVESTIGATING, assigned_to="analyst_alice")
    assert c1.status == CaseStatus.INVESTIGATING
    assert c1.assigned_to == "analyst_alice"

    # Valid: INVESTIGATING -> RESOLVED
    c2 = service.update_case_status(test_db, cid, CaseStatus.RESOLVED, resolution_notes="Compromised credentials rotated")
    assert c2.status == CaseStatus.RESOLVED
    assert c2.resolution_notes == "Compromised credentials rotated"

    # Invalid: RESOLVED -> OPEN
    with pytest.raises(ValueError, match="Invalid case status transition"):
        service.update_case_status(test_db, cid, CaseStatus.OPEN)

    # Invalid: RESOLVED -> INVESTIGATING
    with pytest.raises(ValueError, match="Invalid case status transition"):
        service.update_case_status(test_db, cid, CaseStatus.INVESTIGATING)


def test_kill_chain_and_affected_entities(test_db):
    """Test preservation of detected kill-chain stages and affected entities."""
    service = AlertCaseService()
    risk = create_sample_risk_result(88.0, entity_id="user_admin")
    alert = service.process_risk_score(risk, test_db)

    case_repo = CaseRepository(test_db)
    case_db = case_repo.get_by_case_id(alert.case_id)

    # Kill chain stage preserved
    assert "INITIAL_ACCESS" in case_db.kill_chain_stages
    # Affected entities extracted
    assert "user_admin" in case_db.affected_entities.get("accounts", [])
    assert "198.51.100.1" in case_db.affected_entities.get("source_ips", [])


def test_investigation_timeline(test_db):
    """Test structured investigation timeline chronological aggregation."""
    service = AlertCaseService()
    now = datetime.now(timezone.utc)

    risk1 = create_sample_risk_result(60.0, entity_id="timelined_user", timestamp=now)
    alert1 = service.process_risk_score(risk1, test_db)
    cid = alert1.case_id

    timeline = service.get_case_timeline(test_db, cid)
    assert len(timeline) >= 2  # CASE_OPENED + ALERT + RISK_EVALUATION

    # Chronologically sorted
    for i in range(len(timeline) - 1):
        assert timeline[i].timestamp <= timeline[i + 1].timestamp

    types = [item.evidence_type for item in timeline]
    assert "CASE_OPENED" in types
    assert "ALERT" in types


def test_forbidden_terminology_in_alerts(test_db):
    """Verify explanations and titles do NOT contain forbidden probabilistic/AI buzzwords."""
    service = AlertCaseService()
    risk = create_sample_risk_result(92.0, entity_id="audit_user")
    alert = service.process_risk_score(risk, test_db)

    forbidden_phrases = [
        "ai reasoning",
        "model confidence",
        "ai confidence",
        "probability of compromise",
        "probability of attack",
    ]

    title_lower = alert.title.lower()
    summary_lower = alert.summary.lower()
    expl_lower = alert.explanation.lower()

    for phrase in forbidden_phrases:
        assert phrase not in title_lower, f"Forbidden phrase '{phrase}' in title"
        assert phrase not in summary_lower, f"Forbidden phrase '{phrase}' in summary"
        assert phrase not in expl_lower, f"Forbidden phrase '{phrase}' in explanation"
