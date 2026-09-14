"""Integration test suite for Phase 10 Alerting, Case Management REST API & End-to-End pipeline.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.alerts.schemas import AlertStatus, CaseStatus
from backend.db.session import get_db, SessionLocal
from backend.features.schemas import EntityType
from backend.main import app
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
from simulator.pipeline import run_simulation_pipeline
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.distributed_bruteforce import DistributedBruteForceScenario


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def db_session():
    """Database session fixture."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_alerts_api_flow(client, db_session):
    """Test /api/alerts evaluation, query, and status transition endpoints."""
    import uuid
    unique_id = uuid.uuid4().hex[:8]
    unique_risk_id = f"api-risk-eval-{unique_id}"
    unique_entity = f"victim_api_user_{unique_id}"

    # 1. Create a Risk Score in DB
    risk_repo = RiskRepository(db_session)
    breakdown = ContributorBreakdown(
        statistical=StatisticalContributor(score=22.0, maximum=25.0, evidence="ANOMALOUS", explanation="Peak stat"),
        isolation_forest=IsolationForestContributor(score=20.0, maximum=25.0, evidence="ANOMALOUS", explanation="IF"),
        behavioral_clustering=ClusteringContributor(score=16.0, maximum=20.0, evidence="ANOMALOUS", explanation="KMeans"),
        deterministic_rules=DeterministicRulesContributor(score=20.0, maximum=20.0, explanation="Rules"),
        cross_entity_correlation=CorrelationContributor(score=8.0, maximum=10.0, evidence_strength="CONCLUSIVE", explanation="Corr"),
        final_score=86.0,
        severity=RiskSeverity.CRITICAL,
    )
    risk_res = RiskScoreResult(
        risk_id=unique_risk_id,
        timestamp=datetime.now(timezone.utc),
        entity_type=EntityType.USER,
        entity_id=unique_entity,
        final_score=86.0,
        severity=RiskSeverity.CRITICAL,
        statistical_contribution=22.0,
        isolation_forest_contribution=20.0,
        clustering_contribution=16.0,
        rules_contribution=20.0,
        correlation_contribution=8.0,
        evidence_strength="CONCLUSIVE",
        contributor_breakdown=breakdown,
        explanation="Threat Risk Score 86.0/100 (CRITICAL).",
    )
    risk_repo.create_score(risk_res)

    # 2. POST /api/alerts/evaluate with risk_id
    eval_resp = client.post("/api/alerts/evaluate", json={"risk_id": unique_risk_id})
    assert eval_resp.status_code == 200
    alert_data = eval_resp.json()
    assert alert_data["risk_score"] == 86.0
    assert alert_data["severity"] == "CRITICAL"
    alert_id = alert_data["alert_id"]
    case_id = alert_data["case_id"]

    # 3. GET /api/alerts query
    list_resp = client.get(f"/api/alerts?entity_id={unique_entity}")
    assert list_resp.status_code == 200
    alerts = list_resp.json()
    assert len(alerts) >= 1
    assert any(a["alert_id"] == alert_id for a in alerts)

    # 4. GET /api/alerts/{alert_id}
    detail_resp = client.get(f"/api/alerts/{alert_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["alert_id"] == alert_id

    # 5. PATCH /api/alerts/{alert_id}/status -> ACKNOWLEDGED
    patch_resp = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED", "notes": "Analyst investigating"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "ACKNOWLEDGED"

    # 6. Check associated case via GET /api/cases/{case_id}
    case_resp = client.get(f"/api/cases/{case_id}")
    assert case_resp.status_code == 200
    case_data = case_resp.json()
    assert case_data["case_id"] == case_id
    assert case_data["status"] == "OPEN"
    assert case_data["total_risk_score"] == 86.0

    # 7. GET /api/cases/{case_id}/timeline
    timeline_resp = client.get(f"/api/cases/{case_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert len(timeline) >= 2

    # 8. GET /api/cases/{case_id}/alerts
    case_alerts_resp = client.get(f"/api/cases/{case_id}/alerts")
    assert case_alerts_resp.status_code == 200
    assert len(case_alerts_resp.json()) >= 1

    # 9. PATCH /api/cases/{case_id}/status -> INVESTIGATING -> RESOLVED
    p1 = client.patch(f"/api/cases/{case_id}/status", json={"status": "INVESTIGATING", "assigned_to": "alice"})
    assert p1.status_code == 200
    assert p1.json()["status"] == "INVESTIGATING"

    p2 = client.patch(f"/api/cases/{case_id}/status", json={"status": "RESOLVED", "resolution_notes": "All clean"})
    assert p2.status_code == 200
    assert p2.json()["status"] == "RESOLVED"


def test_full_pipeline_end_to_end_alert_and_case(db_session):
    """Full End-to-End Test:

    Synthetic attack telemetry
    -> Ingestion
    -> Feature Engineering
    -> Detectors
    -> Fusion
    -> Risk Score
    -> Alert
    -> Case
    -> Case Timeline
    """
    import uuid
    target = f"account_p10_e2e_{uuid.uuid4().hex[:8]}"
    cfg = ScenarioConfig(
        name="distributed_bruteforce",
        seed=1001,
        count=120,
        parameters={"unique_ips": 100, "target_accounts": [target]},
    )
    events = DistributedBruteForceScenario(cfg).generate()

    # Run full pipeline through simulation runner
    pipeline_result = run_simulation_pipeline(
        events=events,
        db=db_session,
        window_seconds=300,
        target_account=target,
    )

    # 1. Ingestion and features verified
    assert pipeline_result["ingested_count"] == len(events)
    assert pipeline_result["features"] is not None

    # 2. Risk score exists and computed
    risk_res = pipeline_result["risk_score_result"]
    assert risk_res is not None
    assert risk_res["final_score"] >= 0.0

    # 3. Alert and case integration
    alert = pipeline_result.get("alert_result")
    case = pipeline_result.get("case_result")

    if risk_res["final_score"] >= 40.0:
        # Meets threshold -> Alert and Case created
        assert alert is not None
        assert alert["risk_score"] == risk_res["final_score"]
        assert alert["severity"] == risk_res["severity"]
        assert alert["risk_id"] == risk_res["risk_id"]

        assert case is not None
        assert case["case_id"] == alert["case_id"]
        assert case["total_risk_score"] <= 100.0

        # Timeline verification
        from backend.alerts.service import alert_case_service
        timeline = alert_case_service.get_case_timeline(db_session, case["case_id"])
        assert len(timeline) >= 1
        linked_ids = [item.related_alert_id for item in timeline if item.related_alert_id]
        assert alert["alert_id"] in linked_ids
    else:
        # Score below 40 -> no alert created
        assert alert is None
