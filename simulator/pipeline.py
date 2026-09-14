"""End-to-end simulator pipeline integration and demo progression runner.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Connects synthetic scenario generators directly to the full platform detection pipeline:
Scenario Generator
  -> Canonical Telemetry
  -> Ingestion (EventRepository)
  -> Feature Engineering (FeatureEngineeringService)
  -> Statistical Baseline (StatisticalDetector)
  -> Isolation Forest (IsolationForestService)
  -> Behavioral Clustering (BehavioralClusteringService)
  -> Anomaly Fusion (AnomalyFusionService)
  -> Threat Risk Scoring (RiskScoringService)
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.orm import Session

from backend.detection.clustering_service import behavioral_clustering_service
from backend.detection.fusion_service import anomaly_fusion_service
from backend.detection.isolation_forest_service import isolation_forest_service
from backend.detection.statistical_detector import statistical_detector
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.service import feature_service
from backend.models.canonical import CanonicalEvent
from backend.models.db_event import TelemetryEventDB
from backend.models.telemetry import normalize_event
from backend.repositories.event_repository import EventRepository
from backend.repositories.feature_repository import FeatureRepository
from backend.risk.service import risk_scoring_service
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.distributed_bruteforce import DistributedBruteForceScenario
from simulator.scenarios.normal import NormalTrafficScenario

logger = logging.getLogger(__name__)


def run_simulation_pipeline(
    events: List[Dict[str, Any]],
    db: Session,
    window_seconds: int = 300,
    target_account: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest synthetic events and run end-to-end feature extraction, detection, fusion, and risk scoring."""
    # 1. Normalize and ingest telemetry events
    canonical_events: List[CanonicalEvent] = []
    db_events: List[TelemetryEventDB] = []

    for raw in events:
        try:
            canon = normalize_event(raw)
            canonical_events.append(canon)
            db_events.append(TelemetryEventDB.from_canonical(canon))
        except Exception as e:
            logger.warning("Event normalization skipped: %s", e)

    # Persist ingested events
    if db_events:
        db.add_all(db_events)
        db.commit()

    # 2. Extract feature snapshot for the primary target or GLOBAL entity
    entity_type = EntityType.USER if target_account else EntityType.GLOBAL
    entity_id = target_account if target_account else "GLOBAL"

    relevant_events = (
        [e for e in canonical_events if e.user_id == target_account]
        if target_account
        else canonical_events
    )

    if not relevant_events:
        relevant_events = canonical_events

    snapshot = feature_service.calculate_for_events(
        events=relevant_events,
        window_seconds=window_seconds,
        entity_type=entity_type,
        entity_id=entity_id,
    )

    # Persist feature snapshot
    feat_repo = FeatureRepository(db)
    feat_repo.create_snapshot(snapshot)

    # 3. Phase 4: Statistical Detection
    stat_results = statistical_detector.score_snapshot_with_db(
        db=db,
        snapshot=snapshot,
        persist=True,
    )

    # 4. Phase 5: Isolation Forest Detection
    if_result = None
    try:
        # Check if model is fitted or load if available
        isolation_forest_service.try_load_model()
        if isolation_forest_service.is_ready:
            if_result = isolation_forest_service.evaluate_snapshot(
                db=db,
                snapshot=snapshot,
                persist=True,
            )
    except Exception as e:
        logger.warning("Isolation Forest scoring deferred: %s", e)

    # 5. Phase 6: Behavioral Clustering Detection
    clustering_result = None
    try:
        behavioral_clustering_service.try_load_model()
        if behavioral_clustering_service.is_ready:
            clustering_result = behavioral_clustering_service.evaluate_snapshot(
                db=db,
                snapshot=snapshot,
                persist=True,
            )
    except Exception as e:
        logger.warning("Behavioral Clustering scoring deferred: %s", e)

    # 6. Phase 7: Anomaly Fusion
    fusion_result = anomaly_fusion_service.evaluate_snapshot(
        db=db,
        snapshot_id=snapshot.snapshot_id,
        correlation_window_seconds=window_seconds,
        persist=True,
    )

    # 7. Phase 8: Explainable Threat Risk Scoring
    risk_score_result = risk_scoring_service.evaluate_snapshot(
        db=db,
        snapshot_id=snapshot.snapshot_id,
        correlation_window_seconds=window_seconds,
        persist=True,
    )

    # 8. Phase 10: Alert & Case Management
    from backend.alerts.service import alert_case_service
    alert_result = alert_case_service.process_risk_score(
        risk_result=risk_score_result,
        db=db,
        persist=True,
    )

    case_result = None
    if alert_result and alert_result.case_id:
        from backend.repositories.case_repository import CaseRepository
        case_db = CaseRepository(db).get_by_case_id(alert_result.case_id)
        if case_db:
            case_result = case_db.to_schema()

    return {
        "event_count": len(events),
        "ingested_count": len(db_events),
        "snapshot_id": snapshot.snapshot_id,
        "entity_type": str(entity_type.value),
        "entity_id": entity_id,
        "features": snapshot.features,
        "statistical_results_count": len(stat_results),
        "statistical_anomalies_count": sum(1 for r in stat_results if r.is_anomalous),
        "isolation_forest_evaluated": if_result is not None,
        "clustering_evaluated": clustering_result is not None,
        "fusion_result": {
            "fusion_id": fusion_result.fusion_id,
            "evidence_strength": str(fusion_result.evidence_strength.value),
            "anomalous_detector_count": fusion_result.anomalous_detector_count,
            "contributing_detectors": fusion_result.contributing_detectors,
            "explanation": fusion_result.fusion_explanation,
        },
        "risk_score_result": {
            "risk_id": risk_score_result.risk_id,
            "final_score": risk_score_result.final_score,
            "severity": str(risk_score_result.severity.value),
            "statistical_contribution": risk_score_result.statistical_contribution,
            "isolation_forest_contribution": risk_score_result.isolation_forest_contribution,
            "clustering_contribution": risk_score_result.clustering_contribution,
            "rules_contribution": risk_score_result.rules_contribution,
            "correlation_contribution": risk_score_result.correlation_contribution,
            "explanation": risk_score_result.explanation,
        },
        "alert_result": alert_result.model_dump(mode="json") if alert_result else None,
        "case_result": case_result.model_dump(mode="json") if case_result else None,
    }


def run_demo_progression(db: Session, seed: int = 42) -> Dict[str, Any]:
    """Execute the 9-step hackathon demo progression from baseline normal to high-severity risk score."""
    demo_log: List[str] = []

    def log(msg: str):
        demo_log.append(msg)
        print(msg)

    log("=" * 65)
    log("  SH4D0W_ST4LK3R - 5-MINUTE HACKATHON DEMO PROGRESSION")
    log("=" * 65)

    # STEP 0: Model Readiness & Normal Baseline Check
    log("\n[STEP 0] Verifying unsupervised ML model readiness on normal baseline...")
    from backend.simulation.bootstrap import ensure_ml_models_ready
    ml_status = ensure_ml_models_ready(db, seed=seed)
    log(f"  -> Isolation Forest Status: {'READY' if ml_status.get('isolation_forest_ready') else 'NOT_READY'}")
    log(f"  -> Behavioral Clustering Status: {'READY' if ml_status.get('clustering_ready') else 'NOT_READY'}")

    # STEP 1: Normal baseline telemetry
    log("\n[STEP 1] Generating and ingesting normal baseline enterprise telemetry...")
    normal_cfg = ScenarioConfig(name="normal", seed=seed, count=60)
    normal_events = NormalTrafficScenario(normal_cfg).generate()
    normal_res = run_simulation_pipeline(normal_events, db, window_seconds=300)
    log(f"  -> Ingested {normal_res['ingested_count']} baseline events.")
    log(f"  -> Normal Risk Score: {normal_res['risk_score_result']['final_score']}/100 ({normal_res['risk_score_result']['severity']})")

    # STEP 2: Distributed low-and-slow brute force begins
    log("\n[STEP 2] Launching Distributed Low-and-Slow Brute Force attack...")
    target_account = "account_001"
    attack_cfg = ScenarioConfig(
        name="distributed_bruteforce",
        seed=seed,
        count=150,
        parameters={"unique_ips": 120, "target_accounts": [target_account, "account_002"]},
    )
    attack_events = DistributedBruteForceScenario(attack_cfg).generate()
    log(f"  -> Generated {len(attack_events)} attack events across 120 source IPs (1-2 attempts per IP).")
    log("  -> Individual IP view: 1 attempt per IP (evades conventional per-IP rate limiting).")

    # STEP 3: Collective behavioral features become abnormal
    log("\n[STEP 3] Evaluating collective behavioral feature extraction...")
    attack_res = run_simulation_pipeline(
        attack_events,
        db,
        window_seconds=300,
        target_account=target_account,
    )
    feats = attack_res["features"]
    log(f"  -> unique_source_ips: {feats.get('unique_source_ips', 0):.1f}")
    log(f"  -> ip_to_account_ratio: {feats.get('ip_to_account_ratio', 0):.2f}")
    log(f"  -> distributed_attempt_score: {feats.get('distributed_attempt_score', 0):.2f}")
    log(f"  -> failed_login_rate: {feats.get('failed_login_rate', 0):.2%}")

    # STEP 4: Statistical detector
    log("\n[STEP 4] Statistical Detector: Evaluating z-score deviations...")
    log(f"  -> Flagged {attack_res['statistical_anomalies_count']} anomalous statistical feature(s).")

    # STEP 5: Isolation Forest
    log("\n[STEP 5] Isolation Forest: Evaluating unsupervised multi-dimensional anomaly vector...")
    log(f"  -> Evaluated: {attack_res['isolation_forest_evaluated']}")

    # STEP 6: Behavioral Clustering
    log("\n[STEP 6] Behavioral Clustering: Evaluating centroid distance...")
    log(f"  -> Evaluated: {attack_res['clustering_evaluated']}")

    # STEP 7: Anomaly Fusion
    log("\n[STEP 7] Anomaly Fusion: Independent multi-detector agreement...")
    f_res = attack_res["fusion_result"]
    log(f"  -> Evidence Strength: {f_res['evidence_strength']}")
    log(f"  -> Contributing Detectors: {', '.join(f_res['contributing_detectors'])}")
    log(f"  -> Fusion Rationale: {f_res['explanation']}")

    # STEP 8: Threat Risk Score rises
    log("\n[STEP 8] Threat Risk Score Calculation (0-100)...")
    r_res = attack_res["risk_score_result"]
    log(f"  -> Final Risk Score: {r_res['final_score']}/100 ({r_res['severity']})")
    log(f"  -> Statistical Contribution: {r_res['statistical_contribution']:.1f} pts (max 25)")
    log(f"  -> Isolation Forest Contribution: {r_res['isolation_forest_contribution']:.1f} pts (max 25)")
    log(f"  -> Behavioral Clustering Contribution: {r_res['clustering_contribution']:.1f} pts (max 20)")
    log(f"  -> Correlation Agreement Contribution: {r_res['correlation_contribution']:.1f} pts (max 10)")

    # STEP 9: Transparent Security Explanation
    log("\n[STEP 9] Human-Readable SOC Security Explanation:")
    log(f"  \"{r_res['explanation']}\"")

    # STEP 10: Alert Creation & Case Correlation
    log("\n[STEP 10] Phase 10 SOC Alert & Incident Case Generation:")
    if attack_res.get("alert_result"):
        alt = attack_res["alert_result"]
        log(f"  -> Alert Created: [{alt['severity']}] {alt['title']}")
        log(f"  -> Alert ID: {alt['alert_id']}")
        log(f"  -> Deduplication Key: {alt['dedup_key']} (Occurrences: {alt['occurrence_count']})")
    if attack_res.get("case_result"):
        cas = attack_res["case_result"]
        log(f"  -> Incident Case Linked: {cas['case_id']}")
        log(f"  -> Case Title: {cas['title']}")
        log(f"  -> Total Case Score: {cas['total_risk_score']:.1f}/100 ({cas['severity']})")
        log(f"  -> Detected Kill-Chain Stages: {', '.join(cas['kill_chain_stages'])}")
        log(f"  -> Correlated Alerts: {cas['alert_count']}")
    log("=" * 65)

    return {
        "normal": normal_res,
        "attack": attack_res,
        "progression_log": demo_log,
    }
