"""Service layer for Phase 10 Alerting, Deduplication, and Case Management.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Implements:
1. Alert creation when Threat Risk Score >= 40.0 (MEDIUM, HIGH, CRITICAL).
2. Deduplication within ALERT_DEDUP_WINDOW_SECONDS (300s).
3. Contextual, non-generic title and evidence-grounded explanation generation.
4. Strict state machine validation for AlertStatus and CaseStatus.
5. Case correlation within CASE_CORRELATION_WINDOW_SECONDS (300s).
6. Bounded 0-100 Case total risk scoring (reflecting highest/current risk, never summing).
7. Preservation of detected kill-chain stages and affected entities.
8. Chronological investigation timeline aggregation.
9. Real-time event dispatching via WebSocket manager.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

from sqlalchemy.orm import Session

from backend.alerts.schemas import (
    AlertResult,
    AlertStatus,
    CaseResult,
    CaseStatus,
    TimelineItem,
    VALID_ALERT_TRANSITIONS,
    VALID_CASE_TRANSITIONS,
)
from backend.config import settings
from backend.features.schemas import EntityType
from backend.models.alert import AlertDB
from backend.models.case import CaseDB
from backend.models.risk import RiskScoreDB
from backend.realtime import manager as ws_manager
from backend.repositories.alert_repository import AlertRepository
from backend.repositories.case_repository import CaseRepository
from backend.repositories.risk_repository import RiskRepository
from backend.risk.schemas import RiskScoreResult, RiskSeverity

logger = logging.getLogger(__name__)


def generate_dedup_key(risk_result: RiskScoreResult) -> str:
    """Compute deterministic deduplication key from entity and evidence family."""
    cb = risk_result.contributor_breakdown

    # Identify primary anomalous driver
    dominant_family = "BEHAVIORAL_ANOMALY"
    if cb.deterministic_rules.score > 0 and cb.deterministic_rules.rules:
        dominant_family = cb.deterministic_rules.rules[0].get("rule_id", "RULE")
    elif cb.cross_entity_correlation.score > 0:
        dominant_family = "MULTI_DETECTOR_CORRELATION"
    elif cb.statistical.score >= cb.isolation_forest.score and cb.statistical.score >= cb.behavioral_clustering.score:
        if cb.statistical.features:
            dominant_family = f"STAT_{cb.statistical.features[0].get('feature_name', 'DEVIATION')}"
        else:
            dominant_family = "STATISTICAL_DEVIATION"
    elif cb.isolation_forest.score >= cb.behavioral_clustering.score:
        dominant_family = "ISOLATION_FOREST_ANOMALY"
    elif cb.behavioral_clustering.score > 0:
        dominant_family = "CLUSTERING_OUTLIER"

    return f"{dominant_family}"


def generate_alert_title(risk_result: RiskScoreResult) -> str:
    """Generate contextual, evidence-grounded alert title without generic placeholders."""
    cb = risk_result.contributor_breakdown

    # Check for rule triggers
    if cb.deterministic_rules.score > 0 and cb.deterministic_rules.rules:
        r_id = cb.deterministic_rules.rules[0].get("rule_id", "")
        if "AUTH-DIST" in r_id or "DISTRIBUTED" in r_id:
            return "Distributed Authentication Anomaly Detected"
        if "CRED-STUFF" in r_id or "STUFFING" in r_id:
            return "Credential Stuffing Behavior Detected"
        if "PORT-SCAN" in r_id or "RECON" in r_id:
            return "Network Reconnaissance Anomaly Detected"

    # Check top statistical features
    if cb.statistical.score > 0 and cb.statistical.features:
        feat_names = [f.get("feature_name", "") for f in cb.statistical.features if f.get("is_anomalous")]
        if any("unique_source_ips" in fn or "ip_to_account" in fn or "distributed" in fn for fn in feat_names):
            return "Distributed Authentication Anomaly Detected"
        if any("failed_login" in fn or "account_diversity" in fn for fn in feat_names):
            return "Credential Stuffing Behavior Detected"
        if any("destination_port" in fn or "failed_conn" in fn or "port_diversity" in fn for fn in feat_names):
            return "Network Reconnaissance Anomaly Detected"

    # Multi-detector agreement
    if cb.cross_entity_correlation.score > 0 or risk_result.details.get("anomalous_detector_count", 0) >= 2:
        return "Multi-Detector Behavioral Anomaly Detected"

    if cb.isolation_forest.score > 0:
        return "High-Dimensional Behavioral Outlier Detected"

    if cb.behavioral_clustering.score > 0:
        return "Behavioral Cluster Centroid Deviation Detected"

    return "Elevated Threat Risk Anomaly Detected"


def generate_alert_summary(risk_result: RiskScoreResult, title: str) -> str:
    """Generate concise executive summary grounded in detection evidence."""
    sev_val = (
        risk_result.severity.value
        if hasattr(risk_result.severity, "value")
        else str(risk_result.severity)
    )
    return (
        f"{title} targeting entity {risk_result.entity_id} "
        f"with Threat Risk Score {risk_result.final_score:.1f}/100 ({sev_val})."
    )


def extract_kill_chain_stages(risk_result: RiskScoreResult) -> List[str]:
    """Extract detected kill-chain stages from evidence without fabricating."""
    stages: List[str] = []
    cb = risk_result.contributor_breakdown

    # Check deterministic rules details
    for r in cb.deterministic_rules.rules:
        details = r.get("details", {})
        stg = details.get("kill_chain_stage") or details.get("stage")
        if stg and stg.upper() not in stages:
            stages.append(stg.upper())

    # Check statistical feature contexts
    for f in cb.statistical.features:
        if f.get("is_anomalous"):
            fn = f.get("feature_name", "")
            if "port" in fn or "recon" in fn or "scan" in fn:
                if "RECON" not in stages:
                    stages.append("RECON")
            elif "auth" in fn or "login" in fn or "stuff" in fn or "brute" in fn:
                if "INITIAL_ACCESS" not in stages:
                    stages.append("INITIAL_ACCESS")

    # Check general details
    details = risk_result.details or {}
    for stg_key in ("kill_chain_stage", "stage", "kill_chain_stages"):
        val = details.get(stg_key)
        if isinstance(val, str) and val.upper() not in stages:
            stages.append(val.upper())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.upper() not in stages:
                    stages.append(item.upper())

    return sorted(stages)


def extract_affected_entities(risk_result: RiskScoreResult) -> Dict[str, List[str]]:
    """Aggregate affected accounts, source IPs, devices, destination IPs, and ports from evidence."""
    entities: Dict[str, Set[str]] = {
        "accounts": set(),
        "source_ips": set(),
        "devices": set(),
        "destination_ips": set(),
        "ports": set(),
    }

    # Target entity
    et = str(risk_result.entity_type.value if hasattr(risk_result.entity_type, "value") else risk_result.entity_type).upper()
    eid = risk_result.entity_id

    if et == "USER":
        entities["accounts"].add(eid)
    elif et == "IP":
        entities["source_ips"].add(eid)
    elif et == "HOST":
        entities["devices"].add(eid)

    # Scan details
    details = risk_result.details or {}
    for k, v in details.items():
        if "account" in k and isinstance(v, (str, list)):
            vals = [v] if isinstance(v, str) else v
            entities["accounts"].update(vals)
        elif "source_ip" in k and isinstance(v, (str, list)):
            vals = [v] if isinstance(v, str) else v
            entities["source_ips"].update(vals)
        elif "device" in k and isinstance(v, (str, list)):
            vals = [v] if isinstance(v, str) else v
            entities["devices"].update(vals)
        elif "dest" in k and isinstance(v, (str, list)):
            vals = [v] if isinstance(v, str) else v
            entities["destination_ips"].update(vals)
        elif "port" in k and isinstance(v, (str, int, list)):
            vals = [str(v)] if isinstance(v, (str, int)) else [str(x) for x in v]
            entities["ports"].update(vals)

    return {k: sorted(list(v)) for k, v in entities.items()}


class AlertCaseService:
    """Core domain service for alerts, deduplication, and case lifecycle management."""

    def __init__(
        self,
        alert_risk_threshold: Optional[float] = None,
        dedup_window_seconds: Optional[int] = None,
        case_correlation_window_seconds: Optional[int] = None,
    ) -> None:
        self.alert_threshold = (
            alert_risk_threshold
            if alert_risk_threshold is not None
            else getattr(settings, "ALERT_RISK_THRESHOLD", 40.0)
        )
        self.dedup_window = (
            dedup_window_seconds
            if dedup_window_seconds is not None
            else getattr(settings, "ALERT_DEDUP_WINDOW_SECONDS", 300)
        )
        self.case_correlation_window = (
            case_correlation_window_seconds
            if case_correlation_window_seconds is not None
            else getattr(settings, "CASE_CORRELATION_WINDOW_SECONDS", 300)
        )

    def process_risk_score(
        self,
        risk_result: RiskScoreResult,
        db: Session,
        persist: bool = True,
    ) -> Optional[AlertResult]:
        """Evaluate a Threat Risk Score and create/deduplicate an alert if score >= threshold."""
        # 1. Blueprint Alert Threshold Check (Score >= 40.0)
        if risk_result.final_score < self.alert_threshold:
            logger.debug(
                "Risk score %.1f below alert threshold %.1f for entity %s. No alert created.",
                risk_result.final_score,
                self.alert_threshold,
                risk_result.entity_id,
            )
            return None

        alert_repo = AlertRepository(db)
        case_repo = CaseRepository(db)

        dedup_key = generate_dedup_key(risk_result)
        ref_time = risk_result.timestamp or datetime.now(timezone.utc)

        # 2. Alert Deduplication check
        existing_alert = alert_repo.find_dedup_match(
            entity_id=risk_result.entity_id,
            dedup_key=dedup_key,
            window_seconds=self.dedup_window,
            reference_time=ref_time,
        )

        if existing_alert:
            # Refresh existing alert within dedup window
            logger.info(
                "Deduplication match: refreshing existing alert %s for entity %s (occurrence %d -> %d)",
                existing_alert.alert_id,
                existing_alert.entity_id,
                existing_alert.occurrence_count,
                existing_alert.occurrence_count + 1,
            )
            existing_alert.occurrence_count += 1
            existing_alert.updated_at = ref_time
            # Update risk score to latest or peak
            if risk_result.final_score > existing_alert.risk_score:
                existing_alert.risk_score = risk_result.final_score
                existing_alert.severity = (
                    risk_result.severity.value
                    if hasattr(risk_result.severity, "value")
                    else str(risk_result.severity)
                )

            # Refresh breakdown and explanation
            cb = risk_result.contributor_breakdown
            existing_alert.contributor_breakdown = (
                cb.model_dump(mode="json") if hasattr(cb, "model_dump") else cb
            )
            existing_alert.explanation = risk_result.explanation

            alert_repo.update_alert(existing_alert)

            # Update linked case total score if needed
            if existing_alert.case_id:
                linked_case = case_repo.get_by_case_id(existing_alert.case_id)
                if linked_case:
                    linked_case.total_risk_score = max(
                        linked_case.total_risk_score, existing_alert.risk_score
                    )
                    linked_case.updated_at = ref_time
                    case_repo.update_case(linked_case)

            alert_schema = existing_alert.to_schema()
            ws_manager.dispatch("alert.updated", alert_schema.model_dump(mode="json"))
            return alert_schema

        # 3. Create New Alert
        title = generate_alert_title(risk_result)
        summary = generate_alert_summary(risk_result, title)
        contributing_detectors = [
            canonical_fam
            for canonical_fam, score in [
                ("STATISTICAL_BASELINE", risk_result.contributor_breakdown.statistical.score),
                ("ISOLATION_FOREST", risk_result.contributor_breakdown.isolation_forest.score),
                ("BEHAVIORAL_CLUSTERING", risk_result.contributor_breakdown.behavioral_clustering.score),
                ("DETERMINISTIC_RULE", risk_result.contributor_breakdown.deterministic_rules.score),
            ]
            if score > 0
        ]

        alert_id = str(uuid.uuid4())

        # 4. Correlate into SOC Incident Case
        open_case = case_repo.find_open_case_for_entity(
            entity_id=risk_result.entity_id,
            window_seconds=self.case_correlation_window,
            reference_time=ref_time,
        )

        detected_stages = extract_kill_chain_stages(risk_result)
        affected_entities = extract_affected_entities(risk_result)

        if open_case:
            # Correlate alert into existing case
            case_id = open_case.case_id
            open_case.alert_count += 1
            # Bounded 0-100 max score
            open_case.total_risk_score = round(
                min(100.0, max(open_case.total_risk_score, risk_result.final_score)), 1
            )
            from backend.risk.service import determine_risk_severity
            open_case.severity = determine_risk_severity(open_case.total_risk_score).value

            # Merge kill chain stages
            merged_stages = list(set(open_case.kill_chain_stages or []).union(detected_stages))
            open_case.kill_chain_stages = sorted(merged_stages)

            # Merge affected entities
            curr_aff = open_case.affected_entities or {}
            for k, vals in affected_entities.items():
                curr_set = set(curr_aff.get(k, []))
                curr_set.update(vals)
                curr_aff[k] = sorted(list(curr_set))
            open_case.affected_entities = curr_aff

            # Append to risk history
            r_hist = list(open_case.risk_history or [])
            r_hist.append({
                "timestamp": ref_time.isoformat(),
                "score": risk_result.final_score,
                "severity": (
                    risk_result.severity.value
                    if hasattr(risk_result.severity, "value")
                    else str(risk_result.severity)
                ),
                "alert_id": alert_id,
            })
            open_case.risk_history = r_hist
            open_case.updated_at = ref_time

            case_repo.update_case(open_case)
            ws_manager.dispatch("case.updated", open_case.to_schema().model_dump(mode="json"))

        else:
            # Create new SOC Incident Case
            case_id = str(uuid.uuid4())
            from backend.risk.service import determine_risk_severity
            case_sev = determine_risk_severity(risk_result.final_score)

            case_res = CaseResult(
                case_id=case_id,
                entity_type=risk_result.entity_type,
                entity_id=risk_result.entity_id,
                title=f"Incident: {title} on {risk_result.entity_id}",
                summary=(
                    f"Suspicious activity detected targeting {risk_result.entity_id}. "
                    f"{risk_result.explanation} Current Threat Risk Score: {risk_result.final_score:.1f}/100."
                ),
                opened_at=ref_time,
                updated_at=ref_time,
                status=CaseStatus.OPEN,
                severity=case_sev,
                total_risk_score=risk_result.final_score,
                alert_count=1,
                kill_chain_stages=detected_stages,
                affected_entities=affected_entities,
                evidence_summary={
                    "initial_alert_id": alert_id,
                    "evidence_strength": risk_result.evidence_strength,
                    "contributing_detectors": contributing_detectors,
                },
                risk_history=[{
                    "timestamp": ref_time.isoformat(),
                    "score": risk_result.final_score,
                    "severity": case_sev.value,
                    "alert_id": alert_id,
                }],
            )
            case_repo.create_case(case_res)
            ws_manager.dispatch("case.created", case_res.model_dump(mode="json"))

        # Build AlertResult
        new_alert = AlertResult(
            alert_id=alert_id,
            risk_id=risk_result.risk_id,
            timestamp=ref_time,
            entity_type=risk_result.entity_type,
            entity_id=risk_result.entity_id,
            source_type="BEHAVIORAL",
            severity=risk_result.severity,
            risk_score=risk_result.final_score,
            title=title,
            summary=summary,
            explanation=risk_result.explanation,
            contributor_breakdown=risk_result.contributor_breakdown,
            evidence_strength=risk_result.evidence_strength,
            contributing_detectors=contributing_detectors,
            fusion_id=risk_result.source_fusion_id,
            snapshot_id=risk_result.snapshot_id,
            case_id=case_id,
            status=AlertStatus.NEW,
            occurrence_count=1,
            dedup_key=dedup_key,
            created_at=ref_time,
            updated_at=ref_time,
            details=risk_result.details or {},
        )

        if persist:
            alert_repo.create_alert(new_alert)

        ws_manager.dispatch("alert.created", new_alert.model_dump(mode="json"))
        return new_alert

    def update_alert_status(
        self,
        db: Session,
        alert_id: str,
        new_status: AlertStatus,
        notes: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        resolution: Optional[str] = None,
    ) -> AlertResult:
        """Validate and apply lifecycle status transition for an alert."""
        alert_repo = AlertRepository(db)
        alert_db = alert_repo.get_by_alert_id(alert_id)
        if not alert_db:
            raise ValueError(f"Alert '{alert_id}' not found.")

        current_status = AlertStatus(alert_db.status)
        valid_targets = VALID_ALERT_TRANSITIONS.get(current_status, [])

        if new_status not in valid_targets:
            raise ValueError(
                f"Invalid alert status transition from '{current_status.value}' to '{new_status.value}'. "
                f"Allowed transitions: {[s.value for s in valid_targets]}"
            )

        alert_db.status = new_status.value
        if assigned_analyst:
            alert_db.assigned_analyst = assigned_analyst
        if resolution:
            alert_db.resolution = resolution
        if notes:
            alert_db.resolution_notes = notes
            details = alert_db.details or {}
            notes_history = details.get("status_notes", [])
            notes_history.append({
                "from": current_status.value,
                "to": new_status.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "notes": notes,
                "analyst": assigned_analyst or alert_db.assigned_analyst or "SOC Analyst",
            })
            details["status_notes"] = notes_history
            alert_db.details = details

        alert_repo.update_alert(alert_db)
        schema = alert_db.to_schema()
        ws_manager.dispatch("alert.status_changed", schema.model_dump(mode="json"))
        return schema

    def assign_alert(self, db: Session, alert_id: str, analyst: str) -> AlertResult:
        """Assign a SOC analyst to an alert."""
        alert_repo = AlertRepository(db)
        alert_db = alert_repo.get_by_alert_id(alert_id)
        if not alert_db:
            raise ValueError(f"Alert '{alert_id}' not found.")

        alert_db.assigned_analyst = analyst
        alert_repo.update_alert(alert_db)
        schema = alert_db.to_schema()
        ws_manager.dispatch("alert.updated", schema.model_dump(mode="json"))
        return schema

    def add_alert_note(self, db: Session, alert_id: str, analyst: str, note_text: str) -> AlertResult:
        """Add an analyst note to an alert."""
        alert_repo = AlertRepository(db)
        alert_db = alert_repo.get_by_alert_id(alert_id)
        if not alert_db:
            raise ValueError(f"Alert '{alert_id}' not found.")

        details = alert_db.details or {}
        analyst_notes = details.get("analyst_notes", [])
        analyst_notes.append({
            "analyst": analyst,
            "text": note_text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        details["analyst_notes"] = analyst_notes
        alert_db.details = details
        alert_repo.update_alert(alert_db)
        schema = alert_db.to_schema()
        ws_manager.dispatch("alert.updated", schema.model_dump(mode="json"))
        return schema

    def update_case_status(
        self,
        db: Session,
        case_id: str,
        new_status: CaseStatus,
        resolution_notes: Optional[str] = None,
        assigned_to: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        resolution: Optional[str] = None,
    ) -> CaseResult:
        """Validate and apply lifecycle status transition for a SOC incident case."""
        case_repo = CaseRepository(db)
        case_db = case_repo.get_by_case_id(case_id)
        if not case_db:
            raise ValueError(f"Case '{case_id}' not found.")

        current_status = CaseStatus(case_db.status)
        valid_targets = VALID_CASE_TRANSITIONS.get(current_status, [])

        if new_status not in valid_targets:
            raise ValueError(
                f"Invalid case status transition from '{current_status.value}' to '{new_status.value}'. "
                f"Allowed transitions: {[s.value for s in valid_targets]}"
            )

        case_db.status = new_status.value
        if resolution_notes:
            case_db.resolution_notes = resolution_notes
        assigned = assigned_analyst or assigned_to
        if assigned:
            case_db.assigned_to = assigned
        if resolution:
            case_db.resolution = resolution

        case_repo.update_case(case_db)
        schema = case_db.to_schema()
        ws_manager.dispatch("case.status_changed", schema.model_dump(mode="json"))
        return schema

    def assign_case(self, db: Session, case_id: str, analyst: str) -> CaseResult:
        """Assign a SOC analyst to an incident case."""
        case_repo = CaseRepository(db)
        case_db = case_repo.get_by_case_id(case_id)
        if not case_db:
            raise ValueError(f"Case '{case_id}' not found.")

        case_db.assigned_to = analyst
        case_repo.update_case(case_db)
        schema = case_db.to_schema()
        ws_manager.dispatch("case.updated", schema.model_dump(mode="json"))
        return schema

    def add_case_note(self, db: Session, case_id: str, analyst: str, note_text: str) -> CaseResult:
        """Add an analyst note to an incident case."""
        case_repo = CaseRepository(db)
        case_db = case_repo.get_by_case_id(case_id)
        if not case_db:
            raise ValueError(f"Case '{case_id}' not found.")

        evidence_summary = case_db.evidence_summary or {}
        notes = evidence_summary.get("analyst_notes", [])
        notes.append({
            "analyst": analyst,
            "text": note_text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        evidence_summary["analyst_notes"] = notes
        case_db.evidence_summary = evidence_summary
        case_repo.update_case(case_db)
        schema = case_db.to_schema()
        ws_manager.dispatch("case.updated", schema.model_dump(mode="json"))
        return schema

    def get_case_timeline(self, db: Session, case_id: str) -> List[TimelineItem]:
        """Aggregate chronological investigation timeline items linked to this case."""
        case_repo = CaseRepository(db)
        alert_repo = AlertRepository(db)
        risk_repo = RiskRepository(db)

        case_db = case_repo.get_by_case_id(case_id)
        if not case_db:
            raise ValueError(f"Case '{case_id}' not found.")

        items: List[TimelineItem] = []

        # 1. Case Opened event
        items.append(
            TimelineItem(
                timestamp=case_db.opened_at,
                evidence_type="CASE_OPENED",
                source="CASE_ENGINE",
                severity=case_db.severity,
                risk_score=case_db.total_risk_score,
                explanation=f"Incident case opened: {case_db.title}",
                details={"status": case_db.status, "alert_count": case_db.alert_count},
            )
        )

        # 2. Correlated Alerts
        alerts = alert_repo.get_alerts(case_id=case_id, limit=200)
        for a in alerts:
            items.append(
                TimelineItem(
                    timestamp=a.timestamp,
                    evidence_type="ALERT",
                    source="ALERT_ENGINE",
                    severity=a.severity,
                    risk_score=a.risk_score,
                    explanation=f"{a.title}: {a.explanation}",
                    related_alert_id=a.alert_id,
                    related_risk_id=a.risk_id,
                    related_fusion_id=a.fusion_id,
                    details={
                        "occurrence_count": a.occurrence_count,
                        "evidence_strength": a.evidence_strength,
                        "detectors": a.contributing_detectors,
                    },
                )
            )

            # Link underlying risk score breakdown
            risk_db = risk_repo.get_by_risk_id(a.risk_id)
            if risk_db:
                items.append(
                    TimelineItem(
                        timestamp=risk_db.timestamp,
                        evidence_type="RISK_EVALUATION",
                        source="RISK_ENGINE",
                        severity=risk_db.severity,
                        risk_score=risk_db.final_score,
                        explanation=(
                            f"Risk evaluated {risk_db.final_score:.1f}/100 "
                            f"(Stat: {risk_db.statistical_contribution:.1f}, "
                            f"IF: {risk_db.isolation_forest_contribution:.1f}, "
                            f"Clustering: {risk_db.clustering_contribution:.1f}, "
                            f"Rules: {risk_db.rules_contribution:.1f}, "
                            f"Corr: {risk_db.correlation_contribution:.1f})"
                        ),
                        related_alert_id=a.alert_id,
                        related_risk_id=risk_db.risk_id,
                        related_fusion_id=risk_db.source_fusion_id,
                        details={"contributor_breakdown": risk_db.contributor_breakdown},
                    )
                )

        # 3. Status changes recorded in details
        status_notes = (case_db.evidence_summary or {}).get("status_notes", [])
        for note in status_notes:
            ts_str = note.get("timestamp")
            ts = datetime.fromisoformat(ts_str) if ts_str else case_db.updated_at
            items.append(
                TimelineItem(
                    timestamp=ts,
                    evidence_type="STATUS_CHANGE",
                    source="SOC_ANALYST",
                    explanation=f"Status changed from {note.get('from')} to {note.get('to')}: {note.get('notes', '')}",
                    details=note,
                )
            )

        # Sort chronologically
        items.sort(key=lambda x: x.timestamp)
        return items


# Global singleton service
alert_case_service = AlertCaseService()
