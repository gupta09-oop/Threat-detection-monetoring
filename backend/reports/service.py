"""Service layer for generating structured Threat Intelligence Reports from live alert and case data.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.models.alert import AlertDB
from backend.models.case import CaseDB
from backend.reports.schemas import (
    AffectedEntities,
    DetectionEvidence,
    IncidentInfo,
    IncidentTimelineEvent,
    InvestigationReport,
    ReportHeader,
    ResolutionReport,
    RiskBreakdownReport,
    RiskComponentScore,
    RiskSummary,
    ThreatReportResponse,
)

logger = logging.getLogger(__name__)


def _get_recommendations_for_attack(attack_type: str) -> List[str]:
    t = attack_type.lower()
    if "brute" in t or "distributed" in t:
        return [
            "1. Validate the targeted accounts.",
            "2. Review source IP diversity.",
            "3. Confirm the distributed low-and-slow pattern.",
            "4. Review failed login activity.",
            "5. Check affected sessions and successful authentications.",
            "6. Apply appropriate authentication protections.",
            "7. Document the investigation.",
            "8. Resolve or escalate the incident.",
        ]
    elif "credential" in t or "stuffing" in t:
        return [
            "1. Identify affected accounts.",
            "2. Review successful authentications.",
            "3. Inspect unseen devices.",
            "4. Check geographic anomalies.",
            "5. Review account/session activity.",
            "6. Apply appropriate account protection.",
            "7. Investigate potential credential reuse.",
            "8. Document and resolve/escalate.",
        ]
    elif "port" in t or "scan" in t or "recon" in t:
        return [
            "1. Identify scanner IPs.",
            "2. Review destination systems.",
            "3. Inspect targeted ports.",
            "4. Review refused/timeout ratios.",
            "5. Identify exposed services.",
            "6. Check related network activity.",
            "7. Determine whether reconnaissance preceded another attack.",
            "8. Document and resolve/escalate.",
        ]
    else:
        return [
            "1. Verify the anomalous entity activity.",
            "2. Correlate with historical baseline metrics.",
            "3. Inspect related network and authentication events.",
            "4. Review detector contributor breakdown.",
            "5. Document findings and triage severity.",
            "6. Mitigate risk and resolve/escalate.",
        ]


class ThreatReportService:
    """Generates comprehensive, explainable threat incident reports."""

    def generate_report(
        self,
        db: Session,
        incident_type: str,
        incident_id: str,
    ) -> ThreatReportResponse:
        """Assembles a full ThreatReportResponse from genuine alert or case records."""
        itype = incident_type.lower().strip()

        if itype == "case":
            return self._generate_case_report(db, incident_id)
        else:
            return self._generate_alert_report(db, incident_id)

    def _generate_alert_report(self, db: Session, alert_id: str) -> ThreatReportResponse:
        alert = db.query(AlertDB).filter(AlertDB.alert_id == alert_id).first()
        if not alert:
            raise ValueError(f"Alert with ID '{alert_id}' not found.")

        schema = alert.to_schema()
        details = schema.details or {}
        breakdown = schema.contributor_breakdown

        attack_type = (
            details.get("attack_type")
            or details.get("scenario")
            or details.get("attack_classification")
            or ("Distributed Brute Force" if "brute" in schema.title.lower() else "Multi-Detector Behavioral Anomaly")
        )

        recommendations = _get_recommendations_for_attack(attack_type)

        # Build timeline events
        timeline_events: List[IncidentTimelineEvent] = [
            IncidentTimelineEvent(
                timestamp=schema.created_at.isoformat(),
                evidence_type="ALERT_CREATED",
                source="ALERT_ENGINE",
                severity=schema.severity.value if hasattr(schema.severity, "value") else str(schema.severity),
                risk_score=schema.risk_score,
                explanation=schema.explanation,
            )
        ]

        # Correlated case if available
        if schema.case_id:
            case = db.query(CaseDB).filter(CaseDB.case_id == schema.case_id).first()
            if case:
                timeline_events.insert(
                    0,
                    IncidentTimelineEvent(
                        timestamp=case.opened_at.isoformat(),
                        evidence_type="CASE_OPENED",
                        source="INCIDENT_CORRELATOR",
                        severity=case.severity,
                        risk_score=case.total_risk_score,
                        explanation=case.summary,
                    ),
                )

        # Analyst notes
        notes = details.get("analyst_notes", [])
        if not notes and schema.resolution_notes:
            notes = [
                {
                    "analyst": schema.assigned_analyst or "SOC Analyst",
                    "timestamp": schema.updated_at.isoformat(),
                    "text": schema.resolution_notes,
                }
            ]

        # Extract entities
        source_ips = details.get("source_ips", [])
        if not source_ips and schema.entity_type.value == "IP":
            source_ips = [schema.entity_id]

        accounts = details.get("accounts", [])
        if not accounts and schema.entity_type.value == "USER":
            accounts = [schema.entity_id]

        stat = getattr(breakdown, "statistical", None)
        iso = getattr(breakdown, "isolation_forest", None)
        clust = getattr(breakdown, "behavioral_clustering", None)
        rules = getattr(breakdown, "deterministic_rules", None)
        corr = getattr(breakdown, "cross_entity_correlation", None)

        return ThreatReportResponse(
            report_header=ReportHeader(),
            incident_info=IncidentInfo(
                incident_type="ALERT",
                incident_id=schema.alert_id,
                title=schema.title,
                attack_classification=str(attack_type).upper(),
                severity=schema.severity.value if hasattr(schema.severity, "value") else str(schema.severity),
                status=schema.status.value if hasattr(schema.status, "value") else str(schema.status),
                assigned_analyst=schema.assigned_analyst,
                resolution=schema.resolution,
                resolution_notes=schema.resolution_notes,
            ),
            risk_summary=RiskSummary(
                risk_score=schema.risk_score,
                severity=schema.severity.value if hasattr(schema.severity, "value") else str(schema.severity),
                evidence_strength=str(schema.evidence_strength),
            ),
            risk_breakdown=RiskBreakdownReport(
                statistical_baseline=RiskComponentScore(
                    score=getattr(stat, "score", 0.0),
                    maximum=25.0,
                    explanation=getattr(stat, "explanation", "Baseline features"),
                ),
                isolation_forest=RiskComponentScore(
                    score=getattr(iso, "score", 0.0),
                    maximum=25.0,
                    explanation=getattr(iso, "explanation", "Vector deviations"),
                ),
                behavioral_clustering=RiskComponentScore(
                    score=getattr(clust, "score", 0.0),
                    maximum=20.0,
                    explanation=getattr(clust, "explanation", "Cluster distance"),
                ),
                deterministic_rules=RiskComponentScore(
                    score=getattr(rules, "score", 0.0),
                    maximum=20.0,
                    explanation=getattr(rules, "explanation", "Deterministic rules"),
                ),
                cross_entity_correlation=RiskComponentScore(
                    score=getattr(corr, "score", 0.0),
                    maximum=10.0,
                    explanation=getattr(corr, "explanation", "Multi-detector correlation agreement"),
                ),
                final_score=schema.risk_score,
            ),
            detection_evidence=DetectionEvidence(
                contributing_detectors=schema.contributing_detectors,
                rationale=schema.explanation,
                detector_states={
                    "statistical_baseline": getattr(stat, "score", 0.0) > 0,
                    "isolation_forest": getattr(iso, "score", 0.0) > 0,
                    "behavioral_clustering": getattr(clust, "score", 0.0) > 0,
                    "deterministic_rules": getattr(rules, "score", 0.0) > 0,
                    "cross_entity_correlation": getattr(corr, "score", 0.0) > 0,
                },
                anomalous_features=details.get("anomalous_features", []),
            ),
            affected_entities=AffectedEntities(
                target_entity_id=schema.entity_id,
                entity_type=schema.entity_type.value if hasattr(schema.entity_type, "value") else str(schema.entity_type),
                source_ips=source_ips,
                accounts=accounts,
                devices=details.get("devices", []),
                destination_ips=details.get("destination_ips", []),
                ports=[str(p) for p in details.get("ports", [])],
            ),
            incident_timeline=timeline_events,
            investigation=InvestigationReport(
                assigned_analyst=schema.assigned_analyst,
                analyst_notes=notes,
                checklist_guidance=recommendations,
            ),
            resolution=ResolutionReport(
                resolution=schema.resolution,
                resolution_notes=schema.resolution_notes,
                resolved_by=schema.assigned_analyst,
                final_status=schema.status.value if hasattr(schema.status, "value") else str(schema.status),
            ),
            recommendations=recommendations,
        )

    def _generate_case_report(self, db: Session, case_id: str) -> ThreatReportResponse:
        case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
        if not case:
            raise ValueError(f"Case with ID '{case_id}' not found.")

        schema = case.to_schema()
        affected = schema.affected_entities or {}

        # Fetch correlated alerts
        from backend.repositories.alert_repository import AlertRepository
        alerts = AlertRepository(db).get_alerts(case_id=case_id, limit=50)

        # Extract attack pattern
        attack_type = "Multi-Stage Behavioral Incident"
        if "brute" in schema.title.lower():
            attack_type = "Distributed Brute Force"
        elif "credential" in schema.title.lower() or "stuffing" in schema.title.lower():
            attack_type = "Credential Stuffing"
        elif "port" in schema.title.lower() or "scan" in schema.title.lower():
            attack_type = "Port Scan / Recon"

        recommendations = _get_recommendations_for_attack(attack_type)

        # Get risk breakdown from the top alert or default
        top_alert = max(alerts, key=lambda a: a.risk_score, default=None)
        breakdown = top_alert.to_schema().contributor_breakdown if top_alert else None

        stat = getattr(breakdown, "statistical", None)
        iso = getattr(breakdown, "isolation_forest", None)
        clust = getattr(breakdown, "behavioral_clustering", None)
        rules = getattr(breakdown, "deterministic_rules", None)
        corr = getattr(breakdown, "cross_entity_correlation", None)

        timeline_events = [
            IncidentTimelineEvent(
                timestamp=schema.opened_at.isoformat(),
                evidence_type="CASE_OPENED",
                source="CORRELATOR",
                severity=schema.severity.value if hasattr(schema.severity, "value") else str(schema.severity),
                risk_score=schema.total_risk_score,
                explanation=schema.summary,
            )
        ]

        for alt in alerts:
            alt_sch = alt.to_schema()
            timeline_events.append(
                IncidentTimelineEvent(
                    timestamp=alt_sch.created_at.isoformat(),
                    evidence_type="ALERT_CORRELATED",
                    source="ALERT_ENGINE",
                    severity=alt_sch.severity.value if hasattr(alt_sch.severity, "value") else str(alt_sch.severity),
                    risk_score=alt_sch.risk_score,
                    explanation=alt_sch.explanation,
                )
            )

        analyst = schema.assigned_analyst or schema.assigned_to
        notes = []
        if schema.resolution_notes:
            notes.append({
                "analyst": analyst or "SOC Analyst",
                "timestamp": schema.updated_at.isoformat(),
                "text": schema.resolution_notes,
            })

        return ThreatReportResponse(
            report_header=ReportHeader(),
            incident_info=IncidentInfo(
                incident_type="CASE",
                incident_id=schema.case_id,
                title=schema.title,
                attack_classification=attack_type.upper(),
                severity=schema.severity.value if hasattr(schema.severity, "value") else str(schema.severity),
                status=schema.status.value if hasattr(schema.status, "value") else str(schema.status),
                assigned_analyst=analyst,
                resolution=schema.resolution,
                resolution_notes=schema.resolution_notes,
            ),
            risk_summary=RiskSummary(
                risk_score=schema.total_risk_score,
                severity=schema.severity.value if hasattr(schema.severity, "value") else str(schema.severity),
                evidence_strength="STRONG" if schema.total_risk_score >= 65 else "MODERATE",
            ),
            risk_breakdown=RiskBreakdownReport(
                statistical_baseline=RiskComponentScore(
                    score=getattr(stat, "score", 0.0),
                    maximum=25.0,
                    explanation=getattr(stat, "explanation", "Aggregated statistical baseline"),
                ),
                isolation_forest=RiskComponentScore(
                    score=getattr(iso, "score", 0.0),
                    maximum=25.0,
                    explanation=getattr(iso, "explanation", "Aggregated Isolation Forest score"),
                ),
                behavioral_clustering=RiskComponentScore(
                    score=getattr(clust, "score", 0.0),
                    maximum=20.0,
                    explanation=getattr(clust, "explanation", "Aggregated cluster deviation"),
                ),
                deterministic_rules=RiskComponentScore(
                    score=getattr(rules, "score", 0.0),
                    maximum=20.0,
                    explanation=getattr(rules, "explanation", "Deterministic rules score"),
                ),
                cross_entity_correlation=RiskComponentScore(
                    score=getattr(corr, "score", 0.0),
                    maximum=10.0,
                    explanation=getattr(corr, "explanation", "Cross-entity correlation"),
                ),
                final_score=schema.total_risk_score,
            ),
            detection_evidence=DetectionEvidence(
                contributing_detectors=top_alert.to_schema().contributing_detectors if top_alert else ["cross_entity_correlation"],
                rationale=schema.summary,
                detector_states={
                    "statistical_baseline": getattr(stat, "score", 0.0) > 0,
                    "isolation_forest": getattr(iso, "score", 0.0) > 0,
                    "behavioral_clustering": getattr(clust, "score", 0.0) > 0,
                    "deterministic_rules": getattr(rules, "score", 0.0) > 0,
                    "cross_entity_correlation": getattr(corr, "score", 0.0) > 0,
                },
                anomalous_features=[],
            ),
            affected_entities=AffectedEntities(
                target_entity_id=schema.entity_id,
                entity_type=schema.entity_type.value if hasattr(schema.entity_type, "value") else str(schema.entity_type),
                source_ips=affected.get("source_ips", []),
                accounts=affected.get("accounts", []),
                devices=affected.get("devices", []),
                destination_ips=affected.get("destination_ips", []),
                ports=[str(p) for p in affected.get("ports", [])],
            ),
            incident_timeline=timeline_events,
            investigation=InvestigationReport(
                assigned_analyst=analyst,
                analyst_notes=notes,
                checklist_guidance=recommendations,
            ),
            resolution=ResolutionReport(
                resolution=schema.resolution,
                resolution_notes=schema.resolution_notes,
                resolved_by=analyst,
                final_status=schema.status.value if hasattr(schema.status, "value") else str(schema.status),
            ),
            recommendations=recommendations,
        )


threat_report_service = ThreatReportService()
