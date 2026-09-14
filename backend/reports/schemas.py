"""Pydantic schemas for Threat Intelligence / Security Incident Reports.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class ReportExportRequest(BaseModel):
    """Request payload to generate a threat incident report."""
    model_config = ConfigDict(extra="ignore")

    incident_type: str = Field(default="alert", description="'alert' or 'case'")
    incident_id: str = Field(..., description="UUID identifier of the target alert or case")
    format: str = Field(default="json", description="'json' or 'pdf'")


class ReportHeader(BaseModel):
    platform: str = "SH4D0W_ST4LK3R"
    title: str = "Threat Intelligence / Security Incident Report"
    report_id: str = Field(default_factory=lambda: f"REP-{uuid.uuid4().hex[:8].upper()}")
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IncidentInfo(BaseModel):
    incident_type: str
    incident_id: str
    title: str
    attack_classification: str
    severity: str
    status: str
    assigned_analyst: Optional[str] = None
    resolution: Optional[str] = None
    resolution_notes: Optional[str] = None


class RiskSummary(BaseModel):
    risk_score: float
    max_score: float = 100.0
    severity: str
    evidence_strength: str


class RiskComponentScore(BaseModel):
    score: float
    maximum: float
    explanation: str


class RiskBreakdownReport(BaseModel):
    statistical_baseline: RiskComponentScore
    isolation_forest: RiskComponentScore
    behavioral_clustering: RiskComponentScore
    deterministic_rules: RiskComponentScore
    cross_entity_correlation: RiskComponentScore
    final_score: float


class DetectionEvidence(BaseModel):
    contributing_detectors: List[str] = Field(default_factory=list)
    rationale: str
    detector_states: Dict[str, Any] = Field(default_factory=dict)
    anomalous_features: List[Dict[str, Any]] = Field(default_factory=list)


class AffectedEntities(BaseModel):
    target_entity_id: str
    entity_type: str
    source_ips: List[str] = Field(default_factory=list)
    accounts: List[str] = Field(default_factory=list)
    devices: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    ports: List[str] = Field(default_factory=list)


class IncidentTimelineEvent(BaseModel):
    timestamp: str
    evidence_type: str
    source: str
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    explanation: str


class InvestigationReport(BaseModel):
    assigned_analyst: Optional[str] = None
    analyst_notes: List[Dict[str, Any]] = Field(default_factory=list)
    checklist_guidance: List[str] = Field(default_factory=list)


class ResolutionReport(BaseModel):
    resolution: Optional[str] = None
    resolution_notes: Optional[str] = None
    resolved_by: Optional[str] = None
    final_status: str


class ThreatReportResponse(BaseModel):
    """Complete forensic threat incident report schema."""
    model_config = ConfigDict(extra="ignore")

    report_header: ReportHeader
    incident_info: IncidentInfo
    risk_summary: RiskSummary
    risk_breakdown: RiskBreakdownReport
    detection_evidence: DetectionEvidence
    affected_entities: AffectedEntities
    incident_timeline: List[IncidentTimelineEvent] = Field(default_factory=list)
    investigation: InvestigationReport
    resolution: ResolutionReport
    recommendations: List[str] = Field(default_factory=list)
