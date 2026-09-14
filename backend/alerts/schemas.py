"""Pydantic schemas and enums for Phase 10 Alerting, Deduplication, and Case Management.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from backend.features.schemas import EntityType
from backend.risk.schemas import ContributorBreakdown, RiskSeverity


class AlertStatus(str, Enum):
    """Lifecycle states for security alerts."""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class CaseStatus(str, Enum):
    """Investigation lifecycle states for SOC incident cases."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


# Valid state transitions
VALID_ALERT_TRANSITIONS: Dict[AlertStatus, List[AlertStatus]] = {
    AlertStatus.NEW: [AlertStatus.ACKNOWLEDGED, AlertStatus.ESCALATED, AlertStatus.CLOSED],
    AlertStatus.ACKNOWLEDGED: [AlertStatus.ESCALATED, AlertStatus.CLOSED],
    AlertStatus.ESCALATED: [AlertStatus.CLOSED],
    AlertStatus.CLOSED: [],  # Closed is terminal
}

VALID_CASE_TRANSITIONS: Dict[CaseStatus, List[CaseStatus]] = {
    CaseStatus.OPEN: [CaseStatus.INVESTIGATING, CaseStatus.RESOLVED, CaseStatus.DISMISSED],
    CaseStatus.INVESTIGATING: [CaseStatus.RESOLVED, CaseStatus.DISMISSED],
    CaseStatus.RESOLVED: [],  # Resolved is terminal
    CaseStatus.DISMISSED: [],  # Dismissed is terminal
}


class AlertResult(BaseModel):
    """Contract for a generated or persisted security alert."""
    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique alert identifier")
    risk_id: str = Field(..., description="Reference to underlying Threat Risk Score evaluation")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of the alert")
    entity_type: EntityType = Field(..., description="Target entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Target entity identifier")
    source_type: Optional[str] = Field(default="BEHAVIORAL", description="Source category of telemetry/evidence")
    severity: RiskSeverity = Field(..., description="Alert severity: MEDIUM, HIGH, CRITICAL")
    risk_score: float = Field(..., ge=40.0, le=100.0, description="Evaluated Threat Risk Score (>= 40)")
    title: str = Field(..., description="Human-readable contextual alert title")
    summary: str = Field(..., description="Concise summary of detected anomalous behavior")
    explanation: str = Field(..., description="Detailed analyst security explanation")
    contributor_breakdown: ContributorBreakdown = Field(..., description="Full dimensional risk component breakdown")
    evidence_strength: str = Field(..., description="Independent detector agreement: LOW, MODERATE, STRONG, CONCLUSIVE")
    contributing_detectors: List[str] = Field(default_factory=list, description="Detector families flagging anomalous evidence")
    fusion_id: Optional[str] = Field(default=None, description="Reference to source fusion evaluation")
    snapshot_id: Optional[str] = Field(default=None, description="Reference to feature snapshot")
    case_id: Optional[str] = Field(default=None, description="Reference to correlated SOC incident case")
    status: AlertStatus = Field(default=AlertStatus.NEW, description="Lifecycle state of alert")
    occurrence_count: int = Field(default=1, ge=1, description="Deduplication occurrence counter")
    dedup_key: str = Field(..., description="Deduplication cluster key")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assigned_analyst: Optional[str] = Field(default=None, description="Assigned SOC analyst")
    resolution: Optional[str] = Field(default=None, description="Resolution category: Confirmed Threat, False Positive, Benign Activity, Other")
    resolution_notes: Optional[str] = Field(default=None, description="Resolution rationale")
    details: Dict[str, Any] = Field(default_factory=dict, description="Contextual investigation metadata")


class AlertUpdateStatusRequest(BaseModel):
    """Payload to update an alert's lifecycle status."""
    status: AlertStatus = Field(..., description="New target lifecycle state")
    notes: Optional[str] = Field(default=None, description="Analyst rationale or notes for status change")
    assigned_analyst: Optional[str] = Field(default=None, description="Assigned analyst")
    resolution: Optional[str] = Field(default=None, description="Resolution classification")


class AssignAnalystRequest(BaseModel):
    """Payload to assign a SOC analyst."""
    analyst: str = Field(..., description="Name of the assigned analyst (Arjun Mehta, Priya Sharma, Rahul Verma, Neha Kapoor)")


class AddNoteRequest(BaseModel):
    """Payload to record an investigation note."""
    analyst: str = Field(default="Priya Sharma", description="Authoring analyst")
    text: str = Field(..., min_length=1, description="Analyst investigation note content")

class ResolveRequest(BaseModel):
    """Payload to close/resolve an alert or incident case."""
    resolution: str = Field(
        ...,
        description="Resolution: Confirmed Threat, False Positive, Benign Activity, Other"
    )
    analyst: str = Field(
        ...,
        description="Analyst completing the resolution"
    )
    notes: Optional[str] = Field(
        default=None,
        description="Analyst closure explanation"
    )


class AlertEvaluateRequest(BaseModel):
    """Request payload to create or evaluate alerts directly from a risk evaluation."""
    risk_id: Optional[str] = Field(default=None, description="Evaluate alert from existing RiskScoreDB ID")
    snapshot_id: Optional[str] = Field(default=None, description="Evaluate alert from snapshot ID")
    persist: bool = Field(default=True, description="Whether to persist alert in database")


class TimelineItem(BaseModel):
    """Structured investigation timeline item for SOC analysis."""
    model_config = ConfigDict(extra="ignore")

    item_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(..., description="UTC timestamp of the timeline event")
    evidence_type: str = Field(..., description="ALERT, RISK_EVALUATION, FUSION, DETECTOR_ANOMALY, STATUS_CHANGE")
    source: str = Field(..., description="Subsystem or detection component generating this evidence")
    severity: Optional[str] = Field(default=None, description="Severity if applicable: LOW, MEDIUM, HIGH, CRITICAL")
    risk_score: Optional[float] = Field(default=None, description="Associated risk score if applicable")
    explanation: str = Field(..., description="Security explanation or event narrative")
    related_alert_id: Optional[str] = Field(default=None)
    related_risk_id: Optional[str] = Field(default=None)
    related_fusion_id: Optional[str] = Field(default=None)
    details: Dict[str, Any] = Field(default_factory=dict)


class CaseResult(BaseModel):
    """Contract for a correlated SOC incident case."""
    model_config = ConfigDict(extra="ignore")

    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique case identifier")
    entity_type: EntityType = Field(..., description="Primary entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Primary entity identifier")
    title: str = Field(..., description="Analyst incident title")
    summary: str = Field(..., description="Executive summary of the case")
    opened_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: CaseStatus = Field(default=CaseStatus.OPEN, description="Incident lifecycle state")
    severity: RiskSeverity = Field(..., description="Incident severity level")
    total_risk_score: float = Field(..., ge=0.0, le=100.0, description="Bounded 0-100 incident risk score")
    alert_count: int = Field(default=1, ge=1, description="Total correlated alerts linked to case")
    kill_chain_stages: List[str] = Field(default_factory=list, description="Preserved detected kill-chain stages")
    affected_entities: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Aggregated entity references (e.g. source_ips, accounts, devices, ports)",
    )
    evidence_summary: Dict[str, Any] = Field(default_factory=dict, description="Structured evidence summary")
    risk_history: List[Dict[str, Any]] = Field(default_factory=list, description="Historical score progression")
    assigned_to: Optional[str] = Field(default=None, description="Assigned SOC analyst identifier")
    assigned_analyst: Optional[str] = Field(default=None, description="Assigned SOC analyst")
    resolution: Optional[str] = Field(default=None, description="Resolution category: Confirmed Threat, False Positive, Benign Activity, Other")
    resolution_notes: Optional[str] = Field(default=None, description="Closure and resolution notes")


class CaseCreateRequest(BaseModel):
    """Payload to create an incident case manually."""
    entity_type: EntityType = Field(...)
    entity_id: str = Field(...)
    title: str = Field(...)
    summary: str = Field(...)
    severity: RiskSeverity = Field(default=RiskSeverity.MEDIUM)
    total_risk_score: float = Field(default=50.0, ge=0.0, le=100.0)
    assigned_to: Optional[str] = Field(default=None)
    assigned_analyst: Optional[str] = Field(default=None)


class CaseUpdateStatusRequest(BaseModel):
    """Payload to update an incident case lifecycle status."""
    status: CaseStatus = Field(..., description="New target lifecycle state")
    resolution_notes: Optional[str] = Field(default=None, description="Closure or transition notes")
    assigned_to: Optional[str] = Field(default=None, description="Reassign analyst")
    assigned_analyst: Optional[str] = Field(default=None, description="Reassign analyst")
    resolution: Optional[str] = Field(default=None, description="Resolution classification")
