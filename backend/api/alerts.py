"""API endpoints for Security Alerts.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.alerts.schemas import (
    AddNoteRequest,
    AlertEvaluateRequest,
    AlertResult,
    AlertUpdateStatusRequest,
    AssignAnalystRequest,
    ResolveRequest,
)
from backend.alerts.service import alert_case_service
from backend.db.session import get_db
from backend.repositories.alert_repository import AlertRepository
from backend.repositories.risk_repository import RiskRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["Alerting & Deduplication"])


@router.post(
    "/evaluate",
    response_model=Optional[AlertResult],
    summary="Evaluate Alert from Risk Evaluation",
    description="Evaluates a risk score result and generates or deduplicates a security alert if Risk Score >= 40.0.",
)
def evaluate_alert(
    req: AlertEvaluateRequest,
    db: Session = Depends(get_db),
) -> Optional[AlertResult]:
    """Evaluate and trigger an alert from a risk result or snapshot."""
    if req.risk_id:
        risk_repo = RiskRepository(db)
        risk_db = risk_repo.get_by_risk_id(req.risk_id)
        if not risk_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Risk score evaluation '{req.risk_id}' not found.",
            )
        risk_res = risk_db.to_schema()
        return alert_case_service.process_risk_score(
            risk_result=risk_res,
            db=db,
            persist=req.persist,
        )

    if req.snapshot_id:
        from backend.risk.service import risk_scoring_service
        risk_res = risk_scoring_service.evaluate_snapshot(
            db=db,
            snapshot_id=req.snapshot_id,
            persist=True,
        )
        return alert_case_service.process_risk_score(
            risk_result=risk_res,
            db=db,
            persist=req.persist,
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must specify either 'risk_id' or 'snapshot_id' to evaluate alert.",
    )


@router.get(
    "",
    response_model=List[AlertResult],
    summary="Query Security Alerts",
    description="Retrieve persisted security alerts with filtering and pagination.",
)
def get_alerts(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=100, ge=1, le=500, description="Max results to return"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity identifier"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(default=None, description="Filter by status: NEW, ACKNOWLEDGED, ESCALATED, CLOSED"),
    case_id: Optional[str] = Query(default=None, description="Filter by correlated case UUID"),
    db: Session = Depends(get_db),
) -> List[AlertResult]:
    """Query persisted alerts."""
    repo = AlertRepository(db)
    results = repo.get_alerts(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        status=status,
        case_id=case_id,
    )
    return [r.to_schema() for r in results]


@router.get(
    "/{alert_id}",
    response_model=AlertResult,
    summary="Get Alert by ID",
    description="Retrieve a specific security alert by UUID.",
)
def get_alert_by_id(
    alert_id: str,
    db: Session = Depends(get_db),
) -> AlertResult:
    """Retrieve a specific alert by UUID."""
    repo = AlertRepository(db)
    alert_db = repo.get_by_alert_id(alert_id)
    if not alert_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    return alert_db.to_schema()


@router.patch(
    "/{alert_id}/status",
    response_model=AlertResult,
    summary="Update Alert Status",
    description="Updates the lifecycle status of an alert with state-machine transition validation.",
)
def update_alert_status(
    alert_id: str,
    req: AlertUpdateStatusRequest,
    db: Session = Depends(get_db),
) -> AlertResult:
    """Transition alert status through valid lifecycle states."""
    try:
        return alert_case_service.update_alert_status(
            db=db,
            alert_id=alert_id,
            new_status=req.status,
            notes=req.notes,
            assigned_analyst=req.assigned_analyst,
            resolution=req.resolution,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.patch(
    "/{alert_id}/assign",
    response_model=AlertResult,
    summary="Assign Analyst to Alert",
    description="Assigns a synthetic SOC analyst to an alert.",
)
def assign_alert(
    alert_id: str,
    req: AssignAnalystRequest,
    db: Session = Depends(get_db),
) -> AlertResult:
    """Assign an analyst to this alert."""
    try:
        return alert_case_service.assign_alert(db=db, alert_id=alert_id, analyst=req.analyst)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post(
    "/{alert_id}/notes",
    response_model=AlertResult,
    summary="Add Analyst Note to Alert",
    description="Appends an investigation note to the alert details.",
)
def add_alert_note(
    alert_id: str,
    req: AddNoteRequest,
    db: Session = Depends(get_db),
) -> AlertResult:
    """Record an analyst note on this alert."""
    try:
        return alert_case_service.add_alert_note(
            db=db,
            alert_id=alert_id,
            analyst=req.analyst,
            note_text=req.text,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.patch(
    "/{alert_id}/resolve",
    response_model=AlertResult,
    summary="Resolve and Close Alert",
    description="Closes an alert with a resolution classification and analyst notes.",
)
def resolve_alert(
    alert_id: str,
    req: ResolveRequest,
    db: Session = Depends(get_db),
) -> AlertResult:
    """Close and resolve an alert."""
    try:
        from backend.alerts.schemas import AlertStatus
        return alert_case_service.update_alert_status(
            db=db,
            alert_id=alert_id,
            new_status=AlertStatus.CLOSED,
            notes=req.notes,
            resolution=req.resolution,
            assigned_analyst=req.analyst,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
