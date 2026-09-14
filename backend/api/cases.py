"""API endpoints for SOC Incident Cases.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.alerts.schemas import (
    AddNoteRequest,
    AlertResult,
    AssignAnalystRequest,
    CaseCreateRequest,
    CaseResult,
    CaseStatus,
    CaseUpdateStatusRequest,
    ResolveRequest,
    TimelineItem,
)
from backend.alerts.service import alert_case_service
from backend.db.session import get_db
from backend.repositories.alert_repository import AlertRepository
from backend.repositories.case_repository import CaseRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cases", tags=["SOC Incident Cases"])


@router.post(
    "",
    response_model=CaseResult,
    status_code=status.HTTP_201_CREATED,
    summary="Create Incident Case",
    description="Manually creates a new SOC incident case.",
)
def create_case(
    req: CaseCreateRequest,
    db: Session = Depends(get_db),
) -> CaseResult:
    """Manually create an incident case."""
    import uuid
    from datetime import datetime, timezone

    repo = CaseRepository(db)
    now = datetime.now(timezone.utc)
    case_res = CaseResult(
        case_id=str(uuid.uuid4()),
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        title=req.title,
        summary=req.summary,
        opened_at=now,
        updated_at=now,
        status=CaseStatus.OPEN,
        severity=req.severity,
        total_risk_score=req.total_risk_score,
        alert_count=1,
        assigned_to=req.assigned_to or req.assigned_analyst,
        assigned_analyst=req.assigned_analyst or req.assigned_to,
    )
    repo.create_case(case_res)
    return case_res


@router.get(
    "",
    response_model=List[CaseResult],
    summary="Query Incident Cases",
    description="Retrieve persisted incident cases with filtering and pagination.",
)
def get_cases(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=100, ge=1, le=500, description="Max results to return"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity identifier"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(default=None, description="Filter by status: OPEN, INVESTIGATING, RESOLVED, DISMISSED"),
    db: Session = Depends(get_db),
) -> List[CaseResult]:
    """Query persisted cases."""
    repo = CaseRepository(db)
    results = repo.get_cases(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        status=status,
    )
    return [r.to_schema() for r in results]


@router.get(
    "/{case_id}",
    response_model=CaseResult,
    summary="Get Case by ID",
    description="Retrieve a specific incident case by UUID.",
)
def get_case_by_id(
    case_id: str,
    db: Session = Depends(get_db),
) -> CaseResult:
    """Retrieve a specific case by UUID."""
    repo = CaseRepository(db)
    case_db = repo.get_by_case_id(case_id)
    if not case_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    return case_db.to_schema()


@router.patch(
    "/{case_id}/status",
    response_model=CaseResult,
    summary="Update Case Status",
    description="Updates the lifecycle status of an incident case with transition validation.",
)
def update_case_status(
    case_id: str,
    req: CaseUpdateStatusRequest,
    db: Session = Depends(get_db),
) -> CaseResult:
    """Transition case status through valid lifecycle states."""
    try:
        return alert_case_service.update_case_status(
            db=db,
            case_id=case_id,
            new_status=req.status,
            resolution_notes=req.resolution_notes,
            assigned_to=req.assigned_to,
            resolution=req.resolution,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.patch(
    "/{case_id}/assign",
    response_model=CaseResult,
    summary="Assign Analyst to Case",
    description="Assigns a synthetic SOC analyst to an incident case.",
)
def assign_case(
    case_id: str,
    req: AssignAnalystRequest,
    db: Session = Depends(get_db),
) -> CaseResult:
    """Assign an analyst to this incident case."""
    try:
        return alert_case_service.assign_case(db=db, case_id=case_id, analyst=req.analyst)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post(
    "/{case_id}/notes",
    response_model=CaseResult,
    summary="Add Analyst Note to Case",
    description="Appends an investigation note to the incident case.",
)
def add_case_note(
    case_id: str,
    req: AddNoteRequest,
    db: Session = Depends(get_db),
) -> CaseResult:
    """Record an analyst note on this incident case."""
    try:
        return alert_case_service.add_case_note(
            db=db,
            case_id=case_id,
            analyst=req.analyst,
            note_text=req.text,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.patch(
    "/{case_id}/resolve",
    response_model=CaseResult,
    summary="Resolve Incident Case",
    description="Resolves an incident case with a resolution outcome and analyst notes.",
)
def resolve_case(
    case_id: str,
    req: ResolveRequest,
    db: Session = Depends(get_db),
) -> CaseResult:
    """Resolve an incident case."""
    try:
        return alert_case_service.update_case_status(
            db=db,
            case_id=case_id,
            new_status=CaseStatus.RESOLVED,
            resolution_notes=req.notes,
            resolution=req.resolution,
            assigned_to=req.analyst,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/{case_id}/timeline",
    response_model=List[TimelineItem],
    summary="Get Case Investigation Timeline",
    description="Aggregates and retrieves a chronological timeline of alerts, risk evaluations, and analyst actions for this incident.",
)
def get_case_timeline(
    case_id: str,
    db: Session = Depends(get_db),
) -> List[TimelineItem]:
    """Retrieve structured investigation timeline."""
    try:
        return alert_case_service.get_case_timeline(db=db, case_id=case_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.get(
    "/{case_id}/alerts",
    response_model=List[AlertResult],
    summary="Get Case Correlated Alerts",
    description="Retrieves all security alerts correlated with this incident case.",
)
def get_case_alerts(
    case_id: str,
    db: Session = Depends(get_db),
) -> List[AlertResult]:
    """Retrieve all alerts correlated with this case."""
    repo = AlertRepository(db)
    alerts = repo.get_alerts(case_id=case_id, limit=500)
    return [a.to_schema() for a in alerts]
