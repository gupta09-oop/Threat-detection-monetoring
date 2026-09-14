"""API endpoints for Anomaly Fusion, combining independent detector evidence.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.detection.fusion_service import anomaly_fusion_service
from backend.detection.schemas import (
    FusionActiveEvaluateRequest,
    FusionEvaluateRequest,
    FusionResult,
)
from backend.repositories.fusion_repository import FusionRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fusion", tags=["Anomaly Fusion"])


@router.post(
    "/evaluate",
    response_model=FusionResult,
    summary="Evaluate Anomaly Fusion",
    description="Fuses independent detector evidence (Statistical, Isolation Forest, Clustering, and Rules) within a temporal correlation window.",
)
def evaluate_fusion(
    req: FusionEvaluateRequest,
    db: Session = Depends(get_db),
) -> FusionResult:
    """Evaluate independent detector evidence for a feature snapshot or explicit evidence items."""
    if req.snapshot_id:
        result = anomaly_fusion_service.evaluate_snapshot(
            db=db,
            snapshot_id=req.snapshot_id,
            rule_evidence=req.rule_evidence,
            correlation_window_seconds=req.correlation_window_seconds,
            persist=req.persist,
        )
        # If no detector evidence was found in DB for this snapshot, check if explicit evidence was provided
        if result.independent_detector_count == 0 and req.detector_evidence:
            return anomaly_fusion_service.evaluate_evidence(
                evidence_list=req.detector_evidence,
                rule_evidence=req.rule_evidence,
                entity_type=req.entity_type,
                entity_id=req.entity_id,
                snapshot_id=req.snapshot_id,
                window_seconds=req.window_seconds,
                correlation_window_seconds=req.correlation_window_seconds,
                db=db,
                persist=req.persist,
            )
        return result

    if req.detector_evidence or req.rule_evidence:
        return anomaly_fusion_service.evaluate_evidence(
            evidence_list=req.detector_evidence or [],
            rule_evidence=req.rule_evidence,
            entity_type=req.entity_type,
            entity_id=req.entity_id,
            snapshot_id=req.snapshot_id,
            window_seconds=req.window_seconds,
            correlation_window_seconds=req.correlation_window_seconds,
            db=db,
            persist=req.persist,
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide either snapshot_id or detector_evidence/rule_evidence to evaluate fusion.",
    )


@router.post(
    "/evaluate-active",
    response_model=List[FusionResult],
    summary="Evaluate Active Fusion",
    description="Batch evaluates recent active feature snapshots and detector outputs across entities.",
)
def evaluate_active_fusion(
    req: Optional[FusionActiveEvaluateRequest] = None,
    db: Session = Depends(get_db),
) -> List[FusionResult]:
    """Run anomaly fusion across recent active feature snapshots in the system."""
    params = req or FusionActiveEvaluateRequest()
    return anomaly_fusion_service.evaluate_active(
        db=db,
        window_seconds=params.window_seconds,
        limit=params.limit,
        correlation_window_seconds=params.correlation_window_seconds,
    )


@router.get(
    "/results",
    response_model=List[FusionResult],
    summary="Query Fusion Results",
    description="Retrieve historical anomaly fusion evaluations with filtering and pagination.",
)
def get_fusion_results(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=100, ge=1, le=500, description="Max results to return"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST)"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity identifier"),
    evidence_strength: Optional[str] = Query(default=None, description="Filter by strength: LOW, MODERATE, STRONG, CONCLUSIVE"),
    snapshot_id: Optional[str] = Query(default=None, description="Filter by feature snapshot UUID"),
    db: Session = Depends(get_db),
) -> List[FusionResult]:
    """Query persisted fusion results."""
    repo = FusionRepository(db)
    db_results = repo.get_results(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        evidence_strength=evidence_strength,
        snapshot_id=snapshot_id,
    )
    return [r.to_schema() for r in db_results]


@router.get(
    "/results/{fusion_id}",
    response_model=FusionResult,
    summary="Get Fusion Result by ID",
    description="Retrieve a specific anomaly fusion evaluation by UUID.",
)
def get_fusion_result_by_id(
    fusion_id: str,
    db: Session = Depends(get_db),
) -> FusionResult:
    """Retrieve a specific fusion evaluation by UUID."""
    repo = FusionRepository(db)
    db_result = repo.get_by_fusion_id(fusion_id)
    if not db_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Fusion result with ID '{fusion_id}' not found.",
        )
    return db_result.to_schema()


@router.get(
    "/entity/{entity_id}",
    response_model=List[FusionResult],
    summary="Get Fusion Results by Entity",
    description="Retrieve chronological fusion evaluations for a specific entity ID.",
)
def get_fusion_results_by_entity(
    entity_id: str,
    limit: int = Query(default=50, ge=1, le=200, description="Max results to return"),
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> List[FusionResult]:
    """Retrieve all fusion evaluations for a specific entity identifier."""
    repo = FusionRepository(db)
    db_results = repo.get_by_entity(entity_id=entity_id, limit=limit, skip=skip)
    return [r.to_schema() for r in db_results]
