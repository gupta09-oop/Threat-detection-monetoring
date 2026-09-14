"""API endpoints for Explainable Risk Scoring.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.repositories.risk_repository import RiskRepository
from backend.risk.schemas import (
    RiskActiveEvaluateRequest,
    RiskEvaluateRequest,
    RiskScoreResult,
)
from backend.risk.service import risk_scoring_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/risk", tags=["Explainable Risk Scoring"])


@router.post(
    "/evaluate",
    response_model=RiskScoreResult,
    summary="Evaluate Threat Risk Score",
    description="Computes a bounded 0-100 Threat Risk Score with full contributor breakdown, severity classification, and human-readable security explanation.",
)
def evaluate_risk(
    req: RiskEvaluateRequest,
    db: Session = Depends(get_db),
) -> RiskScoreResult:
    """Evaluate platform risk score from snapshot, fusion ID, or direct evidence."""
    # 1. From existing fusion ID
    if req.fusion_id:
        try:
            return risk_scoring_service.evaluate_fusion_by_id(
                db=db,
                fusion_id=req.fusion_id,
                persist=req.persist,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            )

    # 2. From snapshot ID
    if req.snapshot_id:
        return risk_scoring_service.evaluate_snapshot(
            db=db,
            snapshot_id=req.snapshot_id,
            rule_evidence=req.rule_evidence,
            correlation_window_seconds=req.correlation_window_seconds,
            persist=req.persist,
        )

    # 3. From direct evidence list
    if req.detector_evidence or req.rule_evidence:
        return risk_scoring_service.evaluate_evidence(
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
        detail="Must provide either snapshot_id, fusion_id, or detector_evidence/rule_evidence to evaluate risk score.",
    )


@router.post(
    "/evaluate-active",
    response_model=List[RiskScoreResult],
    summary="Evaluate Active Entities Risk",
    description="Batch evaluates Threat Risk Scores across recent active feature snapshots and detector outputs.",
)
def evaluate_active_risk(
    req: Optional[RiskActiveEvaluateRequest] = None,
    db: Session = Depends(get_db),
) -> List[RiskScoreResult]:
    """Run risk scoring across recent active snapshots in the platform."""
    params = req or RiskActiveEvaluateRequest()
    return risk_scoring_service.evaluate_active(
        db=db,
        window_seconds=params.window_seconds,
        limit=params.limit,
        correlation_window_seconds=params.correlation_window_seconds,
    )


@router.get(
    "/results",
    response_model=List[RiskScoreResult],
    summary="Query Threat Risk Results",
    description="Retrieve historical risk score evaluations with filtering and pagination.",
)
def get_risk_results(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=100, ge=1, le=500, description="Max results to return"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity identifier"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    snapshot_id: Optional[str] = Query(default=None, description="Filter by feature snapshot UUID"),
    source_fusion_id: Optional[str] = Query(default=None, description="Filter by source fusion UUID"),
    db: Session = Depends(get_db),
) -> List[RiskScoreResult]:
    """Query persisted risk scores."""
    repo = RiskRepository(db)
    db_results = repo.get_scores(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        snapshot_id=snapshot_id,
        source_fusion_id=source_fusion_id,
    )
    return [r.to_schema() for r in db_results]


@router.get(
    "/results/{risk_id}",
    response_model=RiskScoreResult,
    summary="Get Risk Score by ID",
    description="Retrieve a specific Threat Risk Score evaluation by UUID.",
)
def get_risk_result_by_id(
    risk_id: str,
    db: Session = Depends(get_db),
) -> RiskScoreResult:
    """Retrieve a specific risk score evaluation by UUID."""
    repo = RiskRepository(db)
    db_result = repo.get_by_risk_id(risk_id)
    if not db_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk score evaluation '{risk_id}' not found.",
        )
    return db_result.to_schema()


@router.get(
    "/{entity_id}",
    response_model=RiskScoreResult,
    summary="Get Latest Entity Risk Score",
    description="Retrieve the most recent Threat Risk Score evaluation for a specific entity.",
)
def get_entity_risk(
    entity_id: str,
    db: Session = Depends(get_db),
) -> RiskScoreResult:
    """Retrieve the latest risk score evaluation for a specific entity."""
    repo = RiskRepository(db)
    db_result = repo.get_by_entity(entity_id)
    if not db_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No risk score evaluations found for entity '{entity_id}'.",
        )
    return db_result.to_schema()


@router.get(
    "/{entity_id}/history",
    response_model=List[RiskScoreResult],
    summary="Get Entity Risk History",
    description="Retrieve chronological history of Threat Risk Score evaluations for a specific entity.",
)
def get_entity_risk_history(
    entity_id: str,
    limit: int = Query(default=100, ge=1, le=500, description="Max history records to return"),
    db: Session = Depends(get_db),
) -> List[RiskScoreResult]:
    """Retrieve historical risk scores for an entity."""
    repo = RiskRepository(db)
    results = repo.get_entity_history(entity_id=entity_id, limit=limit)
    return [r.to_schema() for r in results]
