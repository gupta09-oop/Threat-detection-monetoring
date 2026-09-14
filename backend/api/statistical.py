"""API endpoints for statistical anomaly scoring and result querying."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.detection.schemas import StatisticalAnomalyResult
from backend.detection.statistical_detector import statistical_detector
from backend.features.schemas import FeatureSnapshot
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.anomaly_repository import AnomalyRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/statistical", tags=["Statistical Anomaly Detection"])


class ScoreSnapshotRequest(BaseModel):
    """Request payload to score a feature snapshot."""
    snapshot_id: Optional[str] = Field(default=None, description="ID of persisted snapshot to score")
    snapshot: Optional[FeatureSnapshot] = Field(default=None, description="In-memory snapshot to score directly")
    persist: bool = Field(default=True, description="Whether to persist anomaly results to database")


@router.post(
    "/score",
    response_model=List[StatisticalAnomalyResult],
    summary="Score Feature Snapshot with Z-Score",
    description="Evaluates a FeatureSnapshot against learned empirical baselines and computes statistical deviation z-scores.",
)
def score_snapshot(
    req: ScoreSnapshotRequest,
    db: Session = Depends(get_db),
) -> List[StatisticalAnomalyResult]:
    """Score a feature snapshot against historical baselines."""
    target_snapshot: Optional[FeatureSnapshot] = req.snapshot

    if not target_snapshot and req.snapshot_id:
        db_snap = db.query(FeatureSnapshotDB).filter(FeatureSnapshotDB.snapshot_id == req.snapshot_id).first()
        if not db_snap:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"FeatureSnapshot '{req.snapshot_id}' not found",
            )
        target_snapshot = db_snap.to_schema()

    if not target_snapshot:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'snapshot_id' or a full 'snapshot' payload",
        )

    return statistical_detector.score_snapshot_with_db(
        db=db,
        snapshot=target_snapshot,
        persist=req.persist,
    )


@router.post(
    "/score-active",
    response_model=List[StatisticalAnomalyResult],
    summary="Score Recent Active Feature Snapshots",
    description="Evaluates recent feature snapshots in SQLite against baselines and records anomaly results.",
)
def score_active_snapshots(
    limit: int = Query(default=10, ge=1, le=100, description="Number of recent snapshots to evaluate"),
    db: Session = Depends(get_db),
) -> List[StatisticalAnomalyResult]:
    """Evaluate recent snapshots and persist anomaly results."""
    recent_db_snaps = db.query(FeatureSnapshotDB).order_by(FeatureSnapshotDB.timestamp.desc()).limit(limit).all()
    all_results: List[StatisticalAnomalyResult] = []

    for db_snap in recent_db_snaps:
        snapshot = db_snap.to_schema()
        results = statistical_detector.score_snapshot_with_db(
            db=db,
            snapshot=snapshot,
            persist=True,
        )
        all_results.extend(results)

    return all_results


@router.get(
    "/results",
    response_model=List[StatisticalAnomalyResult],
    summary="Query Statistical Anomaly Results",
    description="Retrieve evaluated statistical anomaly results with filtering by entity, anomalous state, and pagination.",
)
def get_anomaly_results(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=500, description="Maximum results to return"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity ID"),
    is_anomalous: Optional[bool] = Query(default=None, description="Filter for statistically anomalous features only (|z| > 3)"),
    status: Optional[str] = Query(default=None, description="Filter by outcome status: NORMAL, ANOMALOUS, ABSTAIN"),
    db: Session = Depends(get_db),
) -> List[StatisticalAnomalyResult]:
    """Query stored anomaly results."""
    repo = AnomalyRepository(db)
    records = repo.get_results(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        is_anomalous=is_anomalous,
        status=status,
    )
    return [rec.to_schema() for rec in records]


@router.get(
    "/results/{result_id}",
    response_model=StatisticalAnomalyResult,
    summary="Get Anomaly Result by ID",
    description="Retrieve a single statistical anomaly result by its unique UUID.",
)
def get_anomaly_result_by_id(
    result_id: str,
    db: Session = Depends(get_db),
) -> StatisticalAnomalyResult:
    """Retrieve anomaly result by UUID."""
    repo = AnomalyRepository(db)
    record = repo.get_by_result_id(result_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anomaly result '{result_id}' not found",
        )
    return record.to_schema()
