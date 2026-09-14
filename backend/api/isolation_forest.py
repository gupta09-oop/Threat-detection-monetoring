"""API endpoints for Isolation Forest anomaly detection, training, and evidence retrieval."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.detection.isolation_forest_service import isolation_forest_service
from backend.detection.schemas import (
    IsolationForestAnomalyResult,
    IsolationForestModelStatus,
    IsolationForestTrainRequest,
    IsolationForestTrainResponse,
)
from backend.features.schemas import FeatureSnapshot
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.anomaly_repository import AnomalyRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/isolation-forest", tags=["Isolation Forest Anomaly Detection"])


class ScoreIsolationForestRequest(BaseModel):
    """Request payload to score a feature snapshot with Isolation Forest."""
    snapshot_id: Optional[str] = Field(default=None, description="UUID of persisted snapshot to score")
    snapshot: Optional[FeatureSnapshot] = Field(default=None, description="In-memory snapshot to score directly")
    persist: bool = Field(default=True, description="Whether to persist anomaly result in anomaly_results table")


class ScoreActiveRequest(BaseModel):
    """Request payload to score active recent snapshots."""
    limit: int = Field(default=10, ge=1, le=100, description="Number of recent snapshots to evaluate")
    window_seconds: Optional[int] = Field(default=None, description="Optional window duration filter (60, 300, 900)")


@router.post(
    "/train",
    response_model=IsolationForestTrainResponse,
    summary="Train Isolation Forest Model",
    description="Trains the StandardScaler and Isolation Forest detector on normal FeatureSnapshot records.",
)
def train_model(
    req: Optional[IsolationForestTrainRequest] = None,
    db: Session = Depends(get_db),
) -> IsolationForestTrainResponse:
    """Train or retrain the Isolation Forest detector on baseline normal traffic."""
    params = req or IsolationForestTrainRequest()
    response = isolation_forest_service.train(
        db=db,
        min_samples=params.min_samples,
        target_samples=params.target_samples,
        contamination=params.contamination,
        random_seed=params.random_seed,
        n_estimators=params.n_estimators,
        window_seconds=params.window_seconds,
    )

    if response.status == "INSUFFICIENT_DATA":
        # Cold start safety: returns 200 with clear INSUFFICIENT_DATA status or 422 if requested
        return response

    return response


@router.get(
    "/status",
    response_model=IsolationForestModelStatus,
    summary="Get Isolation Forest Model Status",
    description="Returns current readiness, metadata, sample count, and training parameters.",
)
def get_model_status() -> IsolationForestModelStatus:
    """Retrieve model readiness and training metadata."""
    return isolation_forest_service.get_status()


@router.post(
    "/score",
    response_model=IsolationForestAnomalyResult,
    summary="Score Snapshot with Isolation Forest",
    description="Evaluates a single FeatureSnapshot, producing a normalized 0-100 anomaly score and post-hoc deviations.",
)
def score_snapshot(
    req: ScoreIsolationForestRequest,
    db: Session = Depends(get_db),
) -> IsolationForestAnomalyResult:
    """Evaluate a single feature snapshot through the trained Isolation Forest detector."""
    if not isolation_forest_service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Isolation Forest model is not ready. Train detector first using POST /api/isolation-forest/train.",
        )

    target_snapshot: Optional[FeatureSnapshot] = req.snapshot

    if not target_snapshot and req.snapshot_id:
        db_snap = (
            db.query(FeatureSnapshotDB)
            .filter(FeatureSnapshotDB.snapshot_id == req.snapshot_id)
            .first()
        )
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

    try:
        return isolation_forest_service.evaluate_snapshot(
            snapshot=target_snapshot,
            db=db if req.persist else None,
            persist=req.persist,
        )
    except Exception as e:
        logger.exception("Failed to score snapshot with Isolation Forest")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scoring error: {str(e)}",
        )


@router.post(
    "/score-active",
    response_model=List[IsolationForestAnomalyResult],
    summary="Score Active Snapshots with Isolation Forest",
    description="Scores recent active feature snapshots and persists the resulting anomaly evidence.",
)
def score_active_snapshots(
    req: Optional[ScoreActiveRequest] = None,
    db: Session = Depends(get_db),
) -> List[IsolationForestAnomalyResult]:
    """Score the most recent active snapshots in the database."""
    if not isolation_forest_service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Isolation Forest model is not ready. Train detector first using POST /api/isolation-forest/train.",
        )

    params = req or ScoreActiveRequest()
    try:
        return isolation_forest_service.evaluate_active(
            db=db,
            window_seconds=params.window_seconds,
            limit=params.limit,
        )
    except Exception as e:
        logger.exception("Failed to score active snapshots")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Active scoring error: {str(e)}",
        )


@router.get(
    "/results",
    response_model=List[IsolationForestAnomalyResult],
    summary="Query Isolation Forest Anomaly Results",
    description="Query persisted Isolation Forest anomaly evidence with entity and anomaly filters.",
)
def get_isolation_forest_results(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Results limit"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type (e.g. USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(None, description="Filter by entity identifier"),
    is_anomalous: Optional[bool] = Query(None, description="Filter by anomaly decision"),
    db: Session = Depends(get_db),
) -> List[IsolationForestAnomalyResult]:
    """Query persisted Isolation Forest anomaly detection evidence."""
    repo = AnomalyRepository(db)
    records = repo.get_results(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        detector_type="ISOLATION_FOREST",
        is_anomalous=is_anomalous,
    )

    return [record.to_isolation_forest_schema() for record in records]


@router.get(
    "/results/{result_id}",
    response_model=IsolationForestAnomalyResult,
    summary="Get Specific Isolation Forest Result",
    description="Retrieve a single Isolation Forest anomaly result by UUID.",
)
def get_isolation_forest_result_by_id(
    result_id: str,
    db: Session = Depends(get_db),
) -> IsolationForestAnomalyResult:
    """Retrieve an Isolation Forest anomaly result by its result_id."""
    repo = AnomalyRepository(db)
    record = repo.get_by_result_id(result_id)
    if not record or record.detector_type != "ISOLATION_FOREST":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Isolation Forest result with ID '{result_id}' not found",
        )
    return record.to_isolation_forest_schema()
