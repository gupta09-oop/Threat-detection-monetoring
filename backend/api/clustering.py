"""API endpoints for Behavioral Clustering anomaly detection, training, and evidence retrieval."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.detection.clustering_service import behavioral_clustering_service
from backend.detection.schemas import (
    BehavioralClusteringAnomalyResult,
    BehavioralClusteringModelStatus,
    BehavioralClusteringTrainRequest,
    BehavioralClusteringTrainResponse,
)
from backend.features.schemas import FeatureSnapshot
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.anomaly_repository import AnomalyRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/clustering", tags=["Behavioral Clustering Anomaly Detection"])


class ScoreClusteringRequest(BaseModel):
    """Request payload to score a feature snapshot with Behavioral Clustering."""
    snapshot_id: Optional[str] = Field(default=None, description="UUID of persisted snapshot to score")
    snapshot: Optional[FeatureSnapshot] = Field(default=None, description="In-memory snapshot to score directly")
    persist: bool = Field(default=True, description="Whether to persist anomaly result in anomaly_results table")


class ScoreActiveRequest(BaseModel):
    """Request payload to score active recent snapshots."""
    limit: int = Field(default=10, ge=1, le=100, description="Number of recent snapshots to evaluate")
    window_seconds: Optional[int] = Field(default=None, description="Optional window duration filter (60, 300, 900)")


@router.post(
    "/train",
    response_model=BehavioralClusteringTrainResponse,
    summary="Train Behavioral Clustering Model",
    description="Trains StandardScaler, KMeans, and PCA on normal FeatureSnapshot records.",
)
def train_model(
    req: Optional[BehavioralClusteringTrainRequest] = None,
    db: Session = Depends(get_db),
) -> BehavioralClusteringTrainResponse:
    """Train or retrain the Behavioral Clustering detector on baseline normal traffic."""
    params = req or BehavioralClusteringTrainRequest()
    return behavioral_clustering_service.train(
        db=db,
        n_clusters=params.n_clusters,
        min_samples=params.min_samples,
        target_samples=params.target_samples,
        random_seed=params.random_seed,
        distance_percentile=params.distance_percentile,
        window_seconds=params.window_seconds,
    )


@router.get(
    "/status",
    response_model=BehavioralClusteringModelStatus,
    summary="Get Behavioral Clustering Model Status",
    description="Returns current readiness, cluster profiles, 95th percentile threshold, and metadata.",
)
def get_model_status() -> BehavioralClusteringModelStatus:
    """Retrieve model readiness and clustering metadata."""
    return behavioral_clustering_service.get_status()


@router.post(
    "/score",
    response_model=BehavioralClusteringAnomalyResult,
    summary="Score Snapshot with Behavioral Clustering",
    description="Evaluates a single FeatureSnapshot against KMeans clusters and 95th percentile distance threshold.",
)
def score_snapshot(
    req: ScoreClusteringRequest,
    db: Session = Depends(get_db),
) -> BehavioralClusteringAnomalyResult:
    """Evaluate a single feature snapshot through the trained Behavioral Clustering detector."""
    if not behavioral_clustering_service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Behavioral Clustering model is not ready. Train detector first using POST /api/clustering/train.",
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
        return behavioral_clustering_service.evaluate_snapshot(
            snapshot=target_snapshot,
            db=db if req.persist else None,
            persist=req.persist,
        )
    except Exception as e:
        logger.exception("Failed to score snapshot with Behavioral Clustering")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Clustering scoring error: {str(e)}",
        )


@router.post(
    "/score-active",
    response_model=List[BehavioralClusteringAnomalyResult],
    summary="Score Active Snapshots with Behavioral Clustering",
    description="Scores recent active feature snapshots and persists the resulting anomaly evidence.",
)
def score_active_snapshots(
    req: Optional[ScoreActiveRequest] = None,
    db: Session = Depends(get_db),
) -> List[BehavioralClusteringAnomalyResult]:
    """Score the most recent active snapshots in the database."""
    if not behavioral_clustering_service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Behavioral Clustering model is not ready. Train detector first using POST /api/clustering/train.",
        )

    params = req or ScoreActiveRequest()
    try:
        return behavioral_clustering_service.evaluate_active(
            db=db,
            window_seconds=params.window_seconds,
            limit=params.limit,
        )
    except Exception as e:
        logger.exception("Failed to score active snapshots with clustering")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Active clustering scoring error: {str(e)}",
        )


@router.get(
    "/results",
    response_model=List[BehavioralClusteringAnomalyResult],
    summary="Query Behavioral Clustering Anomaly Results",
    description="Query persisted Behavioral Clustering anomaly evidence with entity and anomaly filters.",
)
def get_clustering_results(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Results limit"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type (e.g. USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(None, description="Filter by entity identifier"),
    is_anomalous: Optional[bool] = Query(None, description="Filter by anomaly decision"),
    db: Session = Depends(get_db),
) -> List[BehavioralClusteringAnomalyResult]:
    """Query persisted Behavioral Clustering anomaly detection evidence."""
    repo = AnomalyRepository(db)
    records = repo.get_results(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        detector_type="BEHAVIORAL_CLUSTERING",
        is_anomalous=is_anomalous,
    )

    return [record.to_clustering_schema() for record in records]


@router.get(
    "/results/{result_id}",
    response_model=BehavioralClusteringAnomalyResult,
    summary="Get Specific Behavioral Clustering Result",
    description="Retrieve a single Behavioral Clustering anomaly result by UUID.",
)
def get_clustering_result_by_id(
    result_id: str,
    db: Session = Depends(get_db),
) -> BehavioralClusteringAnomalyResult:
    """Retrieve a Behavioral Clustering anomaly result by its result_id."""
    repo = AnomalyRepository(db)
    record = repo.get_by_result_id(result_id)
    if not record or record.detector_type != "BEHAVIORAL_CLUSTERING":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Behavioral Clustering result with ID '{result_id}' not found",
        )
    return record.to_clustering_schema()
