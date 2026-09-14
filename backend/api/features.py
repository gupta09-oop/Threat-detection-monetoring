"""API endpoints for behavioral feature engineering and snapshot inspection."""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.service import feature_service
from backend.features.windows import SUPPORTED_WINDOWS
from backend.repositories.feature_repository import FeatureRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/features", tags=["Behavioral Features"])


class CalculateFeatureRequest(BaseModel):
    """Request payload to compute behavioral features for a specific entity window."""
    window_seconds: int = Field(default=60, description="Window size in seconds (60, 300, 900)")
    entity_type: EntityType = Field(default=EntityType.GLOBAL, description="Target entity type")
    entity_id: str = Field(default="GLOBAL", description="Entity identifier (username, IP, host, or GLOBAL)")
    persist: bool = Field(default=True, description="Whether to persist the generated snapshot to the database")


@router.post(
    "/calculate",
    response_model=FeatureSnapshot,
    summary="Compute Behavioral Features for Entity",
    description="Calculates behavioral features over the specified time window and optionally persists the snapshot.",
)
def calculate_features(
    req: CalculateFeatureRequest,
    db: Session = Depends(get_db),
) -> FeatureSnapshot:
    """Compute and optionally persist feature snapshot for an entity."""
    if req.window_seconds not in SUPPORTED_WINDOWS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported window: {req.window_seconds}s. Supported windows are: {SUPPORTED_WINDOWS}",
        )

    if req.persist:
        snapshot = feature_service.extract_and_persist_for_window(
            db=db,
            window_seconds=req.window_seconds,
            entity_type=req.entity_type,
            entity_id=req.entity_id,
        )
    else:
        # Compute without writing to DB
        from backend.models.db_event import TelemetryEventDB
        from datetime import timedelta
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(seconds=req.window_seconds)

        query = db.query(TelemetryEventDB).filter(
            TelemetryEventDB.timestamp >= start_time,
            TelemetryEventDB.timestamp <= end_time,
        )
        if req.entity_type == EntityType.USER and req.entity_id != "GLOBAL":
            query = query.filter(TelemetryEventDB.user_id == req.entity_id)
        elif req.entity_type == EntityType.IP and req.entity_id != "GLOBAL":
            query = query.filter(TelemetryEventDB.source_ip == req.entity_id)

        canonical_events = [e.to_canonical() for e in query.all()]
        snapshot = feature_service.calculate_for_events(
            events=canonical_events,
            window_seconds=req.window_seconds,
            entity_type=req.entity_type,
            entity_id=req.entity_id,
            window_end=end_time,
        )

    return snapshot


@router.post(
    "/calculate-active",
    response_model=List[FeatureSnapshot],
    summary="Compute Snapshots for All Active Entities",
    description="Automatically discovers all active entities in the recent window, calculates features, and persists snapshots.",
)
def calculate_active_entities(
    window_seconds: int = Query(default=60, description="Window size in seconds (60, 300, 900)"),
    db: Session = Depends(get_db),
) -> List[FeatureSnapshot]:
    """Compute and persist feature snapshots for all active users, IPs, and global scope."""
    if window_seconds not in SUPPORTED_WINDOWS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported window: {window_seconds}s. Supported windows are: {SUPPORTED_WINDOWS}",
        )

    return feature_service.generate_snapshots_for_active_entities(
        db=db,
        window_seconds=window_seconds,
    )


@router.get(
    "/snapshots",
    response_model=List[FeatureSnapshot],
    summary="Query Persisted Feature Snapshots",
    description="Retrieve stored behavioral feature snapshots with filtering by entity, window, and pagination.",
)
def get_snapshots(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=500, description="Maximum snapshots to return"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity ID"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST, GLOBAL)"),
    window_seconds: Optional[int] = Query(default=None, description="Filter by window duration in seconds"),
    db: Session = Depends(get_db),
) -> List[FeatureSnapshot]:
    """Retrieve persisted feature snapshots."""
    repo = FeatureRepository(db)
    records = repo.get_snapshots(
        skip=skip,
        limit=limit,
        entity_id=entity_id,
        entity_type=entity_type,
        window_seconds=window_seconds,
    )
    return [rec.to_schema() for rec in records]


@router.get(
    "/snapshots/{snapshot_id}",
    response_model=FeatureSnapshot,
    summary="Get Feature Snapshot by ID",
    description="Retrieve a single feature snapshot by its unique UUID.",
)
def get_snapshot_by_id(
    snapshot_id: str,
    db: Session = Depends(get_db),
) -> FeatureSnapshot:
    """Retrieve snapshot by UUID."""
    repo = FeatureRepository(db)
    record = repo.get_by_snapshot_id(snapshot_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature snapshot '{snapshot_id}' not found",
        )
    return record.to_schema()
