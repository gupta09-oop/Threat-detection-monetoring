"""API endpoints for behavioral baseline management and inspection."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.detection.baseline_service import baseline_service
from backend.detection.schemas import StatisticalBaseline
from backend.repositories.baseline_repository import BaselineRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/baselines", tags=["Statistical Baselines"])


class BuildBaselineRequest(BaseModel):
    """Request payload to trigger baseline generation from historical snapshots."""
    max_samples: int = Field(default=1000, ge=1, le=10000, description="Max historical snapshots to examine")
    window_seconds: Optional[int] = Field(default=None, description="Optional window size filter (60, 300, 900)")
    entity_type: Optional[str] = Field(default=None, description="Optional entity type filter (USER, IP, GLOBAL)")
    entity_id: Optional[str] = Field(default=None, description="Optional entity ID filter")


@router.post(
    "/build",
    response_model=List[StatisticalBaseline],
    summary="Build Baselines from Historical Snapshots",
    description="Analyzes historical FeatureSnapshot records in SQLite, computes empirical mean and standard deviation, and persists baselines.",
)
def build_baselines(
    req: BuildBaselineRequest,
    db: Session = Depends(get_db),
) -> List[StatisticalBaseline]:
    """Calculate and persist baselines from historical feature snapshots."""
    return baseline_service.build_and_persist_from_db(
        db=db,
        max_samples=req.max_samples,
        window_seconds=req.window_seconds,
        entity_type=req.entity_type,
        entity_id=req.entity_id,
    )


@router.get(
    "",
    response_model=List[StatisticalBaseline],
    summary="Query Learned Baselines",
    description="Retrieve persisted behavioral baselines with optional entity, window, and feature filtering.",
)
def get_baselines(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=500, description="Maximum baselines to return"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (USER, IP, HOST, GLOBAL)"),
    entity_id: Optional[str] = Query(default=None, description="Filter by entity ID"),
    feature_name: Optional[str] = Query(default=None, description="Filter by feature name"),
    window_seconds: Optional[int] = Query(default=None, description="Filter by window duration in seconds"),
    db: Session = Depends(get_db),
) -> List[StatisticalBaseline]:
    """Query stored baselines."""
    repo = BaselineRepository(db)
    records = repo.get_all_baselines(
        skip=skip,
        limit=limit,
        entity_type=entity_type,
        entity_id=entity_id,
        feature_name=feature_name,
        window_seconds=window_seconds,
    )
    return [rec.to_schema() for rec in records]
