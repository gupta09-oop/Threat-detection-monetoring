"""Telemetry ingestion API endpoints for Sh4d0w_St4lk3r."""

import logging
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.ingestion.queue import (
    BackpressureError,
    dead_letter_queue,
    event_bus,
)
from backend.models.canonical import CanonicalEvent
from backend.models.telemetry import normalize_event
from backend.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/events", tags=["Telemetry Ingestion"])


class IngestionResponse(BaseModel):
    """Response returned when telemetry events are accepted for ingestion."""
    status: str = Field(default="accepted", description="Ingestion status")
    accepted_count: int = Field(..., description="Number of events successfully validated and queued")
    rejected_count: int = Field(..., description="Number of events rejected during validation")
    event_ids: List[str] = Field(default_factory=list, description="IDs of accepted canonical events")
    rejected_items: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Details of events rejected during normalization"
    )


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestionResponse,
    summary="Ingest Telemetry Events",
    description=(
        "Accepts a single telemetry event or a batch of events (AUTH, NETWORK, SYSTEM, or Canonical). "
        "Normalizes incoming payloads into CanonicalEvents and publishes them to the bounded ingestion queue."
    ),
)
async def ingest_events(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
) -> IngestionResponse:
    """Ingest single or batch telemetry events."""
    raw_items: List[Dict[str, Any]] = payload if isinstance(payload, list) else [payload]

    if not raw_items:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload cannot be empty",
        )

    accepted_events: List[CanonicalEvent] = []
    rejected_details: List[Dict[str, Any]] = []

    for index, item in enumerate(raw_items):
        try:
            canonical = normalize_event(item)
            accepted_events.append(canonical)
        except Exception as exc:
            error_msg = f"Validation failed at index {index}: {str(exc)}"
            dead_letter_record = dead_letter_queue.record(raw_payload=item, error=error_msg)
            rejected_details.append({
                "index": index,
                "error": error_msg,
                "dead_letter_id": dead_letter_record["id"],
            })

    # If all items failed validation in a single or batch request
    if not accepted_events and rejected_details:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "All submitted events failed validation",
                "rejected_count": len(rejected_details),
                "errors": rejected_details,
            },
        )

    # Publish accepted events to the bounded EventBus
    published_ids: List[str] = []
    try:
        for event in accepted_events:
            await event_bus.publish(event)
            published_ids.append(event.event_id)
    except BackpressureError as bp_err:
        logger.warning("Backpressure error on ingestion: %s", bp_err)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Ingestion queue full - backpressure applied: {str(bp_err)}",
        )

    return IngestionResponse(
        status="accepted",
        accepted_count=len(published_ids),
        rejected_count=len(rejected_details),
        event_ids=published_ids,
        rejected_items=rejected_details,
    )


@router.get(
    "",
    response_model=List[CanonicalEvent],
    summary="Query Persisted Telemetry Events",
    description="Retrieve persisted canonical events from SQLite with optional filtering and pagination.",
)
def get_events(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=50, ge=1, le=1000, description="Maximum events to return"),
    source_type: Optional[str] = Query(default=None, description="Filter by source type (AUTH, NETWORK, SYSTEM)"),
    user_id: Optional[str] = Query(default=None, description="Filter by user identifier"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP"),
    db: Session = Depends(get_db),
) -> List[CanonicalEvent]:
    """Retrieve persisted events."""
    repo = EventRepository(db)
    db_records = repo.get_events(
        skip=skip,
        limit=limit,
        source_type=source_type,
        user_id=user_id,
        event_type=event_type,
        source_ip=source_ip,
    )
    return [rec.to_canonical() for rec in db_records]


@router.get(
    "/dead-letter",
    summary="Inspect Dead-Letter Queue",
    description="Retrieve rejected and malformed event payloads recorded by the dead-letter mechanism.",
)
def get_dead_letter_events(
    limit: int = Query(default=50, ge=1, le=200, description="Max failures to return"),
) -> List[Dict[str, Any]]:
    """Retrieve dead-letter failure entries."""
    return dead_letter_queue.get_failures(limit=limit)
