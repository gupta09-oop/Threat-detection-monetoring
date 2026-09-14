"""FastAPI REST API router for browser-controlled attack simulation.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import logging
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.simulation.bootstrap import ensure_ml_models_ready
from backend.simulation.schemas import (
    SimulationStartRequest,
    SimulationStatusResponse,
    SimulationStopResponse,
)
from backend.simulation.service import simulation_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/simulation", tags=["Live Attack Simulation"])


@router.post(
    "/start",
    response_model=SimulationStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Start Live Synthetic Attack Simulation",
    description="Initiates an asynchronous browser-controlled synthetic attack or baseline simulation.",
)
def start_simulation(req: SimulationStartRequest) -> SimulationStatusResponse:
    """Start synthetic attack telemetry simulation with gradual real-time pacing."""
    try:
        return simulation_service.start_simulation(req)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/status",
    response_model=SimulationStatusResponse,
    summary="Get Simulation Execution Status",
    description="Returns the real-time execution state, progress percentage, and latest detection summary.",
)
def get_status() -> SimulationStatusResponse:
    """Retrieve current simulation execution status."""
    return simulation_service.get_status()


@router.post(
    "/stop",
    response_model=SimulationStopResponse,
    summary="Stop Active Simulation",
    description="Safely interrupts and cancels the active background simulation task.",
)
def stop_simulation() -> SimulationStopResponse:
    """Stop currently active attack simulation."""
    return simulation_service.stop_simulation()


@router.post(
    "/reset",
    summary="Pure Clean Demo Reset",
    description="Completely purges all runtime alerts, cases, risk scores, fusion results, anomaly results, telemetry events, and feature snapshots while preserving trained ML models and baseline profiles.",
)
def reset_simulation(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Purge all simulation/runtime events and restore clean SOC baseline."""
    return simulation_service.reset_demo_state(db=db)


@router.post(
    "/bootstrap",
    summary="Bootstrap ML Baseline Telemetry",
    description="Generates normal baseline snapshots and trains Isolation Forest & Behavioral Clustering.",
)
def bootstrap_models(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Manually invoke ML readiness bootstrap to train models on genuine normal synthetic data."""
    return ensure_ml_models_ready(db)
