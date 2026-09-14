"""Pydantic schemas and enums for browser-controlled attack simulation.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SimulationScenario(str, Enum):
    NORMAL = "normal"
    DISTRIBUTED_BRUTEFORCE = "distributed_bruteforce"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PORT_SCAN = "port_scan"
    ALL = "all"


class SimulationIntensity(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class SimulationStartRequest(BaseModel):
    """Request payload to initiate a live synthetic attack simulation."""
    scenario: str = Field(
        default="distributed_bruteforce",
        description="Scenario name: normal, distributed_bruteforce, credential_stuffing, port_scan, all",
    )
    seed: int = Field(
        default=42,
        description="Deterministic pseudo-random seed",
    )
    duration_seconds: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Target simulation duration in seconds (individual: ~20-45s, showcase: ~120-180s)",
    )
    intensity: str = Field(
        default="normal",
        description="Attack intensity: low, normal, high",
    )


class SimulationStatusResponse(BaseModel):
    """Real-time execution status and metrics for the simulation engine."""
    running: bool = Field(..., description="Whether a simulation is currently active")
    scenario: Optional[str] = Field(default=None, description="Active or last executed scenario")
    progress: int = Field(default=0, ge=0, le=100, description="Overall progress percentage 0-100")
    events_generated: int = Field(default=0, description="Cumulative synthetic events ingested")
    current_stage: str = Field(default="idle", description="Current execution stage description")
    started_at: Optional[str] = Field(default=None, description="ISO timestamp when simulation started")
    elapsed_seconds: int = Field(default=0, description="Elapsed runtime in seconds")
    completed: bool = Field(default=False, description="Whether the last simulation completed successfully")
    last_result: Optional[Dict[str, Any]] = Field(default=None, description="Detailed result summary of last completed run")
    error: Optional[str] = Field(default=None, description="Error message if simulation failed")


class SimulationStopResponse(BaseModel):
    """Response returned upon cancelling an active simulation."""
    success: bool = Field(..., description="Whether the stop command succeeded")
    message: str = Field(..., description="Status explanation")
