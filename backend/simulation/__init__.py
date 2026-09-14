"""Simulation package for Sh4d0w_St4lk3r live demo and attack generation."""

from backend.simulation.api import router as simulation_router
from backend.simulation.service import simulation_service
from backend.simulation.bootstrap import ensure_ml_models_ready

__all__ = ["simulation_router", "simulation_service", "ensure_ml_models_ready"]
