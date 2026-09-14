"""API package for Sh4d0w_St4lk3r."""

from backend.api.health import router as health_router
from backend.api.events import router as events_router
from backend.api.features import router as features_router
from backend.api.baselines import router as baselines_router
from backend.api.statistical import router as statistical_router
from backend.api.isolation_forest import router as isolation_forest_router
from backend.api.clustering import router as clustering_router
from backend.api.fusion import router as fusion_router
from backend.api.risk import router as risk_router
from backend.api.alerts import router as alerts_router
from backend.api.cases import router as cases_router
from backend.api.events_ws import router as ws_router
from backend.simulation.api import router as simulation_router
from backend.api.reports import router as reports_router

__all__ = [
    "health_router",
    "events_router",
    "features_router",
    "baselines_router",
    "statistical_router",
    "isolation_forest_router",
    "clustering_router",
    "fusion_router",
    "risk_router",
    "alerts_router",
    "cases_router",
    "ws_router",
    "simulation_router",
    "reports_router",
]

