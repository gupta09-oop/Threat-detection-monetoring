"""Main entrypoint for Sh4d0w_St4lk3r FastAPI application."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.api import (
    health_router,
    events_router,
    features_router,
    baselines_router,
    statistical_router,
    isolation_forest_router,
    clustering_router,
    fusion_router,
    risk_router,
    alerts_router,
    cases_router,
    ws_router,
    simulation_router,
    reports_router,
)
from backend.db.session import init_db
from backend.detection.isolation_forest_service import isolation_forest_service
from backend.detection.clustering_service import behavioral_clustering_service
from backend.ingestion.consumer import consumer

# Basic application logging configuration
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sh4d0w_st4lk3r")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to handle startup and shutdown events."""
    logger.info(
        "Starting up %s (version %s)...",
        settings.PROJECT_NAME,
        settings.VERSION,
    )

    # Initialize database and verify connectivity
    init_db()

    # Start background ingestion consumer
    await consumer.start()

    # Attempt to load pre-trained ML model artifacts
    isolation_forest_service.try_load_model()
    behavioral_clustering_service.try_load_model()

    yield

    # Gracefully shut down background consumer and drain backlog
    await consumer.stop()
    logger.info("Shutting down %s...", settings.PROJECT_NAME)


app = FastAPI(
    title=settings.PROJECT_FULL_TITLE,
    version=settings.VERSION,
    description=(
        "Behavioral Threat Intelligence & Anomaly Detection Platform "
        "- Phase 10 Alerting, Deduplication & Case Management"
    ),
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(health_router)
app.include_router(events_router)
app.include_router(features_router)
app.include_router(baselines_router)
app.include_router(statistical_router)
app.include_router(isolation_forest_router)
app.include_router(clustering_router)
app.include_router(fusion_router)
app.include_router(risk_router)
app.include_router(alerts_router)
app.include_router(cases_router)
app.include_router(ws_router)
app.include_router(simulation_router)
app.include_router(reports_router)


# ---------------------------------------------------------------------------
# Production frontend serving
# ---------------------------------------------------------------------------

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"

    if assets_dir.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=assets_dir),
            name="assets",
        )

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve React frontend and support React Router client-side routes."""
        requested_file = FRONTEND_DIST / full_path

        if requested_file.is_file():
            return FileResponse(requested_file)

        return FileResponse(FRONTEND_DIST / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )