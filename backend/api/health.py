"""Health check endpoint for Sh4d0w_St4lk3r."""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from backend.config import settings

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Health check response schema matching the platform specification."""
    status: str = Field(..., description="Operational status of the service")
    service: str = Field(..., description="Name of the service")
    version: str = Field(..., description="Service version")


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service Health Check",
    description="Returns the health status, service identifier, and version of Sh4d0w_St4lk3r."
)
def get_health() -> HealthResponse:
    """Return health status of the platform."""
    return HealthResponse(
        status="healthy",
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
    )
