"""FastAPI REST router for Threat Intelligence / Security Incident Reports.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import logging
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models.alert import AlertDB
from backend.models.case import CaseDB
from backend.reports.schemas import ReportExportRequest, ThreatReportResponse
from backend.reports.service import threat_report_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Threat Intelligence Reports"])


@router.post(
    "/export",
    response_model=ThreatReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Threat Intelligence Report",
    description="Generates an explainable, forensic incident report for an alert or case.",
)
def export_threat_report(
    req: ReportExportRequest,
    db: Session = Depends(get_db),
) -> ThreatReportResponse:
    """Generate structured Threat Intelligence Report."""
    try:
        return threat_report_service.generate_report(
            db=db,
            incident_type=req.incident_type,
            incident_id=req.incident_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except Exception as exc:
        logger.exception("Error generating threat report: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate threat report: {str(exc)}",
        )


@router.get(
    "/incidents",
    summary="List Reportable Incidents",
    description="Returns available alerts and cases suitable for threat report generation.",
)
def list_reportable_incidents(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve list of incidents that can be selected for report generation."""
    alerts = db.query(AlertDB).order_by(AlertDB.created_at.desc()).limit(20).all()
    cases = db.query(CaseDB).order_by(CaseDB.opened_at.desc()).limit(20).all()

    return {
        "alerts": [
            {
                "id": a.alert_id,
                "title": a.title,
                "entity_id": a.entity_id,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
        "cases": [
            {
                "id": c.case_id,
                "title": c.title,
                "entity_id": c.entity_id,
                "severity": c.severity,
                "total_risk_score": c.total_risk_score,
                "status": c.status,
                "opened_at": c.opened_at.isoformat() if c.opened_at else None,
            }
            for c in cases
        ],
    }


@router.get(
    "/{incident_type}/{incident_id}",
    response_model=ThreatReportResponse,
    summary="Get Threat Report by Incident ID",
    description="Fetches a generated threat report for a specific alert or case.",
)
def get_threat_report(
    incident_type: str,
    incident_id: str,
    db: Session = Depends(get_db),
) -> ThreatReportResponse:
    """Retrieve structured Threat Intelligence Report."""
    try:
        return threat_report_service.generate_report(
            db=db,
            incident_type=incident_type,
            incident_id=incident_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
