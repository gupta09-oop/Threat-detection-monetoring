"""Repository for persisting and querying security alerts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import and_, desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.alerts.schemas import AlertResult

from backend.models.alert import AlertDB
from backend.repositories.base import BaseRepository


class AlertRepository(BaseRepository[AlertDB]):
    """Data access layer for security alerts."""

    def __init__(self, db: Session):
        super().__init__(AlertDB, db)

    def create_alert(self, alert: "AlertResult") -> AlertDB:
        """Persist a security alert record."""
        db_obj = AlertDB.from_schema(alert)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def get_by_alert_id(self, alert_id: str) -> Optional[AlertDB]:
        """Retrieve a specific alert by UUID."""
        return (
            self.db.query(AlertDB)
            .filter(AlertDB.alert_id == alert_id)
            .first()
        )

    def get_by_risk_id(self, risk_id: str) -> Optional[AlertDB]:
        """Retrieve alert created from a specific risk evaluation."""
        return (
            self.db.query(AlertDB)
            .filter(AlertDB.risk_id == risk_id)
            .first()
        )

    def find_dedup_match(
        self,
        entity_id: str,
        dedup_key: str,
        window_seconds: int,
        reference_time: Optional[datetime] = None,
    ) -> Optional[AlertDB]:
        """Find an existing active alert matching entity and dedup key within the time window."""
        ref = reference_time or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)

        # Look for open alerts with same entity and dedup_key
        alerts = (
            self.db.query(AlertDB)
            .filter(
                and_(
                    AlertDB.entity_id == entity_id,
                    AlertDB.dedup_key == dedup_key,
                    AlertDB.status.in_(["NEW", "ACKNOWLEDGED", "ESCALATED"]),
                )
            )
            .order_by(desc(AlertDB.updated_at))
            .all()
        )

        for a in alerts:
            ts = a.updated_at or a.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            delta = abs((ref - ts).total_seconds())
            if delta <= window_seconds:
                return a

        return None

    def update_alert(self, db_obj: AlertDB) -> AlertDB:
        """Update and commit an alert record."""
        db_obj.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def get_alerts(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> List[AlertDB]:
        """Query persisted alerts with filtering and pagination."""
        query = self.db.query(AlertDB)

        if entity_type:
            query = query.filter(AlertDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(AlertDB.entity_id == entity_id)
        if severity:
            query = query.filter(AlertDB.severity == severity.upper())
        if status:
            query = query.filter(AlertDB.status == status.upper())
        if case_id:
            query = query.filter(AlertDB.case_id == case_id)

        return (
            query.order_by(desc(AlertDB.timestamp))
            .offset(skip)
            .limit(limit)
            .all()
        )
