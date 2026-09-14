"""Repository for persisting and querying SOC incident cases."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import and_, desc
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.alerts.schemas import CaseResult

from backend.models.case import CaseDB
from backend.repositories.base import BaseRepository


class CaseRepository(BaseRepository[CaseDB]):
    """Data access layer for SOC incident cases."""

    def __init__(self, db: Session):
        super().__init__(CaseDB, db)

    def create_case(self, case_res: "CaseResult") -> CaseDB:
        """Persist a new incident case record."""
        db_obj = CaseDB.from_schema(case_res)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def get_by_case_id(self, case_id: str) -> Optional[CaseDB]:
        """Retrieve a specific case by UUID."""
        return (
            self.db.query(CaseDB)
            .filter(CaseDB.case_id == case_id)
            .first()
        )

    def find_open_case_for_entity(
        self,
        entity_id: str,
        window_seconds: int,
        reference_time: Optional[datetime] = None,
    ) -> Optional[CaseDB]:
        """Find an active (OPEN or INVESTIGATING) case for this entity updated within the window."""
        ref = reference_time or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)

        cases = (
            self.db.query(CaseDB)
            .filter(
                and_(
                    CaseDB.entity_id == entity_id,
                    CaseDB.status.in_(["OPEN", "INVESTIGATING"]),
                )
            )
            .order_by(desc(CaseDB.updated_at))
            .all()
        )

        for c in cases:
            ts = c.updated_at or c.opened_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            delta = abs((ref - ts).total_seconds())
            if delta <= window_seconds:
                return c

        return None

    def update_case(self, db_obj: CaseDB) -> CaseDB:
        """Update and commit a case record."""
        db_obj.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def get_cases(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[CaseDB]:
        """Query persisted cases with filtering and pagination."""
        query = self.db.query(CaseDB)

        if entity_type:
            query = query.filter(CaseDB.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(CaseDB.entity_id == entity_id)
        if severity:
            query = query.filter(CaseDB.severity == severity.upper())
        if status:
            query = query.filter(CaseDB.status == status.upper())

        return (
            query.order_by(desc(CaseDB.opened_at))
            .offset(skip)
            .limit(limit)
            .all()
        )
