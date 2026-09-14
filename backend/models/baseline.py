"""SQLAlchemy ORM model for storing learned statistical behavioral baselines."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import (
    Column,
    Integer,
    Float,
    String,
    DateTime,
    Index,
    UniqueConstraint,
)
from backend.db.base import Base

if TYPE_CHECKING:
    from backend.detection.schemas import StatisticalBaseline


class StatisticalBaselineDB(Base):
    """Database table for statistical baseline profiles (mean, stddev, sample count)."""

    __tablename__ = "statistical_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    baseline_id = Column(String(64), unique=True, index=True, nullable=False)
    entity_type = Column(String(32), index=True, nullable=False)
    entity_id = Column(String(128), index=True, nullable=False)
    window_seconds = Column(Integer, index=True, nullable=False)
    feature_name = Column(String(64), index=True, nullable=False)
    mean = Column(Float, nullable=False)
    stddev = Column(Float, nullable=False)
    sample_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint(
            "entity_type", "entity_id", "window_seconds", "feature_name",
            name="uq_baseline_entity_window_feature"
        ),
        Index("ix_baseline_lookup", "entity_type", "entity_id", "window_seconds"),
    )

    @classmethod
    def from_schema(cls, baseline: "StatisticalBaseline") -> "StatisticalBaselineDB":
        """Convert a StatisticalBaseline Pydantic schema to an ORM entity."""
        et = baseline.entity_type
        if hasattr(et, "value"):
            et = et.value

        return cls(
            baseline_id=baseline.baseline_id,
            entity_type=str(et),
            entity_id=baseline.entity_id,
            window_seconds=baseline.window_seconds,
            feature_name=baseline.feature_name,
            mean=float(baseline.mean),
            stddev=float(baseline.stddev),
            sample_count=int(baseline.sample_count),
            updated_at=baseline.updated_at,
        )

    def to_schema(self) -> "StatisticalBaseline":
        """Convert this database ORM instance back into a StatisticalBaseline Pydantic model."""
        from backend.detection.schemas import StatisticalBaseline
        from backend.features.schemas import EntityType

        return StatisticalBaseline(
            baseline_id=self.baseline_id,
            entity_type=EntityType(self.entity_type),
            entity_id=self.entity_id,
            window_seconds=self.window_seconds,
            feature_name=self.feature_name,
            mean=self.mean,
            stddev=self.stddev,
            sample_count=self.sample_count,
            updated_at=self.updated_at,
        )
