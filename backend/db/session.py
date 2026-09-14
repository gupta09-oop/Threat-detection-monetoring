"""Database session, engine configuration, and lifecycle management."""

import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from backend.config import settings

logger = logging.getLogger(__name__)

# SQLite specific arguments (e.g., check_same_thread=False for multithreading in FastAPI)
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DEBUG and settings.LOG_LEVEL.upper() == "DEBUG",
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to yield database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> bool:
    """Initialize database tables and verify connectivity.
    
    Creates table metadata and verifies engine connectivity via SELECT 1.
    """
    try:
        from backend.db.base import Base
        from backend.models.db_event import TelemetryEventDB  # noqa: F401
        from backend.models.feature_snapshot import FeatureSnapshotDB  # noqa: F401
        from backend.models.baseline import StatisticalBaselineDB  # noqa: F401
        from backend.models.anomaly import AnomalyResultDB  # noqa: F401
        from backend.models.fusion import FusionResultDB  # noqa: F401
        from backend.models.risk import RiskScoreDB  # noqa: F401
        from backend.models.alert import AlertDB  # noqa: F401
        from backend.models.case import CaseDB  # noqa: F401

        # Bind existing metadata (creates tables including alerts and cases)
        Base.metadata.create_all(bind=engine)

        # Verify connectivity and run safe schema migration for added columns
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

            # Safely add columns if missing (SQLite ALTER TABLE)
            for col, col_type in [
                ("assigned_analyst", "VARCHAR(128)"),
                ("resolution", "VARCHAR(64)"),
                ("resolution_notes", "TEXT"),
            ]:
                try:
                    connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}"))
                    connection.commit()
                except Exception:
                    pass

            for col, col_type in [
                ("resolution", "VARCHAR(64)"),
                ("assigned_analyst", "VARCHAR(128)"),
            ]:
                try:
                    connection.execute(text(f"ALTER TABLE cases ADD COLUMN {col} {col_type}"))
                    connection.commit()
                except Exception:
                    pass

        logger.info("Database initialized and connection verified successfully.")
        return True
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc, exc_info=True)
        raise
