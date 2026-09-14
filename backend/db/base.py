"""SQLAlchemy Declarative Base for Sh4d0w_St4lk3r.

Designed to be repository-friendly and compatible across SQLite during Phase 1
and future PostgreSQL/TimescaleDB migrations.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass
