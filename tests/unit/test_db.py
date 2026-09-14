"""Unit tests for database initialization and connectivity."""

from sqlalchemy import text
from sqlalchemy.orm import Session
from backend.db.session import init_db, engine, get_db


def test_database_initialization_succeeds():
    """Verify that database initialization completes without error."""
    result = init_db()
    assert result is True


def test_database_connectivity():
    """Verify that SQLAlchemy engine can connect and execute a basic query."""
    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1")).scalar()
        assert result == 1


def test_database_session_dependency():
    """Verify that get_db yields an active SQLAlchemy session and completes cleanly."""
    db_gen = get_db()
    session = next(db_gen)
    assert isinstance(session, Session)
    # Verify session can execute a query
    result = session.execute(text("SELECT 1")).scalar()
    assert result == 1
    # Clean up generator (should close session and raise StopIteration)
    try:
        next(db_gen)
        assert False, "get_db generator should terminate after one yield"
    except StopIteration:
        pass
