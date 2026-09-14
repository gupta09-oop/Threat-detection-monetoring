"""Pytest test fixtures and configuration."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import init_db


@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    """Ensure database is initialized before running tests."""
    init_db()


@pytest.fixture
def client():
    """Yield a FastAPI TestClient instance."""
    with TestClient(app) as test_client:
        yield test_client
