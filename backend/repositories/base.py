"""Base repository interface to decouple persistence from application logic.

Provides a clean abstraction over SQLAlchemy sessions to ensure the future
migration path to PostgreSQL/TimescaleDB is seamless without refactoring domain logic.
"""

from typing import Generic, TypeVar, Type, Optional, List, Any
from sqlalchemy.orm import Session
from backend.db.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Generic repository providing standard data access operations."""

    def __init__(self, model: Type[ModelType], db: Session):
        self.model = model
        self.db = db

    def get_by_id(self, id: Any) -> Optional[ModelType]:
        """Retrieve a single record by primary key."""
        return self.db.query(self.model).filter(self.model.id == id).first()

    def list(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        """Retrieve records with pagination."""
        return self.db.query(self.model).offset(skip).limit(limit).all()

    def add(self, entity: ModelType) -> ModelType:
        """Persist a new entity to the database."""
        self.db.add(entity)
        self.db.commit()
        self.db.refresh(entity)
        return entity

    def delete(self, entity: ModelType) -> None:
        """Remove an entity from the database."""
        self.db.delete(entity)
        self.db.commit()
