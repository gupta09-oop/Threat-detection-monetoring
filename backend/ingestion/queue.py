"""EventBus abstraction and Dead-Letter mechanism for Sh4d0w_St4lk3r telemetry ingestion.

Exposes an abstract EventBus interface so the in-memory queue can later be replaced
by enterprise streaming systems (Kafka, Redpanda) without altering application routes.
"""

from abc import ABC, abstractmethod
import asyncio
from collections import deque
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from backend.config import settings
from backend.models.canonical import CanonicalEvent

logger = logging.getLogger(__name__)


class BackpressureError(Exception):
    """Raised when the bounded ingestion queue is full, enforcing backpressure."""
    pass


class AbstractEventBus(ABC):
    """Abstract interface for event streaming bus."""

    @abstractmethod
    async def publish(self, event: CanonicalEvent, timeout: Optional[float] = None) -> bool:
        """Publish a single canonical event to the bus."""
        pass

    @abstractmethod
    async def publish_batch(self, events: List[CanonicalEvent], timeout: Optional[float] = None) -> int:
        """Publish a batch of canonical events to the bus."""
        pass

    @abstractmethod
    async def consume(self) -> CanonicalEvent:
        """Retrieve the next event for processing."""
        pass

    @abstractmethod
    def task_done(self) -> None:
        """Signal that a retrieved event was processed."""
        pass

    @abstractmethod
    def qsize(self) -> int:
        """Return the current queue backlog size."""
        pass

    @abstractmethod
    def is_full(self) -> bool:
        """Return True if the buffer has reached maximum capacity."""
        pass


class AsyncInMemoryEventBus(AbstractEventBus):
    """In-memory bounded asyncio event bus adhering to the MVP blueprint."""

    def __init__(self, maxsize: int = 5000):
        self.maxsize = maxsize
        self._queue: Optional[asyncio.Queue[CanonicalEvent]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def queue(self) -> asyncio.Queue[CanonicalEvent]:
        """Return the asyncio queue bound to the current running event loop."""
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if self._queue is None or (current_loop is not None and self._loop != current_loop):
            self._queue = asyncio.Queue(maxsize=self.maxsize)
            self._loop = current_loop
        return self._queue

    async def publish(self, event: CanonicalEvent, timeout: Optional[float] = 0.5) -> bool:
        """Put event into bounded queue. Raises BackpressureError if capacity exceeded."""
        q = self.queue
        if q.full():
            logger.warning("Ingestion EventBus is full (%d items). Backpressure applied.", self.maxsize)
            raise BackpressureError(f"Ingestion queue full (capacity: {self.maxsize})")

        try:
            if timeout is not None:
                await asyncio.wait_for(q.put(event), timeout=timeout)
            else:
                await q.put(event)
            return True
        except asyncio.TimeoutError:
            raise BackpressureError("Ingestion queue timed out waiting for capacity")

    async def publish_batch(self, events: List[CanonicalEvent], timeout: Optional[float] = 1.0) -> int:
        """Publish a batch of events with capacity verification."""
        accepted = 0
        for event in events:
            await self.publish(event, timeout=timeout)
            accepted += 1
        return accepted

    async def consume(self) -> CanonicalEvent:
        """Read the next event from the queue."""
        return await self.queue.get()

    def task_done(self) -> None:
        """Mark task as done in the internal asyncio queue."""
        self.queue.task_done()

    def qsize(self) -> int:
        """Current number of events awaiting consumption."""
        return self.queue.qsize()

    def is_full(self) -> bool:
        """Check if queue has reached capacity."""
        return self.queue.full()


class DeadLetterQueue:
    """Stores rejected and malformed events for inspection and debugging."""

    def __init__(self, max_records: int = 1000):
        self._records: deque[Dict[str, Any]] = deque(maxlen=max_records)

    def record(self, raw_payload: Any, error: str) -> Dict[str, Any]:
        """Record an ingestion failure."""
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error,
            "raw_payload": raw_payload,
        }
        self._records.appendleft(entry)
        logger.warning("Dead-letter event recorded [%s]: %s", entry["id"], error)
        return entry

    def get_failures(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent ingestion failures."""
        return list(self._records)[:limit]

    def count(self) -> int:
        """Get total count of recorded failures."""
        return len(self._records)

    def clear(self) -> None:
        """Clear all records."""
        self._records.clear()


# Global singletons for application lifecycle
event_bus = AsyncInMemoryEventBus(maxsize=settings.INGESTION_QUEUE_MAX_SIZE)
dead_letter_queue = DeadLetterQueue()
