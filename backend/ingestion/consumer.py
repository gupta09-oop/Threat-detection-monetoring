"""Background consumer that ingests canonical events asynchronously into SQLite."""

import asyncio
import logging
from typing import List, Optional

from backend.config import settings
from backend.db.session import SessionLocal
from backend.ingestion.queue import AbstractEventBus, event_bus as default_event_bus
from backend.models.canonical import CanonicalEvent
from backend.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)


class BackgroundEventConsumer:
    """Consumes canonical events from the EventBus and persists them in SQLite.
    
    Operates in non-blocking fashion using micro-batching for high throughput.
    """

    def __init__(
        self,
        bus: Optional[AbstractEventBus] = None,
        batch_size: int = settings.INGESTION_BATCH_SIZE,
        flush_interval: float = settings.INGESTION_FLUSH_INTERVAL,
    ):
        self.bus = bus or default_event_bus
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the background consumer loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume_loop())
        logger.info(
            "BackgroundEventConsumer started (batch_size=%d, flush_interval=%.2fs).",
            self.batch_size,
            self.flush_interval,
        )

    async def stop(self) -> None:
        """Stop the background consumer and drain remaining events."""
        if not self._running:
            return
        logger.info("Stopping BackgroundEventConsumer, draining remaining backlog...")
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        # Drain any leftover events in the queue
        await self._drain_remaining()
        logger.info("BackgroundEventConsumer stopped successfully.")

    async def _consume_loop(self) -> None:
        """Main processing loop gathering micro-batches."""
        while self._running:
            batch: List[CanonicalEvent] = []
            try:
                # Wait for the first event
                event = await self.bus.consume()
                batch.append(event)

                # Attempt to grab additional items up to batch_size without long blocking
                deadline = asyncio.get_event_loop().time() + self.flush_interval
                while len(batch) < self.batch_size:
                    timeout = deadline - asyncio.get_event_loop().time()
                    if timeout <= 0:
                        break
                    try:
                        # Wait shortly for further arrivals
                        next_event = await asyncio.wait_for(self.bus.consume(), timeout=max(0.01, timeout))
                        batch.append(next_event)
                    except (asyncio.TimeoutError, asyncio.QueueEmpty):
                        break

                # Persist collected batch
                self._persist_batch(batch)

                # Acknowledge tasks
                for _ in batch:
                    self.bus.task_done()

            except asyncio.CancelledError:
                if batch:
                    self._persist_batch(batch)
                    for _ in batch:
                        self.bus.task_done()
                break
            except Exception as exc:
                logger.error("Error in background consumer loop: %s", exc, exc_info=True)
                await asyncio.sleep(0.1)

    def _persist_batch(self, batch: List[CanonicalEvent]) -> None:
        """Persist a batch of events to SQLite using a dedicated database session."""
        if not batch:
            return

        db = SessionLocal()
        try:
            repo = EventRepository(db)
            repo.create_batch_events(batch)
            logger.debug("Persisted batch of %d telemetry events to SQLite.", len(batch))
        except Exception as exc:
            logger.error("Failed to persist event batch to SQLite: %s", exc, exc_info=True)
            db.rollback()
        finally:
            db.close()

    async def _drain_remaining(self) -> None:
        """Process any remaining items left in the queue upon shutdown."""
        batch: List[CanonicalEvent] = []
        while self.bus.qsize() > 0:
            try:
                event = await asyncio.wait_for(self.bus.consume(), timeout=0.1)
                batch.append(event)
                if len(batch) >= self.batch_size:
                    self._persist_batch(batch)
                    for _ in batch:
                        self.bus.task_done()
                    batch = []
            except (asyncio.TimeoutError, Exception):
                break

        if batch:
            self._persist_batch(batch)
            for _ in batch:
                self.bus.task_done()


# Global consumer instance
consumer = BackgroundEventConsumer()
