"""Ingestion package for Sh4d0w_St4lk3r telemetry pipelines."""

from backend.ingestion.queue import (
    AbstractEventBus,
    AsyncInMemoryEventBus,
    DeadLetterQueue,
    BackpressureError,
    event_bus,
    dead_letter_queue,
)
from backend.ingestion.consumer import BackgroundEventConsumer, consumer

__all__ = [
    "AbstractEventBus",
    "AsyncInMemoryEventBus",
    "DeadLetterQueue",
    "BackpressureError",
    "event_bus",
    "dead_letter_queue",
    "BackgroundEventConsumer",
    "consumer",
]
