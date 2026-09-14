"""Unit tests for EventBus, bounded queue backpressure, and DeadLetterQueue."""

import pytest
from backend.models.canonical import CanonicalEvent, SourceType
from backend.ingestion.queue import (
    AsyncInMemoryEventBus,
    BackpressureError,
    DeadLetterQueue,
)


@pytest.mark.anyio
async def test_event_bus_publish_and_consume():
    """Verify standard publish and consume on the EventBus."""
    bus = AsyncInMemoryEventBus(maxsize=10)
    event = CanonicalEvent(
        source_type=SourceType.AUTH,
        event_type="LOGIN",
        result="SUCCESS",
        user_id="test.user",
    )

    published = await bus.publish(event)
    assert published is True
    assert bus.qsize() == 1

    consumed = await bus.consume()
    assert consumed.event_id == event.event_id
    assert consumed.user_id == "test.user"
    bus.task_done()
    assert bus.qsize() == 0


@pytest.mark.anyio
async def test_bounded_queue_backpressure():
    """Verify that exceeding bounded queue capacity raises BackpressureError."""
    small_bus = AsyncInMemoryEventBus(maxsize=2)
    e1 = CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="u1")
    e2 = CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="u2")
    e3 = CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="u3")

    await small_bus.publish(e1)
    await small_bus.publish(e2)
    assert small_bus.is_full() is True

    # 3rd publish must raise BackpressureError immediately
    with pytest.raises(BackpressureError):
        await small_bus.publish(e3, timeout=0.05)


def test_dead_letter_queue_recording():
    """Verify DeadLetterQueue records malformed events and retrieves them."""
    dlq = DeadLetterQueue(max_records=5)
    bad_payload = {"malformed": "data", "missing": "fields"}
    record = dlq.record(bad_payload, error="Validation failed: missing source_type")

    assert dlq.count() == 1
    assert record["error"] == "Validation failed: missing source_type"
    assert record["raw_payload"] == bad_payload

    failures = dlq.get_failures(limit=10)
    assert len(failures) == 1
    assert failures[0]["id"] == record["id"]

    dlq.clear()
    assert dlq.count() == 0
