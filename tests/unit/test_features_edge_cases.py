"""Unit tests for cold/empty windows, division-by-zero, and determinism."""

from datetime import datetime, timezone
import math
from backend.features.calculator import FeatureCalculator
from backend.models.canonical import CanonicalEvent, SourceType


def test_empty_window_safety():
    """Verify zero events produce safe 0.0 values without NaN, Inf, or ZeroDivisionError."""
    calc = FeatureCalculator(window_seconds=60)
    flat_features, relationships = calc.calculate_all([])

    assert len(flat_features) > 0
    for name, value in flat_features.items():
        assert not math.isnan(value), f"Feature {name} is NaN"
        assert not math.isinf(value), f"Feature {name} is Infinite"
        assert value == 0.0, f"Expected 0.0 for empty window, got {value} for {name}"

    assert relationships["ip_to_accounts"] == {}
    assert relationships["ip_to_ports"] == {}


def test_single_event_safety():
    """Verify 1 event does not trigger division-by-zero or out-of-bounds calculations."""
    now = datetime.now(timezone.utc)
    single_event = [
        CanonicalEvent(
            source_type=SourceType.AUTH,
            event_type="LOGIN",
            result="SUCCESS",
            user_id="alice",
            source_ip="10.0.0.1",
            timestamp=now,
        )
    ]
    calc = FeatureCalculator(window_seconds=300)
    flat_features, relationships = calc.calculate_all(single_event)

    assert flat_features["success_rate"] == 1.0
    assert flat_features["failed_login_rate"] == 0.0
    assert flat_features["time_deviation"] == 0.0  # 1 event -> 0.0 deviation
    assert flat_features["unique_accounts_targeted"] == 1
    assert flat_features["unique_source_ips"] == 1

    for name, value in flat_features.items():
        assert not math.isnan(value), f"Feature {name} is NaN"
        assert not math.isinf(value), f"Feature {name} is Infinite"


def test_missing_optional_fields_safety():
    """Verify events with null ports, null users, and null devices are safely processed."""
    now = datetime.now(timezone.utc)
    sparse_events = [
        CanonicalEvent(
            source_type=SourceType.NETWORK,
            event_type="CONNECTION",
            result="ALLOW",
            destination_ip="8.8.8.8",
            timestamp=now,
            # port, protocol, bytes, source_ip all None
        ),
        CanonicalEvent(
            source_type=SourceType.SYSTEM,
            event_type="PROCESS_START",
            result="SUCCESS",
            device_id="HOST-01",
            timestamp=now,
            # user_id, source_ip all None
        ),
    ]
    calc = FeatureCalculator(window_seconds=60)
    flat_features, relationships = calc.calculate_all(sparse_events)

    for name, value in flat_features.items():
        assert not math.isnan(value)
        assert not math.isinf(value)


def test_deterministic_feature_calculation():
    """Verify identical event collections produce identical feature dictionaries."""
    t0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="alice", source_ip="10.0.0.1", timestamp=t0),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", destination_ip="1.1.1.1", port=443, timestamp=t0),
    ]

    calc = FeatureCalculator(window_seconds=60)
    res1, _ = calc.calculate_all(events)
    res2, _ = calc.calculate_all(events)

    assert res1 == res2, "Feature calculation must be strictly deterministic"
