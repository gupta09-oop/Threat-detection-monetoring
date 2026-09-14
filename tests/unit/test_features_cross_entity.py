"""Unit tests for cross-entity ratios, distributed indicators, and relationship extraction."""

from datetime import datetime, timedelta, timezone
from backend.features.calculator import FeatureCalculator
from backend.models.canonical import CanonicalEvent, SourceType


def test_ip_to_account_ratios():
    """Verify IP-to-Account and Account-to-IP ratios."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", source_ip="10.0.0.1", user_id="target_admin", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", source_ip="10.0.0.2", user_id="target_admin", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", source_ip="10.0.0.3", user_id="target_admin", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    features = calc.calculate_cross_entity_features(events)

    # 3 distinct IPs targeting 1 account -> ratio = 3.0
    assert features.ip_to_account_ratio == 3.0
    # 1 account / 3 IPs = 0.3333
    assert features.accounts_to_ip_ratio == 0.3333


def test_distributed_attempt_score():
    """Verify distributed attempt score is elevated when distinct IPs target accounts."""
    now = datetime.now(timezone.utc)
    # Single IP targeting 3 accounts: not distributed
    single_ip_events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="FAILURE", source_ip="10.0.0.1", user_id="u1", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="FAILURE", source_ip="10.0.0.1", user_id="u2", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="FAILURE", source_ip="10.0.0.1", user_id="u3", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    f_single = calc.calculate_cross_entity_features(single_ip_events)
    assert f_single.distributed_attempt_score == 0.0

    # 5 distinct IPs targeting the same account: highly distributed
    distributed_events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="FAILURE", source_ip=f"10.0.0.{i}", user_id="victim", timestamp=now)
        for i in range(1, 6)
    ]
    f_dist = calc.calculate_cross_entity_features(distributed_events)
    assert f_dist.distributed_attempt_score > 0.5


def test_temporal_concentration_burst_vs_spread():
    """Verify bursty traffic produces higher temporal concentration than evenly distributed traffic."""
    t0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)

    # 10 events all occurring in the same microsecond (concentrated)
    burst_events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="alice", timestamp=t0)
        for _ in range(10)
    ]
    calc = FeatureCalculator(window_seconds=60)
    f_burst = calc.calculate_cross_entity_features(burst_events)
    assert f_burst.temporal_concentration == 1.0

    # 10 events evenly spaced across 50 seconds (spread)
    spread_events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="alice", timestamp=t0 + timedelta(seconds=i * 5))
        for i in range(10)
    ]
    f_spread = calc.calculate_cross_entity_features(spread_events)
    assert f_spread.temporal_concentration < 0.5


def test_entity_relationships_extraction():
    """Verify extraction of IP-to-Account, IP-to-Device, Account-to-IP, and IP-to-Port relationships."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(
            source_type=SourceType.AUTH,
            event_type="LOGIN",
            result="SUCCESS",
            source_ip="192.168.1.50",
            user_id="bob",
            device_id="DEV-01",
            timestamp=now,
        ),
        CanonicalEvent(
            source_type=SourceType.NETWORK,
            event_type="CONNECTION",
            result="ALLOW",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            port=443,
            timestamp=now,
        ),
    ]
    calc = FeatureCalculator(window_seconds=60)
    relationships = calc.extract_entity_relationships(events)

    assert "bob" in relationships.ip_to_accounts["192.168.1.50"]
    assert "DEV-01" in relationships.ip_to_devices["192.168.1.50"]
    assert "192.168.1.50" in relationships.account_to_ips["bob"]
    assert 443 in relationships.ip_to_ports["192.168.1.50"]
    assert "10.0.0.1" in relationships.ip_to_destinations["192.168.1.50"]
