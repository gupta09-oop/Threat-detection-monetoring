"""Unit tests for network connection behavioral features."""

from datetime import datetime, timezone
from backend.features.calculator import FeatureCalculator
from backend.models.canonical import CanonicalEvent, SourceType


def test_network_port_and_destination_diversity():
    """Verify unique port counts and destination IP diversity."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", destination_ip="1.1.1.1", port=80, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", destination_ip="1.1.1.1", port=443, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", destination_ip="2.2.2.2", port=443, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", destination_ip="2.2.2.2", port=8080, protocol="TCP", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    net_features = calc.calculate_network_features(events)

    # 3 distinct ports (80, 443, 8080)
    assert net_features.unique_destination_ports == 3
    # 3 / 4 = 0.75
    assert net_features.port_diversity == 0.75
    # 2 distinct IPs (1.1.1.1, 2.2.2.2) / 4 = 0.50
    assert net_features.destination_diversity == 0.50


def test_network_connection_failure_rate():
    """Verify failed_connection_rate on DENY/DROP outcomes."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", port=443, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="DENY", port=22, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="DROP", port=23, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", port=80, protocol="TCP", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    net_features = calc.calculate_network_features(events)

    # 2 failed / 4 total = 0.50
    assert net_features.failed_connection_rate == 0.50


def test_network_protocol_diversity():
    """Verify protocol diversity calculation."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", port=443, protocol="TCP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", port=53, protocol="UDP", timestamp=now),
        CanonicalEvent(source_type=SourceType.NETWORK, event_type="CONNECTION", result="ALLOW", port=80, protocol="TCP", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    net_features = calc.calculate_network_features(events)

    # 2 unique protocols (TCP, UDP) / 3 events = 0.6667
    assert net_features.protocol_diversity == 0.6667
