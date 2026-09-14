"""Unit tests for authentication behavioral feature calculations across windows."""

from datetime import datetime, timedelta, timezone
from backend.features.calculator import FeatureCalculator
from backend.features.windows import FeatureWindow
from backend.models.canonical import CanonicalEvent, SourceType


def test_auth_success_and_failure_rates():
    """Verify failed_login_rate and success_rate calculations."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="alice", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="alice", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="FAILURE", user_id="alice", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="FAILURE", user_id="alice", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    features = calc.calculate_auth_features(events)

    assert features.success_rate == 0.50
    assert features.failed_login_rate == 0.50


def test_unique_ip_and_account_diversities():
    """Verify unique counting and diversity metrics for IPs and accounts."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="user1", source_ip="10.0.0.1", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="user2", source_ip="10.0.0.2", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="user3", source_ip="10.0.0.3", timestamp=now),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="user3", source_ip="10.0.0.3", timestamp=now),
    ]
    calc = FeatureCalculator(window_seconds=60)
    features = calc.calculate_auth_features(events)

    assert features.unique_accounts_targeted == 3
    assert features.unique_source_ips == 3
    # 3 unique / 4 events = 0.75
    assert features.account_diversity == 0.75
    assert features.ip_diversity == 0.75


def test_geo_and_device_diversities():
    """Verify distinct device and geo point diversity calculations."""
    now = datetime.now(timezone.utc)
    events = [
        CanonicalEvent(
            source_type=SourceType.AUTH,
            event_type="LOGIN",
            result="SUCCESS",
            user_id="u1",
            device_id="DEV-A",
            geo={"country": "US", "city": "NYC"},
            timestamp=now,
        ),
        CanonicalEvent(
            source_type=SourceType.AUTH,
            event_type="LOGIN",
            result="SUCCESS",
            user_id="u1",
            device_id="DEV-B",
            geo={"country": "UK", "city": "London"},
            timestamp=now,
        ),
    ]
    calc = FeatureCalculator(window_seconds=60)
    features = calc.calculate_auth_features(events)

    assert features.device_diversity == 1.0
    assert features.geo_diversity == 1.0


def test_login_frequency_and_time_deviation_across_windows():
    """Verify login frequency scaling across 60s, 5m (300s), and 15m (900s) windows."""
    t0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="u", timestamp=t0),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="u", timestamp=t0 + timedelta(seconds=10)),
        CanonicalEvent(source_type=SourceType.AUTH, event_type="LOGIN", result="SUCCESS", user_id="u", timestamp=t0 + timedelta(seconds=20)),
    ]

    calc_60s = FeatureCalculator(window_seconds=FeatureWindow.WINDOW_60S)
    f_60 = calc_60s.calculate_auth_features(events)
    # 3 events / 60 seconds = 0.05
    assert f_60.login_frequency == 0.05
    assert f_60.time_deviation == 0.0  # Equal 10s intervals -> 0 standard deviation

    calc_300s = FeatureCalculator(window_seconds=FeatureWindow.WINDOW_5M)
    f_300 = calc_300s.calculate_auth_features(events)
    # 3 events / 300 seconds = 0.01
    assert f_300.login_frequency == 0.01

    calc_900s = FeatureCalculator(window_seconds=FeatureWindow.WINDOW_15M)
    f_900 = calc_900s.calculate_auth_features(events)
    # 3 events / 900 seconds = 0.0033
    assert f_900.login_frequency == 0.0033
