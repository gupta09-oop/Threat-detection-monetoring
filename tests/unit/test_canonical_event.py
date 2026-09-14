"""Unit tests for CanonicalEvent validation, rules, and telemetry normalization."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from backend.models.canonical import CanonicalEvent, SourceType
from backend.models.telemetry import (
    AuthTelemetry,
    NetworkTelemetry,
    SystemTelemetry,
    normalize_event,
)


def test_canonical_event_valid_creation():
    """Verify CanonicalEvent creates cleanly with required fields."""
    event = CanonicalEvent(
        source_type=SourceType.AUTH,
        event_type="LOGIN",
        result="SUCCESS",
        user_id="alice.smith",
        source_ip="192.168.1.100",
    )
    assert event.event_id is not None
    assert event.timestamp is not None
    assert event.source_type == "AUTH"
    assert event.event_type == "LOGIN"
    assert event.result == "SUCCESS"
    assert event.user_id == "alice.smith"


def test_canonical_event_missing_required_fields_rejected():
    """Verify missing required fields raise ValidationError."""
    # Missing result and event_type
    with pytest.raises(ValidationError):
        CanonicalEvent(source_type=SourceType.AUTH, user_id="alice")

    # Missing source_type
    with pytest.raises(ValidationError):
        CanonicalEvent(event_type="LOGIN", result="SUCCESS")


def test_auth_event_validation_rules():
    """Verify source-conditional rules for AUTH events."""
    # AUTH with neither user_id nor source_ip must fail
    with pytest.raises(ValidationError) as exc:
        CanonicalEvent(
            source_type=SourceType.AUTH,
            event_type="LOGIN",
            result="SUCCESS",
        )
    assert "AUTH events require at least 'user_id' or 'source_ip'" in str(exc.value)

    # AUTH with user_id succeeds
    e1 = CanonicalEvent(
        source_type=SourceType.AUTH,
        event_type="LOGIN",
        result="SUCCESS",
        user_id="admin",
    )
    assert e1.user_id == "admin"

    # AUTH with source_ip succeeds
    e2 = CanonicalEvent(
        source_type=SourceType.AUTH,
        event_type="LOGIN",
        result="FAILURE",
        source_ip="10.0.0.1",
    )
    assert e2.source_ip == "10.0.0.1"


def test_network_event_validation_rules():
    """Verify source-conditional rules for NETWORK events."""
    # NETWORK with no destination, port, or protocol must fail
    with pytest.raises(ValidationError) as exc:
        CanonicalEvent(
            source_type=SourceType.NETWORK,
            event_type="CONNECTION",
            result="ALLOW",
            source_ip="10.0.0.5",
        )
    assert "NETWORK events require at least one network context field" in str(exc.value)

    # NETWORK with destination_ip succeeds
    net1 = CanonicalEvent(
        source_type=SourceType.NETWORK,
        event_type="CONNECTION",
        result="ALLOW",
        destination_ip="172.16.0.1",
    )
    assert net1.destination_ip == "172.16.0.1"

    # Invalid port range must fail Pydantic bounds
    with pytest.raises(ValidationError):
        CanonicalEvent(
            source_type=SourceType.NETWORK,
            event_type="CONNECTION",
            result="ALLOW",
            port=99999,
        )


def test_system_event_validation_rules():
    """Verify source-conditional rules for SYSTEM events."""
    # SYSTEM with no host or process context must fail
    with pytest.raises(ValidationError) as exc:
        CanonicalEvent(
            source_type=SourceType.SYSTEM,
            event_type="PROCESS_START",
            result="SUCCESS",
        )
    assert "SYSTEM events require host or process context" in str(exc.value)

    # SYSTEM with device_id succeeds
    sys1 = CanonicalEvent(
        source_type=SourceType.SYSTEM,
        event_type="PROCESS_START",
        result="SUCCESS",
        device_id="SERVER-01",
    )
    assert sys1.device_id == "SERVER-01"

    # SYSTEM with process in metadata succeeds
    sys2 = CanonicalEvent(
        source_type=SourceType.SYSTEM,
        event_type="FILE_WRITE",
        result="SUCCESS",
        metadata={"process": "bash", "host": "srv-prod"},
    )
    assert sys2.metadata["process"] == "bash"


def test_auth_telemetry_normalization():
    """Verify AuthTelemetry converts cleanly to CanonicalEvent."""
    raw = AuthTelemetry(
        source_ip="10.0.10.15",
        user_id="alice.smith",
        login_result="SUCCESS",
        auth_method="MFA",
        device_id="DEV-01",
        geo_country="US",
        geo_city="New York",
        user_agent="Chrome/122",
        session_id="sess_123",
    )
    canonical = raw.to_canonical()
    assert canonical.source_type == "AUTH"
    assert canonical.event_type == "LOGIN"
    assert canonical.result == "SUCCESS"
    assert canonical.user_id == "alice.smith"
    assert canonical.device_id == "DEV-01"
    assert canonical.geo == {"country": "US", "city": "New York"}
    assert canonical.metadata["auth_method"] == "MFA"
    assert canonical.metadata["session_id"] == "sess_123"


def test_network_telemetry_normalization():
    """Verify NetworkTelemetry converts cleanly to CanonicalEvent."""
    raw = NetworkTelemetry(
        source_ip="10.0.10.15",
        destination_ip="142.250.190.46",
        destination_port=443,
        protocol="tcp",
        bytes_sent=1500,
        bytes_received=4500,
        connection_result="allow",
    )
    canonical = raw.to_canonical()
    assert canonical.source_type == "NETWORK"
    assert canonical.port == 443
    assert canonical.protocol == "TCP"
    assert canonical.bytes == 6000
    assert canonical.result == "ALLOW"


def test_system_telemetry_normalization():
    """Verify SystemTelemetry converts cleanly to CanonicalEvent."""
    raw = SystemTelemetry(
        host="DEV-CORP-LNX-01",
        process="sshd",
        event_type="PROCESS_START",
        username="root",
        resource="/usr/sbin/sshd",
    )
    canonical = raw.to_canonical()
    assert canonical.source_type == "SYSTEM"
    assert canonical.device_id == "DEV-CORP-LNX-01"
    assert canonical.user_id == "root"
    assert canonical.event_type == "PROCESS_START"
    assert canonical.metadata["process"] == "sshd"
    assert canonical.metadata["resource"] == "/usr/sbin/sshd"


def test_normalize_event_dictionary_inference():
    """Verify normalize_event correctly auto-detects raw dictionary types."""
    # Auth dict
    auth_dict = {
        "source_ip": "1.2.3.4",
        "user_id": "bob",
        "login_result": "SUCCESS",
    }
    c_auth = normalize_event(auth_dict)
    assert c_auth.source_type == "AUTH"
    assert c_auth.user_id == "bob"

    # Network dict
    net_dict = {
        "source_ip": "1.2.3.4",
        "destination_ip": "5.6.7.8",
        "destination_port": 80,
        "protocol": "TCP",
        "connection_result": "ALLOW",
    }
    c_net = normalize_event(net_dict)
    assert c_net.source_type == "NETWORK"
    assert c_net.port == 80

    # System dict
    sys_dict = {
        "host": "HOST-01",
        "process": "cron",
        "event_type": "PROCESS_START",
    }
    c_sys = normalize_event(sys_dict)
    assert c_sys.source_type == "SYSTEM"
    assert c_sys.device_id == "HOST-01"
