"""Canonical normalized event model for Sh4d0w_St4lk3r.

This model is the unified security telemetry representation defined by the
architecture blueprint. All telemetry types (AUTH, NETWORK, SYSTEM) are normalized
into this canonical structure before queueing and behavioral analysis.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, model_validator


class SourceType(str, Enum):
    """Supported telemetry source categories."""
    AUTH = "AUTH"
    NETWORK = "NETWORK"
    SYSTEM = "SYSTEM"


class CanonicalEvent(BaseModel):
    """Canonical normalized telemetry event."""

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        extra="ignore",
    )

    # Required core fields
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the telemetry event"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the event occurred"
    )
    source_type: SourceType = Field(
        ...,
        description="Telemetry source type: AUTH, NETWORK, or SYSTEM"
    )
    event_type: str = Field(
        ...,
        min_length=1,
        description="Specific event identifier (e.g. LOGIN, CONNECTION, PROCESS_START)"
    )
    result: str = Field(
        ...,
        min_length=1,
        description="Outcome of the event (e.g. SUCCESS, FAILURE, ALLOW, DENY)"
    )

    # Contextual and entity identifiers
    source_ip: Optional[str] = Field(default=None, description="Originating IPv4/IPv6 address")
    destination_ip: Optional[str] = Field(default=None, description="Target IPv4/IPv6 address")
    user_id: Optional[str] = Field(default=None, description="Username or account identifier")
    device_id: Optional[str] = Field(default=None, description="Host or device identifier")
    action: Optional[str] = Field(default=None, description="Action attempted or executed")

    # Network-specific attributes
    port: Optional[int] = Field(default=None, ge=1, le=65535, description="Destination or service port")
    protocol: Optional[str] = Field(default=None, description="Transport/application protocol (e.g. TCP, UDP)")
    bytes: Optional[int] = Field(default=None, ge=0, description="Total transferred bytes")

    # Geolocation and extended metadata
    geo: Optional[Dict[str, Any]] = Field(default=None, description="Geolocation data (country, city, coords)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary source-specific attributes")

    @model_validator(mode="after")
    def validate_source_conditional_rules(self) -> "CanonicalEvent":
        """Apply source-conditional validation rules specified in the architecture blueprint."""
        st = self.source_type
        if isinstance(st, Enum):
            st = st.value

        if st == SourceType.AUTH.value:
            # AUTH events must provide user identity or originating IP
            if not self.user_id and not self.source_ip:
                raise ValueError("AUTH events require at least 'user_id' or 'source_ip'")

        elif st == SourceType.NETWORK.value:
            # NETWORK events must provide network connectivity context
            has_dest = bool(self.destination_ip)
            has_port = self.port is not None
            has_proto = bool(self.protocol)
            if not (has_dest or has_port or has_proto):
                raise ValueError(
                    "NETWORK events require at least one network context field: "
                    "'destination_ip', 'port', or 'protocol'"
                )

        elif st == SourceType.SYSTEM.value:
            # SYSTEM events must validate host/process/system context
            has_host = bool(self.device_id or self.metadata.get("host"))
            has_process = bool(self.action or self.metadata.get("process"))
            if not (has_host or has_process):
                raise ValueError(
                    "SYSTEM events require host or process context in 'device_id', "
                    "'action', or metadata ('host', 'process')"
                )

        return self
