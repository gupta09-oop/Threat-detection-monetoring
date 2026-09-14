"""Telemetry schemas and canonical normalization for Sh4d0w_St4lk3r.

Defines the three raw telemetry schemas (AUTH, NETWORK, SYSTEM) from the
architecture blueprint and their automatic conversion to the CanonicalEvent model.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field

from backend.models.canonical import CanonicalEvent, SourceType


class AuthTelemetry(BaseModel):
    """Raw authentication telemetry schema."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event timestamp"
    )
    source_ip: str = Field(..., description="Client originating IP address")
    user_id: str = Field(..., min_length=1, description="Target username or identifier")
    login_result: str = Field(..., min_length=1, description="Outcome of authentication (e.g. SUCCESS, FAILURE)")
    auth_method: Optional[str] = Field(default=None, description="Mechanism used (e.g. PASSWORD, MFA, SSO)")
    device_id: Optional[str] = Field(default=None, description="Client device identifier")
    geo_country: Optional[str] = Field(default=None, description="Country of origin")
    geo_city: Optional[str] = Field(default=None, description="City of origin")
    user_agent: Optional[str] = Field(default=None, description="Client browser or agent string")
    session_id: Optional[str] = Field(default=None, description="Session token or identifier")

    def to_canonical(self) -> CanonicalEvent:
        """Convert raw authentication telemetry into canonical event format."""
        geo: Dict[str, Any] = {}
        if self.geo_country:
            geo["country"] = self.geo_country
        if self.geo_city:
            geo["city"] = self.geo_city

        metadata: Dict[str, Any] = {}
        if self.auth_method:
            metadata["auth_method"] = self.auth_method
        if self.user_agent:
            metadata["user_agent"] = self.user_agent
        if self.session_id:
            metadata["session_id"] = self.session_id

        return CanonicalEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self.timestamp,
            source_type=SourceType.AUTH,
            source_ip=self.source_ip,
            user_id=self.user_id,
            device_id=self.device_id,
            event_type="LOGIN",
            action="AUTHENTICATE",
            result=self.login_result.upper(),
            geo=geo if geo else None,
            metadata=metadata,
        )


class NetworkTelemetry(BaseModel):
    """Raw network connection/flow telemetry schema."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Flow timestamp"
    )
    source_ip: str = Field(..., description="Source IPv4/IPv6 address")
    destination_ip: str = Field(..., description="Destination IPv4/IPv6 address")
    destination_port: int = Field(..., ge=1, le=65535, description="Target port number")
    protocol: str = Field(..., description="Protocol (e.g. TCP, UDP, ICMP)")
    bytes_sent: Optional[int] = Field(default=0, ge=0, description="Outbound bytes")
    bytes_received: Optional[int] = Field(default=0, ge=0, description="Inbound bytes")
    connection_result: str = Field(..., description="Flow outcome (e.g. ALLOW, DENY, ESTABLISHED, CLOSED)")

    def to_canonical(self) -> CanonicalEvent:
        """Convert raw network telemetry into canonical event format."""
        total_bytes = (self.bytes_sent or 0) + (self.bytes_received or 0)
        metadata = {
            "bytes_sent": self.bytes_sent or 0,
            "bytes_received": self.bytes_received or 0,
        }

        return CanonicalEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self.timestamp,
            source_type=SourceType.NETWORK,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            port=self.destination_port,
            protocol=self.protocol.upper(),
            bytes=total_bytes,
            event_type="CONNECTION",
            action="FLOW",
            result=self.connection_result.upper(),
            metadata=metadata,
        )


class SystemTelemetry(BaseModel):
    """Raw host/system activity telemetry schema."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event timestamp"
    )
    host: str = Field(..., min_length=1, description="Host machine name or identifier")
    process: str = Field(..., min_length=1, description="Process executable name or command")
    event_type: str = Field(..., min_length=1, description="Activity type (e.g. PROCESS_START, FILE_WRITE)")
    username: Optional[str] = Field(default=None, description="Executing system user")
    resource: Optional[str] = Field(default=None, description="Target file, socket, or registry key")

    def to_canonical(self) -> CanonicalEvent:
        """Convert raw system telemetry into canonical event format."""
        metadata = {
            "host": self.host,
            "process": self.process,
        }
        if self.resource:
            metadata["resource"] = self.resource

        return CanonicalEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self.timestamp,
            source_type=SourceType.SYSTEM,
            device_id=self.host,
            user_id=self.username,
            event_type=self.event_type.upper(),
            action=self.process,
            result="SUCCESS",
            metadata=metadata,
        )


def normalize_event(
    payload: Union[CanonicalEvent, AuthTelemetry, NetworkTelemetry, SystemTelemetry, Dict[str, Any]]
) -> CanonicalEvent:
    """Normalize any supported telemetry format or dictionary into a CanonicalEvent.

    Raises ValueError / ValidationError if payload cannot be normalized or validated.
    """
    if isinstance(payload, CanonicalEvent):
        return payload

    if isinstance(payload, (AuthTelemetry, NetworkTelemetry, SystemTelemetry)):
        return payload.to_canonical()

    if isinstance(payload, dict):
        # Check if it already contains source_type matching CanonicalEvent
        source_type = payload.get("source_type")
        if source_type:
            return CanonicalEvent.model_validate(payload)

        # Detect raw telemetry types based on key signatures
        if "login_result" in payload:
            return AuthTelemetry.model_validate(payload).to_canonical()
        if "destination_port" in payload and "protocol" in payload:
            return NetworkTelemetry.model_validate(payload).to_canonical()
        if "host" in payload and "process" in payload:
            return SystemTelemetry.model_validate(payload).to_canonical()

        # Fallback: attempt direct CanonicalEvent parsing
        return CanonicalEvent.model_validate(payload)

    raise ValueError(f"Unsupported event payload type: {type(payload)}")
