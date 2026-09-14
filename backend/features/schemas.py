"""Pydantic schemas for behavioral features, vectors, and snapshots."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class EntityType(str, Enum):
    """Dimensions along which behavioral features are aggregated."""
    USER = "USER"
    IP = "IP"
    HOST = "HOST"
    GLOBAL = "GLOBAL"


class AuthFeatures(BaseModel):
    """Authentication behavioral features."""
    failed_login_rate: float = Field(default=0.0, description="Ratio of failed logins to total auth events")
    success_rate: float = Field(default=0.0, description="Ratio of successful logins to total auth events")
    unique_accounts_targeted: int = Field(default=0, description="Count of distinct user IDs observed")
    unique_source_ips: int = Field(default=0, description="Count of distinct client IPs observed")
    ip_diversity: float = Field(default=0.0, description="Distinct IPs divided by total auth events")
    account_diversity: float = Field(default=0.0, description="Distinct accounts divided by total auth events")
    geo_diversity: float = Field(default=0.0, description="Distinct geo locations divided by total auth events")
    device_diversity: float = Field(default=0.0, description="Distinct device IDs divided by total auth events")
    login_frequency: float = Field(default=0.0, description="Auth events per second across the window")
    time_deviation: float = Field(default=0.0, description="Std deviation of inter-arrival time in seconds")


class NetworkFeatures(BaseModel):
    """Network connection behavioral features."""
    unique_destination_ports: int = Field(default=0, description="Count of distinct target ports observed")
    port_diversity: float = Field(default=0.0, description="Distinct ports divided by total network events")
    connection_rate: float = Field(default=0.0, description="Network events per second across the window")
    destination_diversity: float = Field(default=0.0, description="Distinct destination IPs divided by total network events")
    failed_connection_rate: float = Field(default=0.0, description="Ratio of failed/denied connections to total network events")
    protocol_diversity: float = Field(default=0.0, description="Distinct protocols divided by total network events")


class CrossEntityFeatures(BaseModel):
    """Cross-entity and distributed attack indicator features."""
    ip_to_account_ratio: float = Field(default=0.0, description="Unique source IPs per targeted account")
    accounts_to_ip_ratio: float = Field(default=0.0, description="Targeted accounts per source IP")
    distributed_attempt_score: float = Field(default=0.0, description="Metric measuring dispersion across distributed IPs")
    temporal_concentration: float = Field(default=0.0, description="Clustering of events in time (burstiness)")
    source_diversity: float = Field(default=0.0, description="Normalized diversity of originating entities")


class EntityRelationships(BaseModel):
    """Extracted entity graph relationships for the window."""
    ip_to_accounts: Dict[str, List[str]] = Field(default_factory=dict)
    ip_to_devices: Dict[str, List[str]] = Field(default_factory=dict)
    account_to_ips: Dict[str, List[str]] = Field(default_factory=dict)
    account_to_devices: Dict[str, List[str]] = Field(default_factory=dict)
    ip_to_destinations: Dict[str, List[str]] = Field(default_factory=dict)
    ip_to_ports: Dict[str, List[int]] = Field(default_factory=dict)


class FeatureSnapshot(BaseModel):
    """Complete time-windowed feature snapshot ready for storage and ML consumption."""
    model_config = ConfigDict(extra="ignore")

    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    window_seconds: int = Field(..., description="Window duration in seconds (60, 300, 900)")
    window_start: datetime = Field(..., description="Window start timestamp (inclusive)")
    window_end: datetime = Field(..., description="Window end timestamp (inclusive)")
    entity_type: EntityType = Field(..., description="Entity category: USER, IP, HOST, GLOBAL")
    entity_id: str = Field(..., description="Identifier for entity (or GLOBAL)")
    event_count: int = Field(default=0, description="Total telemetry events analyzed in window")
    features: Dict[str, float] = Field(default_factory=dict, description="Flat key-value feature dictionary")
    relationships: Dict[str, Any] = Field(default_factory=dict, description="Entity relationship mapping")
