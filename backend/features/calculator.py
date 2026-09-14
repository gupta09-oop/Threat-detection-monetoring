"""Feature calculation engine for Sh4d0w_St4lk3r.

Extracts time-windowed behavioral evidence from canonical telemetry events
for authentication, network flows, cross-entity relationships, and entity graphs.
"""

from collections import defaultdict
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.features.schemas import (
    AuthFeatures,
    NetworkFeatures,
    CrossEntityFeatures,
    EntityRelationships,
)
from backend.models.canonical import CanonicalEvent


class FeatureCalculator:
    """Calculates behavioral feature vectors from a collection of canonical events.
    
    Adheres strictly to the architecture blueprint:
    - Pure evidence calculation (no detection decisions here)
    - Full cold-window / empty-window safety (no ZeroDivisionError, NaN, or Infinity)
    - Reusable across any time window duration (60s, 5m, 15m)
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = max(1, window_seconds)

    def calculate_all(
        self,
        events: List[CanonicalEvent],
    ) -> Tuple[Dict[str, float], Dict[str, Any]]:
        """Calculate complete behavioral feature dictionary and entity relationships."""
        auth_features = self.calculate_auth_features(events)
        net_features = self.calculate_network_features(events)
        cross_features = self.calculate_cross_entity_features(events)
        relationships = self.extract_entity_relationships(events)

        # Merge into a flat dictionary suitable for baseline/ML consumption
        flat_features: Dict[str, float] = {}
        flat_features.update(auth_features.model_dump())
        flat_features.update(net_features.model_dump())
        flat_features.update(cross_features.model_dump())

        # Ensure all feature values are valid finite floats
        for k, v in flat_features.items():
            if math.isnan(v) or math.isinf(v):
                flat_features[k] = 0.0

        return flat_features, relationships.model_dump()

    def calculate_auth_features(self, events: List[CanonicalEvent]) -> AuthFeatures:
        """Calculate authentication-specific behavioral features."""
        auth_events = [e for e in events if e.source_type == "AUTH"]
        total_auth = len(auth_events)

        if total_auth == 0:
            return AuthFeatures()

        failed_count = sum(
            1 for e in auth_events
            if str(e.result).upper() in ("FAILURE", "DENY", "FAILED", "ERROR", "REJECTED")
        )
        success_count = sum(
            1 for e in auth_events
            if str(e.result).upper() in ("SUCCESS", "ALLOW", "SUCCESSFUL", "ACCEPTED")
        )

        unique_accounts: Set[str] = {e.user_id for e in auth_events if e.user_id}
        unique_ips: Set[str] = {e.source_ip for e in auth_events if e.source_ip}
        unique_devices: Set[str] = {e.device_id for e in auth_events if e.device_id}

        geo_points: Set[str] = set()
        for e in auth_events:
            if e.geo and isinstance(e.geo, dict):
                country = e.geo.get("country") or e.geo.get("geo_country") or ""
                city = e.geo.get("city") or e.geo.get("geo_city") or ""
                if country or city:
                    geo_points.add(f"{country}:{city}")

        # Inter-arrival time standard deviation
        time_deviation = 0.0
        if total_auth > 1:
            sorted_times = sorted([e.timestamp for e in auth_events])
            intervals = [
                (sorted_times[i] - sorted_times[i - 1]).total_seconds()
                for i in range(1, len(sorted_times))
            ]
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                time_deviation = round(variance ** 0.5, 4)

        return AuthFeatures(
            failed_login_rate=round(failed_count / total_auth, 4),
            success_rate=round(success_count / total_auth, 4),
            unique_accounts_targeted=len(unique_accounts),
            unique_source_ips=len(unique_ips),
            ip_diversity=round(len(unique_ips) / total_auth, 4),
            account_diversity=round(len(unique_accounts) / total_auth, 4),
            geo_diversity=round(len(geo_points) / total_auth, 4),
            device_diversity=round(len(unique_devices) / total_auth, 4),
            login_frequency=round(total_auth / self.window_seconds, 4),
            time_deviation=time_deviation,
        )

    def calculate_network_features(self, events: List[CanonicalEvent]) -> NetworkFeatures:
        """Calculate network flow behavioral features."""
        net_events = [e for e in events if e.source_type == "NETWORK"]
        total_net = len(net_events)

        if total_net == 0:
            return NetworkFeatures()

        ports: Set[int] = {e.port for e in net_events if e.port is not None}
        dest_ips: Set[str] = {e.destination_ip for e in net_events if e.destination_ip}
        protocols: Set[str] = {e.protocol.upper() for e in net_events if e.protocol}

        failed_conns = sum(
            1 for e in net_events
            if str(e.result).upper() in ("DENY", "DROP", "CLOSED", "FAILURE", "FAILED", "REJECTED")
        )

        return NetworkFeatures(
            unique_destination_ports=len(ports),
            port_diversity=round(len(ports) / total_net, 4),
            connection_rate=round(total_net / self.window_seconds, 4),
            destination_diversity=round(len(dest_ips) / total_net, 4),
            failed_connection_rate=round(failed_conns / total_net, 4),
            protocol_diversity=round(len(protocols) / total_net, 4),
        )

    def calculate_cross_entity_features(self, events: List[CanonicalEvent]) -> CrossEntityFeatures:
        """Calculate cross-entity and distributed attack indicator features."""
        total_events = len(events)
        if total_events == 0:
            return CrossEntityFeatures()

        ips: Set[str] = {e.source_ip for e in events if e.source_ip}
        accounts: Set[str] = {e.user_id for e in events if e.user_id}
        num_ips = len(ips)
        num_accounts = len(accounts)

        ip_to_account_ratio = round(num_ips / num_accounts, 4) if num_accounts > 0 else 0.0
        accounts_to_ip_ratio = round(num_accounts / num_ips, 4) if num_ips > 0 else 0.0

        # Distributed attempt score: high when multiple IPs target accounts relative to total events
        distributed_score = 0.0
        if num_ips > 1 and num_accounts >= 1:
            # Dispersion ratio normalized between 0.0 and 1.0
            ip_dispersion = num_ips / total_events
            acct_factor = min(1.0, num_accounts / num_ips)
            distributed_score = round(ip_dispersion * (1.0 + acct_factor) / 2.0, 4)

        # Temporal concentration (burstiness): max concentration in any 1/10th sub-window slice
        temporal_concentration = 0.0
        if total_events > 0:
            slices = 10
            slice_counts = [0] * slices
            sorted_times = sorted([e.timestamp.timestamp() for e in events])
            t_min = sorted_times[0]
            t_max = sorted_times[-1]
            span = max(1.0, t_max - t_min)

            for t in sorted_times:
                idx = min(slices - 1, int(((t - t_min) / span) * slices))
                slice_counts[idx] += 1
            temporal_concentration = round(max(slice_counts) / total_events, 4)

        # Source diversity: distinct (IP, device) combinations / total events
        distinct_sources = len({
            f"{e.source_ip or ''}:{e.device_id or ''}"
            for e in events
            if e.source_ip or e.device_id
        })
        source_diversity = round(distinct_sources / total_events, 4) if total_events > 0 else 0.0

        return CrossEntityFeatures(
            ip_to_account_ratio=ip_to_account_ratio,
            accounts_to_ip_ratio=accounts_to_ip_ratio,
            distributed_attempt_score=distributed_score,
            temporal_concentration=temporal_concentration,
            source_diversity=source_diversity,
        )

    def extract_entity_relationships(self, events: List[CanonicalEvent]) -> EntityRelationships:
        """Extract multi-directional entity graph linkages across events."""
        ip_to_accounts: Dict[str, Set[str]] = defaultdict(set)
        ip_to_devices: Dict[str, Set[str]] = defaultdict(set)
        account_to_ips: Dict[str, Set[str]] = defaultdict(set)
        account_to_devices: Dict[str, Set[str]] = defaultdict(set)
        ip_to_destinations: Dict[str, Set[str]] = defaultdict(set)
        ip_to_ports: Dict[str, Set[int]] = defaultdict(set)

        for e in events:
            if e.source_ip:
                if e.user_id:
                    ip_to_accounts[e.source_ip].add(e.user_id)
                    account_to_ips[e.user_id].add(e.source_ip)
                if e.device_id:
                    ip_to_devices[e.source_ip].add(e.device_id)
                if e.destination_ip:
                    ip_to_destinations[e.source_ip].add(e.destination_ip)
                if e.port is not None:
                    ip_to_ports[e.source_ip].add(e.port)

            if e.user_id and e.device_id:
                account_to_devices[e.user_id].add(e.device_id)

        return EntityRelationships(
            ip_to_accounts={k: sorted(list(v)) for k, v in ip_to_accounts.items()},
            ip_to_devices={k: sorted(list(v)) for k, v in ip_to_devices.items()},
            account_to_ips={k: sorted(list(v)) for k, v in account_to_ips.items()},
            account_to_devices={k: sorted(list(v)) for k, v in account_to_devices.items()},
            ip_to_destinations={k: sorted(list(v)) for k, v in ip_to_destinations.items()},
            ip_to_ports={k: sorted(list(v)) for k, v in ip_to_ports.items()},
        )
