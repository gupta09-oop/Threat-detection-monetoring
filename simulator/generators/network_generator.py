"""Deterministic synthetic network telemetry generator."""

from datetime import datetime, timezone
import random
from typing import Any, Dict, Optional

NORMAL_PORTS = [443, 80, 53, 8080]
PROTOCOLS = ["TCP", "TCP", "TCP", "UDP"]

CLIENT_IPS = [
    "10.0.10.15",
    "10.0.10.22",
    "10.0.10.45",
    "192.168.1.50",
]

TARGET_SERVERS = [
    "10.0.1.10",       # Internal intranet
    "10.0.1.20",       # Internal API gateway
    "142.250.190.46",  # External CDN (e.g. Google)
    "151.101.1.140",   # External CDN (e.g. Fastly)
]


def generate_normal_network_event(
    rng: random.Random,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Generate a single deterministic normal network flow event."""
    ts = timestamp or datetime.now(timezone.utc)
    source_ip = rng.choice(CLIENT_IPS)
    destination_ip = rng.choice(TARGET_SERVERS)
    port = rng.choice(NORMAL_PORTS)
    protocol = "UDP" if port == 53 else "TCP"

    # Routine web traffic sizes
    bytes_sent = rng.randint(250, 4500)
    bytes_received = rng.randint(800, 35000)

    return {
        "timestamp": ts.isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": port,
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "connection_result": "ALLOW",
    }
