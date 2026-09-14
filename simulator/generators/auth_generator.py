"""Deterministic synthetic authentication telemetry generator."""

from datetime import datetime, timezone
import random
from typing import Any, Dict, Optional

# Stable corporate entities reflecting normal baseline
STABLE_USERS = [
    "alice.smith",
    "bob.jones",
    "charlie.davis",
    "dana.scully",
    "edward.snow",
]

STABLE_DEVICES = {
    "alice.smith": "DEV-CORP-W10-01",
    "bob.jones": "DEV-CORP-W10-02",
    "charlie.davis": "DEV-CORP-MAC-01",
    "dana.scully": "DEV-CORP-MAC-02",
    "edward.snow": "DEV-CORP-LNX-01",
}

STABLE_SUBNETS = [
    "10.0.10.15",
    "10.0.10.22",
    "10.0.10.45",
    "192.168.1.50",
    "192.168.1.55",
]

AUTH_METHODS = ["MFA", "PASSWORD", "SSO"]


def generate_normal_auth_event(
    rng: random.Random,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Generate a single deterministic normal authentication telemetry event."""
    ts = timestamp or datetime.now(timezone.utc)
    user = rng.choice(STABLE_USERS)
    device = STABLE_DEVICES.get(user, "DEV-CORP-GENERIC")
    source_ip = rng.choice(STABLE_SUBNETS)
    auth_method = rng.choice(AUTH_METHODS)

    # In normal traffic, 98% success rate
    login_result = "SUCCESS" if rng.random() < 0.98 else "FAILURE"

    return {
        "timestamp": ts.isoformat(),
        "source_ip": source_ip,
        "user_id": user,
        "login_result": login_result,
        "auth_method": auth_method,
        "device_id": device,
        "geo_country": "US",
        "geo_city": "San Francisco" if "MAC" in device else "New York",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
        "session_id": f"sess_{rng.randint(100000, 999999)}",
    }
