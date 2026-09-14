"""Deterministic 21-dimensional behavioral feature vector schema and utilities.

Ensures training and inference always share identical dimension, ordering,
and missing-value sanitization across all models in Sh4d0w_St4lk3r.
"""

import math
from typing import Any, Dict, List, Sequence

FEATURE_SCHEMA_VERSION = "1.0.0"

# 1. Authentication Behavioral Features (10)
AUTH_FEATURES: List[str] = [
    "failed_login_rate",
    "success_rate",
    "unique_accounts_targeted",
    "unique_source_ips",
    "ip_diversity",
    "account_diversity",
    "geo_diversity",
    "device_diversity",
    "login_frequency",
    "time_deviation",
]

# 2. Network Behavioral Features (6)
NETWORK_FEATURES: List[str] = [
    "unique_destination_ports",
    "port_diversity",
    "connection_rate",
    "destination_diversity",
    "failed_connection_rate",
    "protocol_diversity",
]

# 3. Cross-Entity Behavioral Features (5)
CROSS_ENTITY_FEATURES: List[str] = [
    "ip_to_account_ratio",
    "accounts_to_ip_ratio",
    "distributed_attempt_score",
    "temporal_concentration",
    "source_diversity",
]

# Combined canonical feature vector definition (21 dimensions)
CANONICAL_FEATURE_NAMES: List[str] = (
    AUTH_FEATURES + NETWORK_FEATURES + CROSS_ENTITY_FEATURES
)

FEATURE_COUNT: int = len(CANONICAL_FEATURE_NAMES)
assert FEATURE_COUNT == 21, f"Expected 21 canonical features, got {FEATURE_COUNT}"


def sanitize_numeric_value(val: Any, default: float = 0.0) -> float:
    """Safely convert any numeric value to a finite float with zero-fill on error/NaN/Inf."""
    if val is None:
        return default
    try:
        fval = float(val)
        if math.isnan(fval) or math.isinf(fval):
            return default
        return fval
    except (ValueError, TypeError):
        return default


def extract_feature_vector(features: Dict[str, Any]) -> List[float]:
    """Extract a deterministic 21-dimensional float vector from a feature dictionary.
    
    Guarantees:
    - Exactly 21 elements in canonical order
    - No NaN values
    - No Infinity values
    - Missing keys filled deterministically with 0.0
    """
    vector: List[float] = []
    for name in CANONICAL_FEATURE_NAMES:
        val = features.get(name, 0.0)
        vector.append(sanitize_numeric_value(val, default=0.0))
    return vector


def feature_vector_to_dict(vector: Sequence[float]) -> Dict[str, float]:
    """Convert an ordered 21-dimensional vector back to a named dictionary."""
    if len(vector) != FEATURE_COUNT:
        raise ValueError(
            f"Feature vector dimension mismatch: expected {FEATURE_COUNT}, got {len(vector)}"
        )
    return {
        name: sanitize_numeric_value(val, default=0.0)
        for name, val in zip(CANONICAL_FEATURE_NAMES, vector)
    }


def validate_vector(vector: Sequence[float]) -> bool:
    """Validate that a vector matches the canonical dimension and has no NaN/Inf."""
    if len(vector) != FEATURE_COUNT:
        return False
    return all(
        isinstance(x, (int, float)) and not math.isnan(x) and not math.isinf(x)
        for x in vector
    )
