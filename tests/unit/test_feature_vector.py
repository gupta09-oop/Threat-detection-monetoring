"""Unit tests for the 21-dimensional behavioral feature vector schema and sanitization."""

import math
import pytest

from backend.features.vector import (
    AUTH_FEATURES,
    NETWORK_FEATURES,
    CROSS_ENTITY_FEATURES,
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    extract_feature_vector,
    feature_vector_to_dict,
    sanitize_numeric_value,
    validate_vector,
)


def test_feature_vector_dimension_and_order():
    """Verify that canonical feature vector has exactly 21 features in stable order."""
    assert len(AUTH_FEATURES) == 10
    assert len(NETWORK_FEATURES) == 6
    assert len(CROSS_ENTITY_FEATURES) == 5
    assert FEATURE_COUNT == 21
    assert len(CANONICAL_FEATURE_NAMES) == 21

    # Deterministic order checks
    assert CANONICAL_FEATURE_NAMES[0] == "failed_login_rate"
    assert CANONICAL_FEATURE_NAMES[9] == "time_deviation"
    assert CANONICAL_FEATURE_NAMES[10] == "unique_destination_ports"
    assert CANONICAL_FEATURE_NAMES[15] == "protocol_diversity"
    assert CANONICAL_FEATURE_NAMES[16] == "ip_to_account_ratio"
    assert CANONICAL_FEATURE_NAMES[20] == "source_diversity"


def test_missing_features_handled_safely():
    """Missing or empty dictionary keys must default deterministically to 0.0."""
    empty_dict = {}
    vec = extract_feature_vector(empty_dict)
    assert len(vec) == 21
    assert all(x == 0.0 for x in vec)
    assert validate_vector(vec) is True


def test_nan_and_infinity_sanitization():
    """NaN, +Inf, -Inf, and invalid types must be sanitized to 0.0 without errors."""
    dirty_dict = {
        "failed_login_rate": float("nan"),
        "success_rate": float("inf"),
        "unique_accounts_targeted": float("-inf"),
        "unique_source_ips": None,
        "connection_rate": "invalid_string",
        "protocol_diversity": 0.85,
    }

    vec = extract_feature_vector(dirty_dict)
    assert len(vec) == 21
    assert vec[0] == 0.0  # failed_login_rate (was nan)
    assert vec[1] == 0.0  # success_rate (was inf)
    assert vec[2] == 0.0  # unique_accounts_targeted (was -inf)
    assert vec[3] == 0.0  # unique_source_ips (was None)
    assert vec[12] == 0.0  # connection_rate (was invalid_string)
    assert vec[15] == 0.85  # protocol_diversity preserved
    assert validate_vector(vec) is True


def test_feature_vector_dict_reconstruction():
    """Converting from vector back to dictionary preserves named mapping and order."""
    original = {name: float(i + 1) for i, name in enumerate(CANONICAL_FEATURE_NAMES)}
    vec = extract_feature_vector(original)
    reconstructed = feature_vector_to_dict(vec)

    assert len(reconstructed) == 21
    for name, val in original.items():
        assert reconstructed[name] == val

    # Test error on invalid length
    with pytest.raises(ValueError, match="Feature vector dimension mismatch"):
        feature_vector_to_dict([1.0, 2.0, 3.0])


def test_sanitize_numeric_value():
    """Unit tests for single numeric sanitization."""
    assert sanitize_numeric_value(42) == 42.0
    assert sanitize_numeric_value("3.14") == 3.14
    assert sanitize_numeric_value(None, default=0.0) == 0.0
    assert sanitize_numeric_value(float("nan"), default=0.0) == 0.0
    assert sanitize_numeric_value(float("inf"), default=0.0) == 0.0
    assert sanitize_numeric_value("not_a_number", default=0.0) == 0.0
