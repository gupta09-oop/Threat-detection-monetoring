"""Behavioral feature engineering package for Sh4d0w_St4lk3r."""

from backend.features.windows import (
    FeatureWindow,
    SUPPORTED_WINDOWS,
    window_to_label,
)
from backend.features.schemas import (
    EntityType,
    AuthFeatures,
    NetworkFeatures,
    CrossEntityFeatures,
    EntityRelationships,
    FeatureSnapshot,
)
from backend.features.calculator import FeatureCalculator
from backend.features.service import (
    FeatureEngineeringService,
    feature_service,
)
from backend.features.vector import (
    FEATURE_SCHEMA_VERSION,
    AUTH_FEATURES,
    NETWORK_FEATURES,
    CROSS_ENTITY_FEATURES,
    CANONICAL_FEATURE_NAMES,
    FEATURE_COUNT,
    extract_feature_vector,
    feature_vector_to_dict,
    validate_vector,
)

__all__ = [
    "FeatureWindow",
    "SUPPORTED_WINDOWS",
    "window_to_label",
    "EntityType",
    "AuthFeatures",
    "NetworkFeatures",
    "CrossEntityFeatures",
    "EntityRelationships",
    "FeatureSnapshot",
    "FeatureCalculator",
    "FeatureEngineeringService",
    "feature_service",
    "FEATURE_SCHEMA_VERSION",
    "AUTH_FEATURES",
    "NETWORK_FEATURES",
    "CROSS_ENTITY_FEATURES",
    "CANONICAL_FEATURE_NAMES",
    "FEATURE_COUNT",
    "extract_feature_vector",
    "feature_vector_to_dict",
    "validate_vector",
]
