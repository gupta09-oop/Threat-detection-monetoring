"""Configuration and application settings for Sh4d0w_St4lk3r."""

from typing import Dict

# pyrefly: ignore [missing-import]
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    PROJECT_NAME: str = "Sh4d0w_St4lk3r"
    PROJECT_FULL_TITLE: str = (
        "Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform"
    )
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # Database settings
    DATABASE_URL: str = "sqlite:///./sh4d0w_st4lk3r.db"

    # Ingestion queue and backpressure settings
    INGESTION_QUEUE_MAX_SIZE: int = 5000
    INGESTION_BATCH_SIZE: int = 50
    INGESTION_FLUSH_INTERVAL: float = 0.5

    # Phase 4 Statistical Baseline & Z-Score Detection Settings
    STATISTICAL_MIN_SAMPLES_TO_SCORE: int = 5
    STATISTICAL_MIN_ENTITY_SAMPLES: int = 20
    STATISTICAL_Z_THRESHOLD: float = 3.0
    STATISTICAL_MAX_CONTRIBUTION: float = 1.0

    # Phase 5 Isolation Forest ML Anomaly Detection Settings
    ISOLATION_FOREST_CONTAMINATION: float = 0.05
    ISOLATION_FOREST_RANDOM_SEED: int = 42
    ISOLATION_FOREST_N_ESTIMATORS: int = 100
    ISOLATION_FOREST_MIN_TRAINING_SAMPLES: int = 20
    ISOLATION_FOREST_TARGET_TRAINING_SAMPLES: int = 5000
    ISOLATION_FOREST_MODEL_DIR: str = "artifacts/models"
    ISOLATION_FOREST_MODEL_FILE: str = "isolation_forest.joblib"

    # Phase 6 Behavioral Clustering Settings
    CLUSTERING_N_CLUSTERS: int = 5
    CLUSTERING_RANDOM_SEED: int = 42
    CLUSTERING_MIN_TRAINING_SAMPLES: int = 20
    CLUSTERING_TARGET_TRAINING_SAMPLES: int = 5000
    CLUSTERING_DISTANCE_PERCENTILE: float = 95.0
    CLUSTERING_MODEL_DIR: str = "artifacts/models"
    CLUSTERING_MODEL_FILE: str = "behavioral_clustering.joblib"

    # Phase 7 Anomaly Fusion Settings
    FUSION_CORRELATION_WINDOW_SECONDS: int = 300

    # Phase 8 Explainable Risk Scoring Settings
    RISK_STATISTICAL_MAX: float = 25.0
    RISK_ISOLATION_FOREST_MAX: float = 25.0
    RISK_CLUSTERING_MAX: float = 20.0
    RISK_RULES_MAX: float = 20.0
    RISK_CORRELATION_MAX: float = 10.0
    RISK_CORRELATION_MAP: Dict[int, float] = {
        0: 0.0,
        1: 0.0,
        2: 5.0,
        3: 8.0,
        4: 10.0,
    }

    # Phase 10 Alerting & Case Management Settings
    ALERT_RISK_THRESHOLD: float = 40.0
    ALERT_DEDUP_WINDOW_SECONDS: int = 300
    CASE_CORRELATION_WINDOW_SECONDS: int = 300

    # CORS
    # Stored as a comma-separated string so it works directly
    # with the Render environment variable ALLOWEDORIGINS.
    ALLOWEDORIGINS: str = (
        "http://localhost:3000,"
        "http://localhost:5173,"
        "http://127.0.0.1:3000,"
        "http://127.0.0.1:5173"
    )


settings = Settings()