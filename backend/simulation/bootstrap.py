"""Deterministic bootstrap mechanism for training ML detectors with legitimate normal telemetry.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Ensures Isolation Forest and Behavioral Clustering have sufficient normal FeatureSnapshot records
(minimum 20 samples required by config) to train without fabricating synthetic scores or lowering thresholds.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.orm import Session

from backend.config import settings
from backend.detection.clustering_service import behavioral_clustering_service
from backend.detection.isolation_forest_service import isolation_forest_service
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.service import feature_service
from backend.models.canonical import CanonicalEvent
from backend.models.db_event import TelemetryEventDB
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.models.telemetry import normalize_event
from backend.repositories.feature_repository import FeatureRepository
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.normal import NormalTrafficScenario

logger = logging.getLogger(__name__)


def ensure_ml_models_ready(
    db: Session,
    seed: int = 42,
    target_normal_snapshots: int = 25,
) -> Dict[str, Any]:
    """Ensure Isolation Forest and Behavioral Clustering models are trained and ready.
    
    If models are already loaded and ready, returns immediately.
    Otherwise, generates legitimate normal synthetic enterprise telemetry across distinct windows,
    computes behavioral feature snapshots, inserts them into the database, fits both models,
    and saves joblib artifacts to disk.
    """
    # 1. Attempt loading existing artifacts first
    isolation_forest_service.try_load_model()
    behavioral_clustering_service.try_load_model()

    if isolation_forest_service.is_ready and behavioral_clustering_service.is_ready:
        return {
            "status": "READY",
            "message": "Both ML detectors are already fitted and ready.",
            "isolation_forest_ready": True,
            "clustering_ready": True,
            "snapshots_present": db.query(FeatureSnapshotDB).count(),
        }

    logger.info(
        "Bootstrapping normal baseline telemetry to ready ML detectors (target: %d snapshots)...",
        target_normal_snapshots,
    )

    now = datetime.now(timezone.utc)
    all_db_events: List[TelemetryEventDB] = []
    created_snapshots: List[FeatureSnapshot] = []

    # Check how many snapshots already exist in DB
    existing_count = db.query(FeatureSnapshotDB).count()
    needed_snapshots = max(0, target_normal_snapshots - existing_count)

    for i in range(needed_snapshots):
        slice_seed = seed + (i * 17)
        slice_time = now - timedelta(minutes=(needed_snapshots - i) * 5)

        # Generate normal baseline batch using existing generator
        cfg = ScenarioConfig(
            name="normal",
            seed=slice_seed,
            count=30,
            parameters={"time_step_seconds": 2.0},
        )
        scenario = NormalTrafficScenario(cfg)
        scenario.current_time = slice_time
        raw_events = scenario.generate()

        # Normalize to canonical events
        canonical_events: List[CanonicalEvent] = []
        for raw in raw_events:
            try:
                canon = normalize_event(raw)
                canonical_events.append(canon)
                all_db_events.append(TelemetryEventDB.from_canonical(canon))
            except Exception as e:
                logger.debug("Normal event normalization skipped: %s", e)

        # Compute feature snapshot for this normal time window
        entity_id = f"user_{i % 5:03d}"
        snapshot = feature_service.calculate_for_events(
            events=canonical_events,
            window_seconds=300,
            entity_type=EntityType.USER,
            entity_id=entity_id,
            window_end=slice_time + timedelta(minutes=5),
        )
        created_snapshots.append(snapshot)

    # Persist batch events and snapshots to DB
    if all_db_events:
        db.add_all(all_db_events)
        db.commit()

    if created_snapshots:
        feat_repo = FeatureRepository(db)
        feat_repo.create_batch_snapshots(created_snapshots)

    # Train Isolation Forest on genuine normal snapshots
    iforest_train_resp = isolation_forest_service.train(
        db=db,
        min_samples=settings.ISOLATION_FOREST_MIN_TRAINING_SAMPLES,
        target_samples=settings.ISOLATION_FOREST_TARGET_TRAINING_SAMPLES,
        contamination=settings.ISOLATION_FOREST_CONTAMINATION,
        random_seed=seed,
    )
    if iforest_train_resp.status == "SUCCESS":
        isolation_forest_service.save_model()
        logger.info("Isolation Forest successfully trained and saved during bootstrap.")
    else:
        logger.warning("Isolation Forest bootstrap training status: %s", iforest_train_resp.status)

    # Train Behavioral Clustering on genuine normal snapshots
    cluster_train_resp = behavioral_clustering_service.train(
        db=db,
        n_clusters=settings.CLUSTERING_N_CLUSTERS,
        min_samples=settings.CLUSTERING_MIN_TRAINING_SAMPLES,
        target_samples=settings.CLUSTERING_TARGET_TRAINING_SAMPLES,
        random_seed=seed,
    )
    if cluster_train_resp.status == "SUCCESS":
        behavioral_clustering_service.save_model()
        logger.info("Behavioral Clustering successfully trained and saved during bootstrap.")
    else:
        logger.warning("Behavioral Clustering bootstrap training status: %s", cluster_train_resp.status)

    return {
        "status": "BOOTSTRAPPED",
        "message": "Normal baseline snapshots generated and models trained.",
        "isolation_forest_ready": isolation_forest_service.is_ready,
        "clustering_ready": behavioral_clustering_service.is_ready,
        "snapshots_present": db.query(FeatureSnapshotDB).count(),
        "iforest_train_status": iforest_train_resp.status,
        "clustering_train_status": cluster_train_resp.status,
    }
