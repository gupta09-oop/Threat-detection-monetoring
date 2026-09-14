"""Unit tests for the BehavioralClusteringService lifecycle, cold-start, persistence, and DB integration."""

from datetime import datetime, timedelta, timezone
import os
import shutil
import tempfile
import uuid
import pytest

from backend.db.session import SessionLocal
from backend.detection.clustering_service import BehavioralClusteringService
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import CANONICAL_FEATURE_NAMES
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.anomaly_repository import AnomalyRepository


@pytest.fixture
def temp_service():
    """Create an isolated BehavioralClusteringService using a temporary model directory."""
    tmp_dir = tempfile.mkdtemp()
    service = BehavioralClusteringService(model_dir=tmp_dir, model_file="test_clustering.joblib")
    yield service
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_service_initial_status_unready(temp_service):
    """Initial service status must report NOT_READY when no model exists."""
    status = temp_service.get_status()
    assert status.is_ready is False
    assert status.status == "NOT_READY"
    assert "not trained or loaded" in status.message


def test_cold_start_insufficient_samples(temp_service):
    """Training with fewer samples than minimum returns INSUFFICIENT_DATA and preserves NOT_READY."""
    db = SessionLocal()
    try:
        # Request training for a non-existent window (0 snapshots present)
        resp = temp_service.train(db=db, min_samples=50, n_clusters=5, window_seconds=9999)
        assert resp.status == "INSUFFICIENT_DATA"
        assert "Cold-start active" in resp.message
        assert temp_service.is_ready is False
    finally:
        db.close()


def test_service_train_save_load_and_evaluate(temp_service):
    """End-to-end service test: populate snapshots, train, save, reload, and evaluate."""
    db = SessionLocal()
    test_snapshots_ids = []
    try:
        now = datetime.now(timezone.utc)
        # Insert 30 normal FeatureSnapshot records with natural variation
        for i in range(30):
            snap_id = f"test_cluster_snap_{uuid.uuid4()}"
            test_snapshots_ids.append(snap_id)

            features = {name: float(0.01 + 0.005 * (i % 5)) for name in CANONICAL_FEATURE_NAMES}
            features["login_frequency"] = float(0.05 + 0.01 * (i % 3))
            features["connection_rate"] = float(0.1 + 0.02 * (i % 4))

            db_snap = FeatureSnapshotDB(
                snapshot_id=snap_id,
                timestamp=now - timedelta(minutes=i),
                window_seconds=60,
                window_start=now - timedelta(minutes=i, seconds=60),
                window_end=now - timedelta(minutes=i),
                entity_type="USER",
                entity_id=f"cluster_user_{i % 3}",
                event_count=10,
                features=features,
                relationships={},
            )
            db.add(db_snap)
        db.commit()

        # Train model with min_samples=10, n_clusters=4
        resp = temp_service.train(
            db=db,
            min_samples=10,
            n_clusters=4,
            random_seed=42,
        )

        assert resp.status == "SUCCESS"
        assert resp.training_sample_count >= 30
        assert resp.n_clusters == 4
        assert temp_service.is_ready is True
        assert os.path.exists(temp_service.model_path)

        # Check status
        status = temp_service.get_status()
        assert status.is_ready is True
        assert status.status == "READY"
        assert len(status.clusters) == 4

        # Verify evaluate_snapshot with persistence in anomaly_results
        test_snapshot = FeatureSnapshot(
            snapshot_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            window_seconds=60,
            window_start=datetime.now(timezone.utc) - timedelta(seconds=60),
            window_end=datetime.now(timezone.utc),
            entity_type=EntityType.USER,
            entity_id="eval_cluster_user",
            event_count=5,
            features={name: 0.02 for name in CANONICAL_FEATURE_NAMES},
            relationships={},
        )

        result = temp_service.evaluate_snapshot(test_snapshot, db=db, persist=True)
        assert result.detector_type == "BEHAVIORAL_CLUSTERING"
        assert 0.0 <= result.normalized_anomaly_score <= 100.0
        assert result.pca_coordinates is not None
        assert len(result.pca_coordinates) == 2

        # Verify saved in SQLite anomaly_results table
        repo = AnomalyRepository(db)
        saved_db_record = repo.get_by_result_id(result.result_id)
        assert saved_db_record is not None
        assert saved_db_record.detector_type == "BEHAVIORAL_CLUSTERING"
        assert saved_db_record.snapshot_id == test_snapshot.snapshot_id
        assert saved_db_record.status in ("NORMAL", "ANOMALOUS")

        # Test reload in a fresh service instance
        new_service = BehavioralClusteringService(
            model_dir=str(temp_service.model_dir),
            model_file=temp_service.model_file,
        )
        assert not new_service.is_ready
        loaded = new_service.try_load_model()
        assert loaded is True
        assert new_service.is_ready is True

        # Test evaluating with reloaded service
        reloaded_res = new_service.evaluate_snapshot(test_snapshot, db=None, persist=False)
        assert reloaded_res.assigned_cluster_id == result.assigned_cluster_id
        assert reloaded_res.cluster_distance == result.cluster_distance
        assert reloaded_res.normalized_anomaly_score == result.normalized_anomaly_score

    finally:
        if test_snapshots_ids:
            db.query(FeatureSnapshotDB).filter(FeatureSnapshotDB.snapshot_id.in_(test_snapshots_ids)).delete(synchronize_session=False)
            db.commit()
        db.close()
