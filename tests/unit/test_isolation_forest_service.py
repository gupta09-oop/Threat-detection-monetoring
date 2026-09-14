"""Unit tests for the IsolationForestService lifecycle, cold-start, persistence, and evaluation."""

from datetime import datetime, timedelta, timezone
import os
import shutil
import tempfile
import uuid
import pytest

from backend.db.session import SessionLocal
from backend.detection.isolation_forest_service import IsolationForestService
from backend.features.schemas import EntityType, FeatureSnapshot
from backend.features.vector import CANONICAL_FEATURE_NAMES
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.repositories.anomaly_repository import AnomalyRepository


@pytest.fixture
def temp_service():
    """Create an isolated IsolationForestService using a temporary model directory."""
    tmp_dir = tempfile.mkdtemp()
    service = IsolationForestService(model_dir=tmp_dir, model_file="test_iforest.joblib")
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
        # Require 50 samples for a non-existent window (0 snapshots present)
        resp = temp_service.train(db=db, min_samples=50, contamination=0.05, window_seconds=9999)
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
        # Insert 30 normal FeatureSnapshot records into SQLite
        now = datetime.now(timezone.utc)
        for i in range(30):
            snap_id = f"test_snap_{uuid.uuid4()}"
            test_snapshots_ids.append(snap_id)

            features = {name: float(0.01 * (i % 5)) for name in CANONICAL_FEATURE_NAMES}
            features["failed_login_rate"] = 0.02
            features["unique_accounts_targeted"] = 1.0

            db_snap = FeatureSnapshotDB(
                snapshot_id=snap_id,
                timestamp=now - timedelta(minutes=i),
                window_seconds=60,
                window_start=now - timedelta(minutes=i, seconds=60),
                window_end=now - timedelta(minutes=i),
                entity_type="USER",
                entity_id=f"user_{i % 3}",
                event_count=10,
                features=features,
                relationships={},
            )
            db.add(db_snap)
        db.commit()

        # Train model with min_samples=10
        resp = temp_service.train(
            db=db,
            min_samples=10,
            contamination=0.05,
            random_seed=42,
            n_estimators=30,
        )

        assert resp.status == "SUCCESS"
        assert resp.training_sample_count >= 30
        assert temp_service.is_ready is True
        assert os.path.exists(temp_service.model_path)

        # Check status
        status = temp_service.get_status()
        assert status.is_ready is True
        assert status.status == "READY"

        # Verify evaluate_snapshot with persistence in anomaly_results
        test_snapshot = FeatureSnapshot(
            snapshot_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            window_seconds=60,
            window_start=datetime.now(timezone.utc) - timedelta(seconds=60),
            window_end=datetime.now(timezone.utc),
            entity_type=EntityType.USER,
            entity_id="eval_user",
            event_count=5,
            features={name: 0.02 for name in CANONICAL_FEATURE_NAMES},
            relationships={},
        )

        result = temp_service.evaluate_snapshot(test_snapshot, db=db, persist=True)
        assert result.detector_type == "ISOLATION_FOREST"
        assert 0.0 <= result.normalized_anomaly_score <= 100.0

        # Verify saved in SQLite anomaly_results table
        repo = AnomalyRepository(db)
        saved_db_record = repo.get_by_result_id(result.result_id)
        assert saved_db_record is not None
        assert saved_db_record.detector_type == "ISOLATION_FOREST"
        assert saved_db_record.snapshot_id == test_snapshot.snapshot_id
        assert saved_db_record.status in ("NORMAL", "ANOMALOUS")

        # Test reload in a fresh service instance
        new_service = IsolationForestService(
            model_dir=str(temp_service.model_dir),
            model_file=temp_service.model_file,
        )
        assert not new_service.is_ready
        loaded = new_service.try_load_model()
        assert loaded is True
        assert new_service.is_ready is True

        # Test evaluating with reloaded service
        reloaded_res = new_service.evaluate_snapshot(test_snapshot, db=None, persist=False)
        assert reloaded_res.raw_prediction == result.raw_prediction
        assert reloaded_res.normalized_anomaly_score == result.normalized_anomaly_score

    finally:
        # Cleanup test snapshots
        if test_snapshots_ids:
            db.query(FeatureSnapshotDB).filter(FeatureSnapshotDB.snapshot_id.in_(test_snapshots_ids)).delete(synchronize_session=False)
            db.commit()
        db.close()
