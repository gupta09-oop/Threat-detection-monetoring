"""Unit tests for BaselineRepository and AnomalyRepository in SQLite."""

from datetime import datetime, timezone
import uuid
from backend.db.session import SessionLocal
from backend.detection.schemas import StatisticalAnomalyResult, StatisticalBaseline
from backend.features.schemas import EntityType
from backend.repositories.anomaly_repository import AnomalyRepository
from backend.repositories.baseline_repository import BaselineRepository


def test_baseline_repository_upsert_and_retrieve():
    """Verify upserting and updating a baseline in SQLite."""
    db = SessionLocal()
    try:
        repo = BaselineRepository(db)
        b1 = StatisticalBaseline(
            baseline_id=str(uuid.uuid4()),
            entity_type=EntityType.USER,
            entity_id="test_repo_user",
            window_seconds=60,
            feature_name="failed_login_rate",
            mean=0.05,
            stddev=0.02,
            sample_count=20,
        )

        db_rec = repo.upsert_baseline(b1)
        assert db_rec.id is not None
        assert db_rec.mean == 0.05

        # Update the baseline with new sample count and mean
        b1_updated = StatisticalBaseline(
            baseline_id=b1.baseline_id,
            entity_type=EntityType.USER,
            entity_id="test_repo_user",
            window_seconds=60,
            feature_name="failed_login_rate",
            mean=0.06,
            stddev=0.025,
            sample_count=25,
        )
        updated_rec = repo.upsert_baseline(b1_updated)
        assert updated_rec.id == db_rec.id  # Same record updated
        assert updated_rec.mean == 0.06
        assert updated_rec.sample_count == 25

        # Retrieve exact baseline
        fetched = repo.get_baseline("USER", "test_repo_user", 60, "failed_login_rate")
        assert fetched is not None
        assert fetched.mean == 0.06
    finally:
        db.close()


def test_anomaly_repository_create_and_query():
    """Verify persisting and filtering anomaly results in SQLite."""
    db = SessionLocal()
    try:
        repo = AnomalyRepository(db)
        res_id = str(uuid.uuid4())
        res = StatisticalAnomalyResult(
            result_id=res_id,
            timestamp=datetime.now(timezone.utc),
            detector_type="STATISTICAL_ZSCORE",
            entity_type=EntityType.IP,
            entity_id="192.168.100.1",
            snapshot_id="snap_123",
            window_seconds=300,
            feature_name="port_diversity",
            current_value=0.9,
            baseline_mean=0.1,
            baseline_stddev=0.05,
            sample_count=50,
            signed_z_score=16.0,
            absolute_z_score=16.0,
            is_anomalous=True,
            anomaly_score=1.0,
            explanation="Statistically anomalous port scan activity",
            status="ANOMALOUS",
        )

        db_obj = repo.create_result(res)
        assert db_obj.id is not None
        assert db_obj.result_id == res_id

        # Query by result_id
        fetched = repo.get_by_result_id(res_id)
        assert fetched is not None
        assert fetched.is_anomalous is True
        assert fetched.signed_z_score == 16.0

        # Query anomalous only
        anomalies = repo.get_results(entity_id="192.168.100.1", is_anomalous=True)
        assert any(a.result_id == res_id for a in anomalies)
    finally:
        db.close()
