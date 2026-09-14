"""Anomaly Fusion Service for combining independent detection evidence.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Combines independent detector evidence from:
- Statistical Baseline (Directional Z-Score)
- Isolation Forest (Unsupervised tree isolation)
- Behavioral Clustering (KMeans centroid distance)
- Deterministic Rules (Extensible rule evidence interface)

Preserves individual detector identity and evidence without opaque ensembles
or artificial risk score blending.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Set
import uuid

from sqlalchemy.orm import Session

from backend.config import settings
from backend.detection.schemas import (
    DeterministicRuleEvidence,
    EvidenceStrength,
    FusionDetectorEvidence,
    FusionResult,
)
from backend.features.schemas import EntityType
from backend.models.anomaly import AnomalyResultDB
from backend.models.feature_snapshot import FeatureSnapshotDB
from backend.models.fusion import FusionResultDB
from backend.repositories.fusion_repository import FusionRepository

logger = logging.getLogger(__name__)

# Standard independent detection method family identifiers
DETECTOR_STATISTICAL = "STATISTICAL_BASELINE"
DETECTOR_ISOLATION_FOREST = "ISOLATION_FOREST"
DETECTOR_CLUSTERING = "BEHAVIORAL_CLUSTERING"
DETECTOR_DETERMINISTIC_RULE = "DETERMINISTIC_RULE"

ALL_STANDARD_DETECTORS = [
    DETECTOR_STATISTICAL,
    DETECTOR_ISOLATION_FOREST,
    DETECTOR_CLUSTERING,
]


def canonical_detector_type(detector_type: str) -> str:
    """Normalize detector name to its canonical independent detection family."""
    dt = detector_type.upper().strip()
    if dt in ("STATISTICAL_ZSCORE", "STATISTICAL_BASELINE", "STATISTICAL"):
        return DETECTOR_STATISTICAL
    if dt in ("ISOLATION_FOREST", "IF"):
        return DETECTOR_ISOLATION_FOREST
    if dt in ("BEHAVIORAL_CLUSTERING", "KMEANS", "CLUSTERING"):
        return DETECTOR_CLUSTERING
    if dt in ("DETERMINISTIC_RULE", "RULE"):
        return DETECTOR_DETERMINISTIC_RULE
    return dt


def determine_evidence_strength(anomalous_detector_count: int) -> EvidenceStrength:
    """Map the count of independent anomalous detectors to transparent evidence strength.

    - 0 independent anomalous detectors: LOW
    - 1 independent anomalous detector: MODERATE
    - 2 independent anomalous detectors: STRONG
    - 3+ independent anomalous detectors: CONCLUSIVE
    """
    if anomalous_detector_count >= 3:
        return EvidenceStrength.CONCLUSIVE
    elif anomalous_detector_count == 2:
        return EvidenceStrength.STRONG
    elif anomalous_detector_count == 1:
        return EvidenceStrength.MODERATE
    else:
        return EvidenceStrength.LOW


def format_fusion_explanation(
    anomalous_detectors: List[str],
    available_detectors: List[str],
    correlation_window_seconds: int,
) -> str:
    """Generate a transparent analyst explanation for the fusion result."""
    anom_count = len(anomalous_detectors)
    avail_count = len(available_detectors)

    number_words = {
        0: "Zero",
        1: "One",
        2: "Two",
        3: "Three",
        4: "Four",
        5: "Five",
    }
    anom_word = number_words.get(anom_count, str(anom_count))

    if anom_count == 0:
        base = (
            f"All evaluated detection methods ({avail_count} available) reported normal "
            f"behavior within the {correlation_window_seconds}s correlation window."
        )
    elif anom_count == 1:
        det_list = anomalous_detectors[0]
        base = (
            f"{anom_word} independent detection method identified anomalous behavior "
            f"within the {correlation_window_seconds}s correlation window: {det_list}."
        )
    else:
        det_list = ", ".join(anomalous_detectors)
        base = (
            f"{anom_word} independent detection methods identified anomalous behavior "
            f"within the {correlation_window_seconds}s correlation window: {det_list}."
        )

    # Note missing detector families if not all standard detectors were evaluated
    missing = [d for d in ALL_STANDARD_DETECTORS if d not in available_detectors]
    if missing:
        missing_names = ", ".join(missing)
        base += f" (Fusion based on {avail_count} available detector evidence source(s); {missing_names} evidence not available)."

    return base


class AnomalyFusionService:
    """Reusable service for correlating and fusing multi-detector anomaly evidence."""

    def __init__(self, default_correlation_window_seconds: Optional[int] = None):
        self.default_correlation_window_seconds = (
            default_correlation_window_seconds
            or getattr(settings, "FUSION_CORRELATION_WINDOW_SECONDS", 300)
        )

    def evaluate_evidence(
        self,
        evidence_list: List[FusionDetectorEvidence],
        rule_evidence: Optional[List[DeterministicRuleEvidence]] = None,
        entity_type: Optional[EntityType] = None,
        entity_id: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        window_seconds: Optional[int] = None,
        correlation_window_seconds: Optional[int] = None,
        reference_time: Optional[datetime] = None,
        db: Optional[Session] = None,
        persist: bool = False,
    ) -> FusionResult:
        """Combine independent detector evidence into a unified FusionResult.

        Validates entity compatibility, filters out of window temporal anomalies,
        aggregates by canonical detector family, maps evidence strength,
        and generates transparent explanations.
        """
        correlation_window = (
            correlation_window_seconds or self.default_correlation_window_seconds
        )

        all_evidences: List[FusionDetectorEvidence] = list(evidence_list or [])

        # Integrate extensible rule evidence if provided
        if rule_evidence:
            for rule in rule_evidence:
                all_evidences.append(rule.to_detector_evidence())

        # Determine target entity context
        target_entity_type: Optional[EntityType] = entity_type
        target_entity_id: Optional[str] = entity_id

        # If not explicitly provided, infer from evidence items
        if not target_entity_id and all_evidences:
            for ev in all_evidences:
                if ev.entity_id:
                    target_entity_id = ev.entity_id
                    target_entity_type = ev.entity_type or EntityType.GLOBAL
                    break

        if not target_entity_id:
            target_entity_id = "GLOBAL"
            target_entity_type = EntityType.GLOBAL

        if not target_entity_type:
            target_entity_type = EntityType.GLOBAL

        # Determine reference evaluation timestamp
        if reference_time is None:
            if all_evidences:
                # Latest evidence timestamp or current time
                reference_time = max(
                    (ev.timestamp for ev in all_evidences if ev.timestamp is not None),
                    default=datetime.now(timezone.utc),
                )
            else:
                reference_time = datetime.now(timezone.utc)

        # Enforce entity matching and temporal correlation window
        correlated_evidences: List[FusionDetectorEvidence] = []
        for ev in all_evidences:
            # Check entity compatibility
            if ev.entity_id and ev.entity_id != target_entity_id:
                logger.warning(
                    "Excluding evidence with mismatched entity_id '%s' (expected '%s')",
                    ev.entity_id,
                    target_entity_id,
                )
                continue

            # Check temporal correlation window
            if ev.timestamp is not None and reference_time is not None:
                # Make timestamps timezone-aware for comparison if needed
                ts1 = ev.timestamp
                ts2 = reference_time
                if ts1.tzinfo is None:
                    ts1 = ts1.replace(tzinfo=timezone.utc)
                if ts2.tzinfo is None:
                    ts2 = ts2.replace(tzinfo=timezone.utc)

                delta_seconds = abs((ts1 - ts2).total_seconds())
                if delta_seconds > correlation_window:
                    logger.debug(
                        "Excluding evidence outside correlation window (delta %.1fs > %ds)",
                        delta_seconds,
                        correlation_window,
                    )
                    continue

            correlated_evidences.append(ev)

        # Group evidences by canonical independent detection family
        grouped_detectors: Dict[str, List[FusionDetectorEvidence]] = {}
        for ev in correlated_evidences:
            fam = canonical_detector_type(ev.detector_type)
            if fam not in grouped_detectors:
                grouped_detectors[fam] = []
            grouped_detectors[fam].append(ev)

        # Count independent detector families and determine which ones flagged anomalous
        available_detectors = sorted(list(grouped_detectors.keys()))
        independent_detector_count = len(available_detectors)

        contributing_detectors: List[str] = []
        for fam, items in grouped_detectors.items():
            if any(item.is_anomalous for item in items):
                contributing_detectors.append(fam)

        contributing_detectors.sort()
        anomalous_detector_count = len(contributing_detectors)

        # Map to evidence strength: LOW, MODERATE, STRONG, CONCLUSIVE
        evidence_strength = determine_evidence_strength(anomalous_detector_count)

        # Generate transparent explanation
        explanation = format_fusion_explanation(
            anomalous_detectors=contributing_detectors,
            available_detectors=available_detectors,
            correlation_window_seconds=correlation_window,
        )

        # Snapshot ID and window duration resolution
        resolved_snapshot_id = snapshot_id
        resolved_window_seconds = window_seconds
        if not resolved_snapshot_id and correlated_evidences:
            for ev in correlated_evidences:
                if ev.snapshot_id:
                    resolved_snapshot_id = ev.snapshot_id
                    break
        if not resolved_window_seconds and correlated_evidences:
            for ev in correlated_evidences:
                if ev.window_seconds:
                    resolved_window_seconds = ev.window_seconds
                    break

        fusion_result = FusionResult(
            fusion_id=str(uuid.uuid4()),
            timestamp=reference_time,
            entity_type=target_entity_type,
            entity_id=target_entity_id,
            snapshot_id=resolved_snapshot_id,
            window_seconds=resolved_window_seconds,
            independent_detector_count=independent_detector_count,
            anomalous_detector_count=anomalous_detector_count,
            evidence_strength=evidence_strength,
            contributing_detectors=contributing_detectors,
            detector_results=correlated_evidences,
            fusion_explanation=explanation,
            correlation_window_seconds=correlation_window,
            details={
                "available_detectors": available_detectors,
                "correlation_window_seconds": correlation_window,
                "evaluated_evidence_count": len(correlated_evidences),
            },
        )

        # Persist if requested and DB session available
        if persist and db is not None:
            repo = FusionRepository(db)
            repo.create_result(fusion_result)

        return fusion_result

    def evaluate_snapshot(
        self,
        db: Session,
        snapshot_id: str,
        rule_evidence: Optional[List[DeterministicRuleEvidence]] = None,
        correlation_window_seconds: Optional[int] = None,
        persist: bool = True,
    ) -> FusionResult:
        """Query persisted detector results for a snapshot from anomaly_results and fuse evidence."""
        # 1. Look up feature snapshot if it exists
        snap_db = (
            db.query(FeatureSnapshotDB)
            .filter(FeatureSnapshotDB.snapshot_id == snapshot_id)
            .first()
        )
        entity_type: Optional[EntityType] = None
        entity_id: Optional[str] = None
        window_seconds: Optional[int] = None
        reference_time: Optional[datetime] = None

        if snap_db:
            entity_type = EntityType(snap_db.entity_type)
            entity_id = snap_db.entity_id
            window_seconds = snap_db.window_seconds
            reference_time = snap_db.timestamp

        # 2. Query all detector results linked directly to this snapshot
        results_db = (
            db.query(AnomalyResultDB)
            .filter(AnomalyResultDB.snapshot_id == snapshot_id)
            .all()
        )

        # Convert AnomalyResultDB records to FusionDetectorEvidence
        evidences: List[FusionDetectorEvidence] = []
        for r in results_db:
            if not entity_id:
                entity_id = r.entity_id
                entity_type = EntityType(r.entity_type)
                window_seconds = r.window_seconds
                reference_time = r.timestamp

            evidences.append(
                FusionDetectorEvidence(
                    detector_type=canonical_detector_type(r.detector_type),
                    detector_status=r.status,
                    detector_score=float(r.anomaly_score),
                    is_anomalous=bool(r.is_anomalous),
                    explanation=r.explanation,
                    source_result_id=r.result_id,
                    timestamp=r.timestamp,
                    entity_type=EntityType(r.entity_type),
                    entity_id=r.entity_id,
                    feature_name=r.feature_name,
                    window_seconds=r.window_seconds,
                    snapshot_id=r.snapshot_id,
                    details=r.details or {},
                )
            )

        return self.evaluate_evidence(
            evidence_list=evidences,
            rule_evidence=rule_evidence,
            entity_type=entity_type,
            entity_id=entity_id,
            snapshot_id=snapshot_id,
            window_seconds=window_seconds,
            correlation_window_seconds=correlation_window_seconds,
            reference_time=reference_time,
            db=db,
            persist=persist,
        )

    def evaluate_active(
        self,
        db: Session,
        window_seconds: Optional[int] = None,
        limit: int = 20,
        correlation_window_seconds: Optional[int] = None,
    ) -> List[FusionResult]:
        """Evaluate fusion across recent active feature snapshots and persisted detector outputs."""
        query = (
            db.query(AnomalyResultDB.snapshot_id)
            .distinct()
            .order_by(AnomalyResultDB.timestamp.desc())
        )
        if window_seconds is not None:
            query = query.filter(AnomalyResultDB.window_seconds == window_seconds)

        snapshot_ids = [row[0] for row in query.limit(limit).all() if row[0]]

        fused_results: List[FusionResult] = []
        for snap_id in snapshot_ids:
            try:
                res = self.evaluate_snapshot(
                    db=db,
                    snapshot_id=snap_id,
                    correlation_window_seconds=correlation_window_seconds,
                    persist=True,
                )
                fused_results.append(res)
            except Exception as e:
                logger.error("Failed to evaluate fusion for snapshot %s: %s", snap_id, e)

        return fused_results


# Global singleton instance
anomaly_fusion_service = AnomalyFusionService()
