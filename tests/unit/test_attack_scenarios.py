"""Unit tests for Phase 9: Synthetic Attack Scenarios & Demo Simulation.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Verifies:
- Scenario existence (normal, distributed_bruteforce, credential_stuffing, port_scan)
- Determinism (identical seeds yield identical event streams)
- Distributed brute force characteristics (~500 IPs, 1-2 attempts per IP, account concentration)
- Credential stuffing characteristics (~300 IPs, ~200 accounts, ~95% failure, ~5% success, unseen devices)
- Port scan characteristics (1-5 IPs, 50-200 ports, high connection failure rate)
- Normal baseline behavior (no attack characteristics)
- Scenario metadata retention
- Scenario metrics calculation
- End-to-end pipeline integration through feature extraction, detection, fusion, and risk scoring
- 9-step demo progression execution
"""

import pytest

from backend.db.session import SessionLocal, init_db
from backend.models.canonical import CanonicalEvent
from backend.models.telemetry import normalize_event
from simulator.pipeline import run_demo_progression, run_simulation_pipeline
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.credential_stuffing import CredentialStuffingScenario
from simulator.scenarios.distributed_bruteforce import DistributedBruteForceScenario
from simulator.scenarios.metrics import (
    calculate_credential_stuffing_metrics,
    calculate_distributed_bruteforce_metrics,
    calculate_normal_metrics,
    calculate_port_scan_metrics,
    calculate_scenario_metrics,
)
from simulator.scenarios.normal import NormalTrafficScenario
from simulator.scenarios.port_scan import PortScanScenario


def test_scenario_existence():
    """Verify all four core scenario classes instantiate and generate events."""
    normal = NormalTrafficScenario(ScenarioConfig(count=10, seed=42)).generate()
    distbf = DistributedBruteForceScenario(ScenarioConfig(count=20, seed=42)).generate()
    credstuff = CredentialStuffingScenario(ScenarioConfig(count=20, seed=42)).generate()
    portscan = PortScanScenario(ScenarioConfig(count=20, seed=42)).generate()

    assert len(normal) == 10
    assert len(distbf) >= 20
    assert len(credstuff) >= 20
    assert len(portscan) >= 20


def test_determinism_across_all_scenarios():
    """Verify that identical seeds produce bit-for-bit identical telemetry events."""
    for ScenarioCls, count in [
        (NormalTrafficScenario, 30),
        (DistributedBruteForceScenario, 50),
        (CredentialStuffingScenario, 40),
        (PortScanScenario, 35),
    ]:
        cfg1 = ScenarioConfig(seed=42, count=count)
        events1 = ScenarioCls(cfg1).generate()

        cfg2 = ScenarioConfig(seed=42, count=count)
        events2 = ScenarioCls(cfg2).generate()

        assert events1 == events2, f"Scenario {ScenarioCls.__name__} must be deterministic for identical seeds"

        # Verify different seeds vary
        cfg3 = ScenarioConfig(seed=999, count=count)
        events3 = ScenarioCls(cfg3).generate()
        assert events1 != events3, f"Scenario {ScenarioCls.__name__} should produce different output for different seeds"


def test_scenario_metadata_presence():
    """Verify all scenarios stamp events with scenario metadata for tracking."""
    scenarios = [
        NormalTrafficScenario(ScenarioConfig(count=5, seed=1)),
        DistributedBruteForceScenario(ScenarioConfig(count=5, seed=1)),
        CredentialStuffingScenario(ScenarioConfig(count=5, seed=1)),
        PortScanScenario(ScenarioConfig(count=5, seed=1)),
    ]

    for sc in scenarios:
        events = sc.generate()
        for ev in events:
            assert "scenario" in ev
            assert "attack_stage" in ev
            assert "synthetic_session" in ev
            assert "scenario_seed" in ev
            assert ev["scenario_seed"] == 1

            # Verify normalization into CanonicalEvent is safe and clean
            canon = normalize_event(ev)
            assert isinstance(canon, CanonicalEvent)
            assert canon.event_id is not None


def test_distributed_bruteforce_characteristics():
    """Verify Distributed Low-and-Slow Brute Force scenario contract:
    - Approximately 500 unique IPs
    - 1-2 attempts per IP
    - Concentrated account targeting
    """
    cfg = ScenarioConfig(
        name="distributed_bruteforce",
        seed=42,
        count=500,
        parameters={"unique_ips": 500, "target_accounts": ["account_001", "account_002", "account_003"]},
    )
    events = DistributedBruteForceScenario(cfg).generate()

    metrics = calculate_distributed_bruteforce_metrics(events)

    # Unique IPs should be approximately 500
    assert 480 <= metrics["unique_source_ips"] <= 520
    # Strictly 1-2 attempts per IP (low-and-slow)
    assert 1.0 <= metrics["attempts_per_ip"] <= 2.0
    assert metrics["max_attempts_single_ip"] <= 2
    assert metrics["min_attempts_single_ip"] >= 1

    # Concentrated targeting against small account set
    assert metrics["targeted_accounts"] <= 3
    attempts_per_account = metrics["attempts_per_target_account"]
    assert "account_001" in attempts_per_account
    # account_001 should receive the vast majority of attempts
    assert attempts_per_account["account_001"] > sum(
        v for k, v in attempts_per_account.items() if k != "account_001"
    )


def test_credential_stuffing_characteristics():
    """Verify Credential Stuffing scenario contract:
    - Approximately 300 source IPs
    - Approximately 200 accounts
    - ~95% login failures, ~5% successes
    - Unseen device IDs
    """
    cfg = ScenarioConfig(
        name="credential_stuffing",
        seed=42,
        count=300,
        parameters={"unique_ips": 300, "unique_accounts": 200},
    )
    events = CredentialStuffingScenario(cfg).generate()

    metrics = calculate_credential_stuffing_metrics(events)

    assert 280 <= metrics["unique_ips"] <= 320
    assert 180 <= metrics["unique_accounts"] <= 220
    # High failure rate (~95%)
    assert 0.90 <= metrics["failure_rate"] <= 0.99
    # Some successful authentications (>0)
    assert metrics["success_count"] > 0
    # Many unseen devices
    assert metrics["unseen_devices"] > 100


def test_port_scan_characteristics():
    """Verify Port Scan scenario contract:
    - 1-5 source IPs
    - 50-200 destination ports
    - High failed connection rate (~90%+)
    """
    cfg = ScenarioConfig(
        name="port_scan",
        seed=42,
        count=150,
        parameters={"scanner_count": 2, "ports_per_scanner": 75},
    )
    events = PortScanScenario(cfg).generate()

    metrics = calculate_port_scan_metrics(events)

    # 1-5 source IPs
    assert 1 <= metrics["unique_source_ips"] <= 5
    # 50-200 destination ports
    assert 50 <= metrics["unique_destination_ports"] <= 200
    # High failed connection rate (DENY / timeout)
    assert metrics["failed_connection_rate"] >= 0.80
    assert metrics["connection_count"] >= 100


def test_normal_baseline_characteristics():
    """Verify normal traffic does not exhibit attack characteristics:
    - High success rate (~98%)
    - Small, stable set of source IPs
    - Predictable ports
    """
    cfg = ScenarioConfig(name="normal", seed=42, count=100)
    events = NormalTrafficScenario(cfg).generate()

    metrics = calculate_normal_metrics(events)

    assert metrics["event_count"] == 100
    assert metrics["success_rate"] >= 0.90
    assert metrics["failure_rate"] <= 0.10
    assert metrics["unique_ips"] <= 15


def test_scenario_metrics_dispatcher():
    """Verify calculate_scenario_metrics correctly routes to all scenario calculators."""
    for name, ScenarioCls, count in [
        ("normal", NormalTrafficScenario, 20),
        ("distributed_bruteforce", DistributedBruteForceScenario, 30),
        ("credential_stuffing", CredentialStuffingScenario, 30),
        ("port_scan", PortScanScenario, 30),
    ]:
        events = ScenarioCls(ScenarioConfig(count=count, seed=42)).generate()
        metrics = calculate_scenario_metrics(name, events)
        assert isinstance(metrics, dict)
        assert len(metrics) > 1


def test_pipeline_integration_with_distributed_bruteforce():
    """Verify that synthetic events flow through the entire Phase 1-8 pipeline cleanly:
    telemetry -> ingestion -> features -> statistical -> IF -> clustering -> fusion -> risk score.
    """
    init_db()
    db = SessionLocal()
    try:
        cfg = ScenarioConfig(
            name="distributed_bruteforce",
            seed=42,
            count=100,
            parameters={"unique_ips": 80, "target_accounts": ["account_demo_01"]},
        )
        events = DistributedBruteForceScenario(cfg).generate()

        res = run_simulation_pipeline(
            events=events,
            db=db,
            window_seconds=300,
            target_account="account_demo_01",
        )

        assert res["ingested_count"] > 0
        assert res["snapshot_id"] is not None
        assert "unique_source_ips" in res["features"]
        assert res["features"]["unique_source_ips"] >= 50.0
        assert res["features"]["ip_to_account_ratio"] >= 50.0

        # Fusion and risk scoring must be produced
        assert res["fusion_result"]["fusion_id"] is not None
        risk = res["risk_score_result"]
        assert risk["risk_id"] is not None
        assert 0.0 <= risk["final_score"] <= 100.0
        assert risk["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(risk["explanation"]) > 0
    finally:
        db.close()


def test_demo_progression_execution():
    """Verify 9-step hackathon demo progression executes end-to-end without errors."""
    init_db()
    db = SessionLocal()
    try:
        demo_output = run_demo_progression(db=db, seed=42)

        assert "normal" in demo_output
        assert "attack" in demo_output
        assert len(demo_output["progression_log"]) >= 9

        # Normal risk score should be LOW
        normal_risk = demo_output["normal"]["risk_score_result"]
        assert normal_risk["severity"] in ("LOW", "MEDIUM")

        # Attack feature metrics should show elevated collective behavior
        attack_feats = demo_output["attack"]["features"]
        assert attack_feats["unique_source_ips"] >= 50.0
        assert attack_feats["ip_to_account_ratio"] >= 50.0
    finally:
        db.close()
