"""CLI entrypoint for running the Sh4d0w_St4lk3r telemetry simulator.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from backend.db.session import SessionLocal, init_db
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.credential_stuffing import CredentialStuffingScenario
from simulator.scenarios.distributed_bruteforce import DistributedBruteForceScenario
from simulator.scenarios.metrics import calculate_scenario_metrics
from simulator.scenarios.normal import NormalTrafficScenario
from simulator.scenarios.port_scan import PortScanScenario


def get_scenario_instance(scenario_name: str, config: ScenarioConfig):
    """Instantiate scenario object by name."""
    s = scenario_name.lower().strip()
    if s == "normal":
        return NormalTrafficScenario(config)
    elif s in ("distributed_bruteforce", "dist_bf", "bruteforce"):
        return DistributedBruteForceScenario(config)
    elif s in ("credential_stuffing", "cred_stuff", "stuffing"):
        return CredentialStuffingScenario(config)
    elif s in ("port_scan", "portscan", "recon"):
        return PortScanScenario(config)
    else:
        raise ValueError(
            f"Unknown scenario '{scenario_name}'. Supported: normal, distributed_bruteforce, credential_stuffing, port_scan, all"
        )


def run_simulator(
    scenario_name: str = "normal",
    count: Optional[int] = None,
    seed: int = 42,
    target_url: Optional[str] = None,
    output_file: Optional[str] = None,
    run_pipeline: bool = False,
) -> List[Dict[str, Any]]:
    """Run simulation scenario(s), display validation metrics, and optionally post/pipe results."""
    all_events: List[Dict[str, Any]] = []

    if scenario_name.lower() == "all":
        scenarios_to_run = [
            ("normal", count or 50),
            ("distributed_bruteforce", count or 500),
            ("credential_stuffing", count or 300),
            ("port_scan", count or 150),
        ]
        for name, cnt in scenarios_to_run:
            cfg = ScenarioConfig(name=name, seed=seed, count=cnt)
            sc = get_scenario_instance(name, cfg)
            evs = sc.generate()
            metrics = calculate_scenario_metrics(name, evs)
            print(f"\n[+] SCENARIO: {name.upper()} (events: {len(evs)}, seed: {seed})")
            for k, v in metrics.items():
                print(f"    - {k}: {v}")
            all_events.extend(evs)
    else:
        default_counts = {
            "normal": 50,
            "distributed_bruteforce": 500,
            "credential_stuffing": 300,
            "port_scan": 150,
        }
        effective_count = count or default_counts.get(scenario_name.lower(), 50)
        cfg = ScenarioConfig(name=scenario_name, seed=seed, count=effective_count)
        scenario = get_scenario_instance(scenario_name, cfg)
        all_events = scenario.generate()

        metrics = calculate_scenario_metrics(scenario_name, all_events)
        print(f"\n[+] SCENARIO: {scenario_name.upper()} (events: {len(all_events)}, seed: {seed})")
        for k, v in metrics.items():
            print(f"    - {k}: {v}")

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_events, f, indent=2)
        print(f"\n[+] Saved {len(all_events)} events to {output_file}")

    if target_url:
        print(f"\n[+] POSTing {len(all_events)} events to Ingestion API ({target_url})...")
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(target_url, json=all_events)
                print(f"[+] Ingestion Response [{response.status_code}]: {response.text}")
        except Exception as exc:
            print(f"[-] Failed to POST to {target_url}: {exc}")

    if run_pipeline:
        print("\n[+] Running in-process detection, fusion, and risk scoring pipeline...")
        from simulator.pipeline import run_simulation_pipeline

        init_db()
        db = SessionLocal()
        try:
            res = run_simulation_pipeline(all_events, db, window_seconds=300)
            print("\n" + "=" * 60)
            print("  PIPELINE EXECUTION SUMMARY")
            print("=" * 60)
            print(f"  Ingested Events:       {res['ingested_count']}")
            print(f"  Snapshot ID:           {res['snapshot_id']}")
            print(f"  Statistical Anomalies: {res['statistical_anomalies_count']}")
            print(f"  Evidence Strength:     {res['fusion_result']['evidence_strength']}")
            print(f"  Final Risk Score:      {res['risk_score_result']['final_score']}/100 ({res['risk_score_result']['severity']})")
            print(f"  Risk Explanation:      {res['risk_score_result']['explanation']}")
            print("=" * 60)
        finally:
            db.close()

    return all_events


def main():
    parser = argparse.ArgumentParser(
        description="Sh4d0w_St4lk3r Telemetry Simulator & Scenario Generator",
    )
    parser.add_argument(
        "--scenario",
        default="normal",
        choices=["normal", "distributed_bruteforce", "credential_stuffing", "port_scan", "all"],
        help="Telemetry scenario to run (default: normal)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Event / IP target count (default: scenario-specific defaults)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic pseudo-random seed (default: 42)",
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Optional API URL to POST events to (e.g. http://127.0.0.1:8000/api/events)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional JSON file path to write generated events to",
    )
    parser.add_argument(
        "--run-pipeline",
        action="store_true",
        help="Trigger end-to-end in-process feature engineering, fusion, and risk scoring",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run 5-minute hackathon progression demo from normal baseline to high risk",
    )

    args = parser.parse_args()

    if args.demo:
        from simulator.pipeline import run_demo_progression

        init_db()
        db = SessionLocal()
        try:
            run_demo_progression(db=db, seed=args.seed)
        finally:
            db.close()
        return

    events = run_simulator(
        scenario_name=args.scenario,
        count=args.count,
        seed=args.seed,
        target_url=args.target_url,
        output_file=args.output,
        run_pipeline=args.run_pipeline,
    )

    if not args.output and not args.target_url and not args.run_pipeline and events:
        print("\n--- Sample Event ---")
        print(json.dumps(events[0], indent=2))


if __name__ == "__main__":
    main()
