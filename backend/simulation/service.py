"""Asynchronous simulation service and live scenario execution engine.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Controls live attack simulations, generates synthetic telemetry deterministically,
streams events gradually in paced batches through the real platform pipeline,
and broadcasts real-time execution progress over WebSockets.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from backend.db.session import SessionLocal
from backend.realtime.manager import manager as ws_manager
from backend.simulation.bootstrap import ensure_ml_models_ready
from backend.simulation.schemas import (
    SimulationScenario,
    SimulationStartRequest,
    SimulationStatusResponse,
    SimulationStopResponse,
)
from simulator.pipeline import run_simulation_pipeline
from simulator.scenarios.base import ScenarioConfig
from simulator.scenarios.credential_stuffing import CredentialStuffingScenario
from simulator.scenarios.distributed_bruteforce import DistributedBruteForceScenario
from simulator.scenarios.normal import NormalTrafficScenario
from simulator.scenarios.port_scan import PortScanScenario

logger = logging.getLogger(__name__)


class SimulationManager:
    """Manages background simulation tasks, status tracking, and paced event streaming."""

    def __init__(self) -> None:
        self._running: bool = False
        self._scenario: Optional[str] = None
        self._progress: int = 0
        self._events_generated: int = 0
        self._current_stage: str = "idle"
        self._started_at: Optional[datetime] = None
        self._completed: bool = False
        self._last_result: Optional[Dict[str, Any]] = None
        self._error: Optional[str] = None
        self._stop_requested: bool = False
        self._task: Optional[asyncio.Task] = None

    @property
    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> SimulationStatusResponse:
        """Return the current simulation status snapshot."""
        elapsed = 0
        if self._started_at:
            elapsed = int((datetime.now(timezone.utc) - self._started_at).total_seconds())

        return SimulationStatusResponse(
            running=self._running,
            scenario=self._scenario,
            progress=self._progress,
            events_generated=self._events_generated,
            current_stage=self._current_stage,
            started_at=self._started_at.isoformat() if self._started_at else None,
            elapsed_seconds=elapsed,
            completed=self._completed,
            last_result=self._last_result,
            error=self._error,
        )

    def start_simulation(self, req: SimulationStartRequest) -> SimulationStatusResponse:
        """Initiate a live synthetic simulation in the background."""
        if self._running:
            raise RuntimeError("Simulation is already running. Stop the active simulation first.")

        # Validate scenario name
        scenario_name = req.scenario.lower().strip()
        valid_scenarios = [s.value for s in SimulationScenario]
        if scenario_name not in valid_scenarios:
            raise ValueError(f"Invalid scenario '{req.scenario}'. Allowed: {', '.join(valid_scenarios)}")

        # Validate intensity
        intensity = req.intensity.lower().strip()
        if intensity not in ("low", "normal", "high"):
            raise ValueError(f"Invalid intensity '{req.intensity}'. Allowed: low, normal, high")

        # Initialize execution state
        self._running = True
        self._scenario = scenario_name
        self._progress = 0
        self._events_generated = 0
        self._current_stage = "INITIALIZING"
        self._started_at = datetime.now(timezone.utc)
        self._completed = False
        self._last_result = None
        self._error = None
        self._stop_requested = False

        # Spawn asynchronous worker task
        try:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(
                self._run_simulation_task(
                    scenario_name=scenario_name,
                    seed=req.seed,
                    duration_seconds=req.duration_seconds,
                    intensity=intensity,
                )
            )
        except RuntimeError:
            import threading

            def _thread_runner():
                thread_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(thread_loop)
                try:
                    thread_loop.run_until_complete(
                        self._run_simulation_task(
                            scenario_name=scenario_name,
                            seed=req.seed,
                            duration_seconds=req.duration_seconds,
                            intensity=intensity,
                        )
                    )
                finally:
                    thread_loop.close()

            th = threading.Thread(target=_thread_runner, daemon=True)
            self._thread = th
            th.start()

        return self.get_status()

    def stop_simulation(self) -> SimulationStopResponse:
        """Request immediate safe cancellation of the active simulation."""
        if not self._running:
            return SimulationStopResponse(success=True, message="No active simulation is currently running.")

        self._stop_requested = True
        if self._task and not self._task.done():
            self._task.cancel()

        if hasattr(self, "_thread") and self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        self._running = False
        self._current_stage = "STOPPED_BY_USER"
        self._broadcast_status()

        logger.info("Simulation '%s' stopped by user request.", self._scenario)
        return SimulationStopResponse(success=True, message="Simulation successfully cancelled.")

    def reset_demo_state(self, db: Any) -> Dict[str, Any]:
        """Completely reset all runtime simulation and detection state.

        Deletes runtime alerts, cases, risk scores, fusion results, anomaly results,
        telemetry events, and feature snapshots.
        Preserves trained ML models and statistical baseline profiles so the platform
        remains immediately detection-ready.
        """
        # 1. Stop any active simulation
        if self._running:
            self.stop_simulation()

        # 2. Reset in-memory simulation state
        self._running = False
        self._scenario = None
        self._progress = 0
        self._events_generated = 0
        self._current_stage = "READY"
        self._started_at = None
        self._completed = False
        self._last_result = None
        self._error = None
        self._stop_requested = False

        # 3. Purge runtime telemetry, features, detector outputs, risks, alerts, cases
        from backend.models.alert import AlertDB
        from backend.models.case import CaseDB
        from backend.models.risk import RiskScoreDB
        from backend.models.fusion import FusionResultDB
        from backend.models.anomaly import AnomalyResultDB
        from backend.models.db_event import TelemetryEventDB
        from backend.models.feature_snapshot import FeatureSnapshotDB

        try:
            db.query(AlertDB).delete()
            db.query(CaseDB).delete()
            db.query(RiskScoreDB).delete()
            db.query(FusionResultDB).delete()
            db.query(AnomalyResultDB).delete()
            db.query(TelemetryEventDB).delete()
            db.query(FeatureSnapshotDB).delete()
            db.commit()
            logger.info("Runtime database tables purged successfully.")
        except Exception as e:
            db.rollback()
            logger.error("Error clearing runtime database records: %s", e)
            raise e

        # 4. Clear WebSocket history
        ws_manager.clear_history()

        # 5. Broadcast reset event to all connected UI clients
        ws_manager.dispatch(
            "simulation.reset",
            {
                "status": "CLEAN",
                "message": "Demo state successfully reset to baseline clean state.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        return {
            "status": "CLEAN",
            "message": "Demo state reset successfully. All runtime alerts, cases, risk evaluations, and telemetry cleared. ML models preserved.",
            "current_threat_level": "LOW",
            "risk_score": 0.0,
            "active_alerts": 0,
            "critical_threats": 0,
            "open_cases": 0,
            "evidence_strength": "NONE",
            "simulation_state": "READY",
        }

    def _broadcast_status(self) -> None:
        """Broadcast current status via real-time WebSocket connection manager."""
        try:
            status_dict = self.get_status().model_dump(mode="json")
            ws_manager.dispatch("simulation.status", status_dict)
        except Exception as e:
            logger.debug("Failed to dispatch WebSocket simulation.status: %s", e)

    async def _run_simulation_task(
        self,
        scenario_name: str,
        seed: int,
        duration_seconds: int,
        intensity: str,
    ) -> None:
        """Main asynchronous simulation worker routine."""
        db = SessionLocal()
        try:
            # 1. Ensure ML detectors have normal baseline training data
            self._current_stage = "BASELINE CHECK & ML READINESS"
            self._progress = 5
            self._broadcast_status()

            ensure_ml_models_ready(db, seed=seed)

            if self._stop_requested:
                return

            # Multiplier for intensity
            intensity_mult = 0.6 if intensity == "low" else (1.5 if intensity == "high" else 1.0)

            if scenario_name == "all":
                await self._execute_full_showcase(db, seed=seed, duration_seconds=duration_seconds)
            else:
                await self._execute_single_scenario(
                    db,
                    scenario_name=scenario_name,
                    seed=seed,
                    duration_seconds=duration_seconds,
                    intensity_mult=intensity_mult,
                )

            if not self._stop_requested:
                self._completed = True
                self._progress = 100
                self._current_stage = "COMPLETE"

        except asyncio.CancelledError:
            self._current_stage = "STOPPED"
            logger.info("Simulation task was cancelled.")
        except Exception as exc:
            logger.exception("Simulation execution failed: %s", exc)
            self._error = str(exc)
            self._current_stage = "ERROR"
        finally:
            self._running = False
            self._broadcast_status()
            db.close()

    async def _execute_single_scenario(
        self,
        db: Any,
        scenario_name: str,
        seed: int,
        duration_seconds: int,
        intensity_mult: float,
    ) -> None:
        """Execute a single scenario with gradual batch pacing."""
        target_account: Optional[str] = None

        if scenario_name == "distributed_bruteforce":
            target_account = "account_001"
            ip_count = int(120 * intensity_mult)
            event_count = int(150 * intensity_mult)
            cfg = ScenarioConfig(
                name="distributed_bruteforce",
                seed=seed,
                count=event_count,
                parameters={"unique_ips": ip_count, "target_accounts": [target_account, "account_002"]},
            )
            scenario_obj = DistributedBruteForceScenario(cfg)
            stage_name = "DISTRIBUTED BRUTE FORCE"

        elif scenario_name == "credential_stuffing":
            ip_count = int(100 * intensity_mult)
            account_count = int(80 * intensity_mult)
            event_count = int(140 * intensity_mult)
            cfg = ScenarioConfig(
                name="credential_stuffing",
                seed=seed,
                count=event_count,
                parameters={"unique_ips": ip_count, "unique_accounts": account_count},
            )
            scenario_obj = CredentialStuffingScenario(cfg)
            stage_name = "CREDENTIAL STUFFING"

        elif scenario_name == "port_scan":
            ports = int(60 * intensity_mult)
            event_count = int(120 * intensity_mult)
            cfg = ScenarioConfig(
                name="port_scan",
                seed=seed,
                count=event_count,
                parameters={"scanner_count": 2, "ports_per_scanner": ports},
            )
            scenario_obj = PortScanScenario(cfg)
            stage_name = "PORT SCANNING"

        else:  # normal
            event_count = int(60 * intensity_mult)
            cfg = ScenarioConfig(name="normal", seed=seed, count=event_count)
            scenario_obj = NormalTrafficScenario(cfg)
            stage_name = "NORMAL BASELINE"

        self._current_stage = stage_name
        all_events = scenario_obj.generate()

        # Batch configuration
        batch_size = max(5, int(len(all_events) / max(10, int(duration_seconds / 0.8))))
        batches = [all_events[i : i + batch_size] for i in range(0, len(all_events), batch_size)]
        interval = max(0.1, min(0.6, duration_seconds / max(1, len(batches))))

        await self._stream_and_process_batches(
            db=db,
            batches=batches,
            target_account=target_account,
            interval=interval,
            stage_name=stage_name,
            progress_start=10,
            progress_end=95,
        )

    async def _execute_full_showcase(
        self,
        db: Any,
        seed: int,
        duration_seconds: int,
    ) -> None:
        """Execute the Full Attack Showcase sequentially through all phases."""
        stages = [
            ("NORMAL BASELINE", "normal", None, 50, 10, 25),
            ("DISTRIBUTED BRUTE FORCE", "distributed_bruteforce", "account_001", 120, 25, 50),
            ("RECOVERY / BASELINE", "normal", None, 30, 50, 60),
            ("CREDENTIAL STUFFING", "credential_stuffing", None, 100, 60, 75),
            ("RECOVERY / BASELINE", "normal", None, 30, 75, 82),
            ("PORT SCANNING", "port_scan", None, 90, 82, 95),
        ]

        stage_duration = max(5, int(duration_seconds / len(stages)))

        for stage_title, sc_type, target_acc, count, prog_start, prog_end in stages:
            if self._stop_requested:
                break

            self._current_stage = stage_title
            if sc_type == "distributed_bruteforce":
                cfg = ScenarioConfig(
                    name="distributed_bruteforce",
                    seed=seed,
                    count=count,
                    parameters={"unique_ips": 100, "target_accounts": ["account_001", "account_002"]},
                )
                sc = DistributedBruteForceScenario(cfg)
            elif sc_type == "credential_stuffing":
                cfg = ScenarioConfig(
                    name="credential_stuffing",
                    seed=seed,
                    count=count,
                    parameters={"unique_ips": 80, "unique_accounts": 60},
                )
                sc = CredentialStuffingScenario(cfg)
            elif sc_type == "port_scan":
                cfg = ScenarioConfig(
                    name="port_scan",
                    seed=seed,
                    count=count,
                    parameters={"scanner_count": 2, "ports_per_scanner": 45},
                )
                sc = PortScanScenario(cfg)
            else:
                cfg = ScenarioConfig(name="normal", seed=seed, count=count)
                sc = NormalTrafficScenario(cfg)

            events = sc.generate()
            batch_size = max(5, int(len(events) / max(6, int(stage_duration / 0.5))))
            batches = [events[i : i + batch_size] for i in range(0, len(events), batch_size)]
            interval = max(0.15, min(0.5, stage_duration / max(1, len(batches))))

            await self._stream_and_process_batches(
                db=db,
                batches=batches,
                target_account=target_acc,
                interval=interval,
                stage_name=stage_title,
                progress_start=prog_start,
                progress_end=prog_end,
            )

            # Brief pause between sequential attack showcase stages
            if not self._stop_requested:
                await asyncio.sleep(0.5)

    async def _stream_and_process_batches(
        self,
        db: Any,
        batches: List[List[Dict[str, Any]]],
        target_account: Optional[str],
        interval: float,
        stage_name: str,
        progress_start: int,
        progress_end: int,
    ) -> None:
        """Stream event batches at configured pacing through the real platform detection pipeline."""
        total_batches = len(batches)
        accumulated_events: List[Dict[str, Any]] = []

        for idx, batch in enumerate(batches):
            if self._stop_requested:
                break

            accumulated_events.extend(batch)
            self._events_generated += len(batch)

            # Process newly accumulated batch through real pipeline
            pipeline_result = run_simulation_pipeline(
                events=accumulated_events,
                db=db,
                window_seconds=300,
                target_account=target_account,
            )

            # Calculate progress within the stage range
            pct = (idx + 1) / total_batches
            self._progress = int(progress_start + (pct * (progress_end - progress_start)))
            self._current_stage = stage_name

            # Keep latest summary up to date
            r_res = pipeline_result.get("risk_score_result", {})
            f_res = pipeline_result.get("fusion_result", {})
            alt_res = pipeline_result.get("alert_result")
            case_res = pipeline_result.get("case_result")

            # Determine existing peak risk score
            current_score = r_res.get("final_score", 0.0)
            existing_peak = (self._last_result or {}).get("peak_risk_score", 0.0)
            peak_score = max(existing_peak, current_score)

            existing_alerts_count = (self._last_result or {}).get("alerts_created", 0)
            existing_cases_count = (self._last_result or {}).get("cases_created", 0)

            self._last_result = {
                "scenario": self._scenario,
                "events_generated": self._events_generated,
                "alerts_created": existing_alerts_count + (1 if alt_res else 0),
                "cases_created": existing_cases_count + (1 if case_res else 0),
                "peak_risk_score": round(peak_score, 1),
                "latest_risk_score": round(current_score, 1),
                "severity": r_res.get("severity", "LOW"),
                "evidence_strength": f_res.get("evidence_strength", "NORMAL"),
                "contributing_detectors": f_res.get("contributing_detectors", []),
                "isolation_forest_evaluated": pipeline_result.get("isolation_forest_evaluated", False),
                "clustering_evaluated": pipeline_result.get("clustering_evaluated", False),
                "explanation": r_res.get("explanation", ""),
            }

            self._broadcast_status()
            await asyncio.sleep(interval)


# Global singleton instance
simulation_service = SimulationManager()
