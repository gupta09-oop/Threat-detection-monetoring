"""Scenarios package for telemetry simulation."""

from simulator.scenarios.base import BaseScenario, ScenarioConfig
from simulator.scenarios.normal import NormalTrafficScenario
from simulator.scenarios.distributed_bruteforce import DistributedBruteForceScenario
from simulator.scenarios.credential_stuffing import CredentialStuffingScenario
from simulator.scenarios.port_scan import PortScanScenario
from simulator.scenarios.metrics import (
    calculate_scenario_metrics,
    calculate_normal_metrics,
    calculate_distributed_bruteforce_metrics,
    calculate_credential_stuffing_metrics,
    calculate_port_scan_metrics,
)

__all__ = [
    "BaseScenario",
    "ScenarioConfig",
    "NormalTrafficScenario",
    "DistributedBruteForceScenario",
    "CredentialStuffingScenario",
    "PortScanScenario",
    "calculate_scenario_metrics",
    "calculate_normal_metrics",
    "calculate_distributed_bruteforce_metrics",
    "calculate_credential_stuffing_metrics",
    "calculate_port_scan_metrics",
]
