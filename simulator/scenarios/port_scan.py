"""Port Scanning / Network Reconnaissance scenario.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Characteristics:
- 1–5 source IPs
- 50–200 destination ports per scanner IP
- Protocol: TCP
- High proportion of REFUSED / TIMEOUT connection failures (~90%+)
- Small proportion of successful ALLOW connections (~10%)
- Naturally triggers network behavioral features: unique_destination_ports,
  port_diversity, connection_rate, failed_connection_rate.
"""

from datetime import datetime, timedelta, timezone
import random
from typing import Any, Dict, List, Optional

from simulator.scenarios.base import BaseScenario, ScenarioConfig

COMMON_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
]


class PortScanScenario(BaseScenario):
    """Generates synthetic TCP port scanning and network reconnaissance telemetry."""

    def __init__(self, config: Optional[ScenarioConfig] = None):
        super().__init__(config)
        self.scanner_count = self.config.parameters.get("scanner_count", 2)
        self.ports_per_scanner = self.config.parameters.get("ports_per_scanner", 75)
        self.target_host = self.config.parameters.get("target_host", "10.0.1.50")

    def generate(self) -> List[Dict[str, Any]]:
        """Generate deterministic TCP port scanning flow events."""
        events: List[Dict[str, Any]] = []

        scanner_ips = [f"198.51.100.{200 + i}" for i in range(1, self.scanner_count + 1)]

        current_ts = self.current_time
        window_duration = self.config.parameters.get("window_seconds", 300.0)
        total_probes = self.scanner_count * self.ports_per_scanner
        time_step = window_duration / max(1, total_probes)

        for scanner_ip in scanner_ips:
            # Build a deterministic pool of destination ports (common + high ports)
            candidate_ports = list(COMMON_SCAN_PORTS)
            # Add additional ports up to self.ports_per_scanner
            extra_port = 1024
            while len(candidate_ports) < self.ports_per_scanner:
                if extra_port not in candidate_ports:
                    candidate_ports.append(extra_port)
                extra_port += self.rng.randint(5, 50)

            scan_ports = candidate_ports[:self.ports_per_scanner]
            self.rng.shuffle(scan_ports)

            for port in scan_ports:
                current_ts += timedelta(seconds=max(0.05, time_step + self.rng.uniform(-0.02, 0.05)))

                # 90%+ failed connection results (REFUSED or TIMEOUT)
                roll = self.rng.random()
                if roll < 0.70:
                    conn_result = "DENY"  # TCP RST / Connection refused
                elif roll < 0.90:
                    conn_result = "DENY"  # TCP Timeout / Dropped by firewall
                else:
                    conn_result = "ALLOW" # Open port

                event = {
                    "timestamp": current_ts.isoformat(),
                    "source_ip": scanner_ip,
                    "destination_ip": self.target_host,
                    "destination_port": port,
                    "protocol": "TCP",
                    "bytes_sent": self.rng.randint(40, 64),       # SYN packet size
                    "bytes_received": 0 if conn_result == "DENY" else self.rng.randint(40, 64),
                    "connection_result": conn_result,
                    # Scenario metadata
                    "scenario": "port_scan",
                    "attack_stage": "recon",
                    "synthetic_session": f"sess_portscan_{self.config.seed}_{scanner_ip}",
                    "scenario_seed": self.config.seed,
                }
                events.append(event)

        return events
