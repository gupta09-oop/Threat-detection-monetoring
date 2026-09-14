"""Distributed Low-and-Slow Brute Force attack scenario.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Characteristics:
- ~500 unique source IPs
- Strictly 1–2 login attempts per source IP
- Concentrated targeting against a small number of accounts (e.g., account_001, account_002, account_003)
- Individual IPs look completely normal and benign
- Collective behavior exposes elevated unique_source_ips, ip_to_account_ratio,
  and distributed_attempt_score.
"""

from datetime import datetime, timedelta, timezone
import random
from typing import Any, Dict, List, Optional

from simulator.scenarios.base import BaseScenario, ScenarioConfig

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

AUTH_METHODS = ["PASSWORD", "PASSWORD", "PASSWORD", "SSO"]


class DistributedBruteForceScenario(BaseScenario):
    """Generates synthetic distributed low-and-slow brute force attack telemetry."""

    def __init__(self, config: Optional[ScenarioConfig] = None):
        super().__init__(config)
        # Default to 500 IPs if not overridden
        self.target_ip_count = self.config.parameters.get("unique_ips", max(50, self.config.count))
        self.target_accounts = self.config.parameters.get(
            "target_accounts", ["account_001", "account_002", "account_003"]
        )

    def _generate_synthetic_ips(self, count: int) -> List[str]:
        """Deterministically generate a pool of synthetic test IP addresses (RFC 5737)."""
        ips: List[str] = []
        subnets = ["198.51.100", "203.0.113", "192.0.2"]
        subnet_idx = 0
        host_idx = 1

        for _ in range(count):
            ips.append(f"{subnets[subnet_idx]}.{host_idx}")
            host_idx += 1
            if host_idx > 254:
                host_idx = 1
                subnet_idx = (subnet_idx + 1) % len(subnets)

        return ips

    def generate(self) -> List[Dict[str, Any]]:
        """Generate deterministic distributed low-and-slow authentication events."""
        events: List[Dict[str, Any]] = []
        ip_pool = self._generate_synthetic_ips(self.target_ip_count)

        # Shuffle deterministically using scenario RNG
        self.rng.shuffle(ip_pool)

        current_ts = self.current_time
        # Compress event timestamps so entire distributed attack occurs within a 300s window
        window_duration = self.config.parameters.get("window_seconds", 300.0)
        time_increment = window_duration / max(1, len(ip_pool) * 1.5)

        for i, source_ip in enumerate(ip_pool):
            # Strictly 1 or 2 attempts per IP (individual IP is quiet and benign)
            attempts_for_ip = 1 if self.rng.random() < 0.75 else 2

            for attempt_idx in range(attempts_for_ip):
                current_ts += timedelta(seconds=max(0.1, time_increment + self.rng.uniform(-0.1, 0.2)))

                # Concentrated targeting: 75% attempts hit primary account_001
                if self.rng.random() < 0.75:
                    target_account = self.target_accounts[0]
                else:
                    target_account = self.rng.choice(self.target_accounts[1:]) if len(self.target_accounts) > 1 else self.target_accounts[0]

                # Low-and-slow password guessing: mostly failures (~97%), rare MFA lock or failure
                login_result = "FAILURE" if self.rng.random() < 0.97 else "FAILURE"

                device_id = f"DEV-EXT-{self.rng.randint(10000, 99999)}"
                user_agent = self.rng.choice(USER_AGENTS)
                auth_method = self.rng.choice(AUTH_METHODS)

                event = {
                    "timestamp": current_ts.isoformat(),
                    "source_ip": source_ip,
                    "user_id": target_account,
                    "login_result": login_result,
                    "auth_method": auth_method,
                    "device_id": device_id,
                    "geo_country": self.rng.choice(["US", "DE", "NL", "GB", "SG"]),
                    "geo_city": self.rng.choice(["Frankfurt", "Amsterdam", "London", "Dallas", "Singapore"]),
                    "user_agent": user_agent,
                    "session_id": f"sess_distbf_{self.config.seed}_{i}_{attempt_idx}",
                    # Scenario metadata
                    "scenario": "distributed_bruteforce",
                    "attack_stage": "attack",
                    "synthetic_session": f"sess_distbf_{self.config.seed}",
                    "scenario_seed": self.config.seed,
                }
                events.append(event)

        return events
