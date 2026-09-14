"""Credential Stuffing attack scenario.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform

Characteristics:
- ~300 source IPs
- ~200 targeted accounts
- Approximately 95% login failures, ~5% successes (valid dumped credentials)
- Diverse, previously unseen synthetic devices
- High account diversity and high IP diversity across broad entity combinations.
"""

from datetime import datetime, timedelta, timezone
import random
from typing import Any, Dict, List, Optional

from simulator.scenarios.base import BaseScenario, ScenarioConfig

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


class CredentialStuffingScenario(BaseScenario):
    """Generates synthetic credential stuffing telemetry against enterprise accounts."""

    def __init__(self, config: Optional[ScenarioConfig] = None):
        super().__init__(config)
        self.ip_count = self.config.parameters.get("unique_ips", 300)
        self.account_count = self.config.parameters.get("unique_accounts", 200)

    def _generate_synthetic_ips(self, count: int) -> List[str]:
        """Generate deterministic synthetic IPs across multiple test subnets."""
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
        """Generate deterministic credential stuffing attack events."""
        events: List[Dict[str, Any]] = []

        ip_pool = self._generate_synthetic_ips(self.ip_count)
        account_pool = [f"user_{i:03d}@enterprise.local" for i in range(1, self.account_count + 1)]

        self.rng.shuffle(ip_pool)
        self.rng.shuffle(account_pool)

        current_ts = self.current_time
        window_duration = self.config.parameters.get("window_seconds", 300.0)
        time_step = window_duration / max(1, self.ip_count)

        # Generate pairings across ~300 IPs and ~200 accounts
        for i in range(self.ip_count):
            current_ts += timedelta(seconds=max(0.1, time_step + self.rng.uniform(-0.1, 0.1)))

            source_ip = ip_pool[i]
            target_account = account_pool[i % len(account_pool)]

            # ~95% login failures, ~5% login successes
            is_success = self.rng.random() < 0.05
            login_result = "SUCCESS" if is_success else "FAILURE"

            # Fresh, unseen device ID per bot/session
            device_id = f"UNSEEN-BOT-{self.rng.randint(100000, 999999)}"
            user_agent = self.rng.choice(USER_AGENTS)

            event = {
                "timestamp": current_ts.isoformat(),
                "source_ip": source_ip,
                "user_id": target_account,
                "login_result": login_result,
                "auth_method": "PASSWORD",
                "device_id": device_id,
                "geo_country": self.rng.choice(["US", "FR", "NL", "BR", "VN", "RU"]),
                "geo_city": self.rng.choice(["Paris", "Amsterdam", "Hanoi", "Sao Paulo", "Moscow"]),
                "user_agent": user_agent,
                "session_id": f"sess_credstuff_{self.config.seed}_{i}",
                # Scenario metadata
                "scenario": "credential_stuffing",
                "attack_stage": "attack",
                "synthetic_session": f"sess_credstuff_{self.config.seed}",
                "scenario_seed": self.config.seed,
            }
            events.append(event)

        return events
