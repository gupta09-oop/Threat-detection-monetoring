"""Normal enterprise baseline telemetry scenario."""

from datetime import timedelta
from typing import Any, Dict, List, Optional

from simulator.generators.auth_generator import generate_normal_auth_event
from simulator.generators.network_generator import generate_normal_network_event
from simulator.generators.system_generator import generate_normal_system_event
from simulator.scenarios.base import BaseScenario, ScenarioConfig


class NormalTrafficScenario(BaseScenario):
    """Generates realistic normal baseline telemetry.

    Characteristics from blueprint:
    - Low-volume authentication (~15%)
    - Stable devices & predictable geography
    - Predictable network ports (80, 443, 53, 8080) (~55%)
    - Routine system activity (process starts, file reads) (~30%)
    """

    def __init__(self, config: Optional[ScenarioConfig] = None):
        super().__init__(config)

    def generate(self) -> List[Dict[str, Any]]:
        """Generate deterministic normal traffic events."""
        events: List[Dict[str, Any]] = []
        current_ts = self.current_time

        for _ in range(self.config.count):
            # Advance time step
            current_ts += timedelta(seconds=self.config.time_step_seconds)

            # Determine event type based on normal enterprise distribution
            roll = self.rng.random()
            if roll < 0.15:
                # Low-volume authentication
                event = generate_normal_auth_event(self.rng, timestamp=current_ts)
            elif roll < 0.70:
                # Predictable network flows
                event = generate_normal_network_event(self.rng, timestamp=current_ts)
            else:
                # Routine system activity
                event = generate_normal_system_event(self.rng, timestamp=current_ts)

            # Annotate with scenario metadata (retained for debugging/demo, ignored by detector features)
            event["scenario"] = "normal"
            event["attack_stage"] = "baseline"
            event["synthetic_session"] = f"sess_normal_{self.config.seed}"
            event["scenario_seed"] = self.config.seed

            events.append(event)

        return events
