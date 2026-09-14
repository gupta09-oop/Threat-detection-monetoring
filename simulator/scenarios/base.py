"""Base scenario abstraction for the Sh4d0w_St4lk3r simulator.

Designed to allow seamless addition of future attack scenarios
(brute-force, credential stuffing, port scan) without redesigning the engine.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
import random
from typing import Any, Dict, List, Optional


@dataclass
class ScenarioConfig:
    """Configuration settings for a simulation scenario run."""
    name: str = "normal"
    seed: int = 42
    count: int = 50
    start_time: Optional[datetime] = None
    time_step_seconds: float = 1.0
    parameters: Dict[str, Any] = field(default_factory=dict)


class BaseScenario(ABC):
    """Abstract base class for telemetry simulation scenarios."""

    def __init__(self, config: Optional[ScenarioConfig] = None):
        self.config = config or ScenarioConfig()
        self.rng = random.Random(self.config.seed)
        # Default to deterministic baseline timestamp if not explicitly specified
        self.current_time = self.config.start_time or datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @abstractmethod
    def generate(self) -> List[Dict[str, Any]]:
        """Generate synthetic telemetry events deterministically."""
        pass
