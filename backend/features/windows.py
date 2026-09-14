"""Time window definitions for Sh4d0w_St4lk3r behavioral feature engineering."""

from enum import IntEnum
from typing import List


class FeatureWindow(IntEnum):
    """Standard sliding time windows in seconds specified in the architecture blueprint."""
    WINDOW_60S = 60
    WINDOW_5M = 300
    WINDOW_15M = 900


SUPPORTED_WINDOWS: List[int] = [
    FeatureWindow.WINDOW_60S,
    FeatureWindow.WINDOW_5M,
    FeatureWindow.WINDOW_15M,
]


def window_to_label(seconds: int) -> str:
    """Return human-readable label for a window in seconds."""
    if seconds == 60:
        return "60s"
    if seconds == 300:
        return "5m"
    if seconds == 900:
        return "15m"
    return f"{seconds}s"
