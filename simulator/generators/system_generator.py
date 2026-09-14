"""Deterministic synthetic system activity telemetry generator."""

from datetime import datetime, timezone
import random
from typing import Any, Dict, Optional

NORMAL_HOSTS = [
    "DEV-CORP-W10-01",
    "DEV-CORP-W10-02",
    "DEV-CORP-MAC-01",
    "DEV-CORP-LNX-01",
]

NORMAL_PROCESSES = [
    ("chrome.exe", "PROCESS_START", "C:\\Program Files\\Google\\Chrome\\chrome.exe"),
    ("git.exe", "PROCESS_START", "C:\\Program Files\\Git\\bin\\git.exe"),
    ("code.exe", "PROCESS_START", "C:\\Users\\alice\\AppData\\Local\\Programs\\VSCode\\Code.exe"),
    ("sshd", "PROCESS_START", "/usr/sbin/sshd"),
    ("cron", "PROCESS_START", "/usr/sbin/cron"),
    ("systemd", "FILE_READ", "/etc/systemd/system.conf"),
]

SYSTEM_USERS = ["alice.smith", "bob.jones", "root", "SYSTEM"]


def generate_normal_system_event(
    rng: random.Random,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Generate a single deterministic routine system activity telemetry event."""
    ts = timestamp or datetime.now(timezone.utc)
    host = rng.choice(NORMAL_HOSTS)
    proc, event_type, resource = rng.choice(NORMAL_PROCESSES)
    user = "root" if "LNX" in host and rng.random() < 0.3 else rng.choice(SYSTEM_USERS)

    return {
        "timestamp": ts.isoformat(),
        "host": host,
        "process": proc,
        "event_type": event_type,
        "username": user,
        "resource": resource,
    }
