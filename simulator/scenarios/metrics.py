"""Scenario validation metrics calculator and formatting.

Sh4d0w_St4lk3r — Behavioral Threat Intelligence & Anomaly Detection Platform
"""

from collections import Counter
from typing import Any, Dict, List


def calculate_normal_metrics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate validation metrics for Normal baseline scenario."""
    unique_ips = len({e.get("source_ip") for e in events if e.get("source_ip")})
    unique_accounts = len({e.get("user_id") for e in events if e.get("user_id")})
    unique_ports = len({e.get("destination_port") for e in events if e.get("destination_port")})

    auth_events = [e for e in events if e.get("login_result")]
    auth_success = sum(1 for e in auth_events if e.get("login_result") == "SUCCESS")
    auth_failure = sum(1 for e in auth_events if e.get("login_result") == "FAILURE")
    success_rate = (auth_success / len(auth_events)) if auth_events else 1.0

    return {
        "event_count": len(events),
        "unique_ips": unique_ips,
        "unique_accounts": unique_accounts,
        "unique_ports": unique_ports,
        "auth_event_count": len(auth_events),
        "success_rate": round(success_rate, 4),
        "failure_rate": round(1.0 - success_rate, 4),
    }


def calculate_distributed_bruteforce_metrics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate validation metrics for Distributed Low-and-Slow Brute Force scenario."""
    ip_counter = Counter(e.get("source_ip") for e in events if e.get("source_ip"))
    account_counter = Counter(e.get("user_id") for e in events if e.get("user_id"))

    unique_ips = len(ip_counter)
    attempts_per_ip = (len(events) / unique_ips) if unique_ips else 0.0

    return {
        "event_count": len(events),
        "unique_source_ips": unique_ips,
        "attempts_per_ip": round(attempts_per_ip, 2),
        "targeted_accounts": len(account_counter),
        "attempts_per_target_account": dict(account_counter),
        "max_attempts_single_ip": max(ip_counter.values()) if ip_counter else 0,
        "min_attempts_single_ip": min(ip_counter.values()) if ip_counter else 0,
    }


def calculate_credential_stuffing_metrics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate validation metrics for Credential Stuffing scenario."""
    unique_ips = len({e.get("source_ip") for e in events if e.get("source_ip")})
    unique_accounts = len({e.get("user_id") for e in events if e.get("user_id")})
    unique_devices = len({e.get("device_id") for e in events if e.get("device_id")})

    success_count = sum(1 for e in events if e.get("login_result") == "SUCCESS")
    failure_count = sum(1 for e in events if e.get("login_result") == "FAILURE")
    failure_rate = (failure_count / len(events)) if events else 0.0

    return {
        "event_count": len(events),
        "unique_ips": unique_ips,
        "unique_accounts": unique_accounts,
        "unseen_devices": unique_devices,
        "success_count": success_count,
        "failure_count": failure_count,
        "failure_rate": round(failure_rate, 4),
    }


def calculate_port_scan_metrics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate validation metrics for Port Scan scenario."""
    unique_ips = len({e.get("source_ip") for e in events if e.get("source_ip")})
    unique_ports = len({e.get("destination_port") for e in events if e.get("destination_port")})

    failed_connections = sum(
        1 for e in events if e.get("connection_result") in ("DENY", "REFUSED", "TIMEOUT", "DROP")
    )
    failed_rate = (failed_connections / len(events)) if events else 0.0

    return {
        "connection_count": len(events),
        "unique_source_ips": unique_ips,
        "unique_destination_ports": unique_ports,
        "failed_connections": failed_connections,
        "failed_connection_rate": round(failed_rate, 4),
    }


def calculate_scenario_metrics(scenario_name: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Dispatch metrics calculation based on scenario name."""
    s = scenario_name.lower().strip()
    if s == "normal":
        return calculate_normal_metrics(events)
    elif s == "distributed_bruteforce":
        return calculate_distributed_bruteforce_metrics(events)
    elif s == "credential_stuffing":
        return calculate_credential_stuffing_metrics(events)
    elif s == "port_scan":
        return calculate_port_scan_metrics(events)
    else:
        return {"event_count": len(events)}
