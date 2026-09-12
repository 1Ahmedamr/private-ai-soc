# tests/scenarios/scenario_definitions.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType


def scenario_brute_force():
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 20), source=EventSource.WINDOWS,
            event_type=EventType.AUTHENTICATION, user="admin", event_id="4625", status="failure",
        )
        for i in range(6)
    ]
    return {"name": "Brute Force", "events": events, "expect_incident": True, "expect_rule": "Brute Force Detection"}


def scenario_powershell_execution_placeholder():
    """
    Roadmap Scenario 2. Genuinely NOT buildable yet - we have no
    process-execution event type wired to a real detection rule (that
    needs Sysmon-style parsing, not yet built). Marked explicitly as a
    gap rather than faked, so the benchmark report is honest about
    coverage instead of padding the number of "scenarios" dishonestly.
    """
    return {"name": "PowerShell Execution", "events": [], "expect_incident": False, "not_implemented": True}


def scenario_suspicious_dns_placeholder():
    """Roadmap Scenario 3 - needs Zeek dns.log parsing, not yet built."""
    return {"name": "Suspicious DNS", "events": [], "expect_incident": False, "not_implemented": True}


def scenario_port_scanning():
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base + timedelta(seconds=i), source=EventSource.ZEEK,
            event_type=EventType.NETWORK_CONNECTION, src_ip="10.0.0.15", dst_ip="10.0.0.50",
            dst_port=p, protocol="tcp", conn_state="S0",
        )
        for i, p in enumerate([21, 22, 23, 80, 443, 3389])
    ]
    return {"name": "Port Scanning", "events": events, "expect_incident": True, "expect_rule": "Port Scan Detection (Fast)"}


def scenario_possible_c2_placeholder():
    """Roadmap Scenario 5 - the C2 beacon placeholder rule from Day 8 was never wired into DetectionEngine (deliberately, per that day's notes). Still a gap."""
    return {"name": "Possible C2", "events": [], "expect_incident": False, "not_implemented": True}


def scenario_credential_attack():
    """SSH root brute force - a distinct scenario from generic brute force per Day 12's rule."""
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 15), source=EventSource.LINUX,
            event_type=EventType.AUTHENTICATION, user="root", src_ip="45.33.12.99",
            event_id="failed_password", status="failure",
        )
        for i in range(5)
    ]
    return {"name": "Credential Attack (SSH Root)", "events": events, "expect_incident": True, "expect_rule": "SSH Root Brute Force"}


def scenario_benign_activity():
    """
    Roadmap Scenario 7 - THE MOST IMPORTANT ONE FOR TRUST. A pile of
    completely normal successful logins across different users. If this
    ever creates an incident, that's a false positive bug, full stop.
    """
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base + timedelta(minutes=i * 10), source=EventSource.WINDOWS,
            event_type=EventType.AUTHENTICATION, user=f"employee{i}", event_id="4624", status="success",
        )
        for i in range(10)
    ]
    return {"name": "Benign Activity", "events": events, "expect_incident": False}


ALL_SCENARIOS = [
    scenario_brute_force,
    scenario_powershell_execution_placeholder,
    scenario_suspicious_dns_placeholder,
    scenario_port_scanning,
    scenario_possible_c2_placeholder,
    scenario_credential_attack,
    scenario_benign_activity,
]