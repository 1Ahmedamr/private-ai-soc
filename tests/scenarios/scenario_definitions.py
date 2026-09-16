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


def scenario_powershell_execution():
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base, source=EventSource.WINDOWS,
            event_type=EventType.PROCESS_EXECUTION, user="admin", host="WIN-CLIENT",
            process="powershell.exe", command="powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        )
    ]
    return {"name": "PowerShell Execution", "events": events, "expect_incident": True, "expect_rule": "Suspicious PowerShell Execution"}


def scenario_suspicious_dns():
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base, source=EventSource.ZEEK,
            event_type=EventType.DNS_QUERY, src_ip="10.0.0.15",
            event_id="a3f8k2p9m1q7.malware-c2.net",
        )
    ]
    return {"name": "Suspicious DNS", "events": events, "expect_incident": True, "expect_rule": "Suspicious DNS (High-Entropy Domain)"}


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


def scenario_possible_c2():
    base = datetime(2026, 9, 11, 9, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 60),
            source=EventSource.ZEEK, event_type=EventType.NETWORK_CONNECTION,
            src_ip="10.0.0.15", dst_ip="185.220.101.5",
            dst_port=443, protocol="tcp", conn_state="SF",
        )
        for i in range(8)
    ]
    return {"name": "Possible C2", "events": events, "expect_incident": True, "expect_rule": "Possible C2 Beacon (Periodic Connections)"}


def scenario_credential_attack():
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
    scenario_powershell_execution,
    scenario_suspicious_dns,
    scenario_port_scanning,
    scenario_possible_c2,
    scenario_credential_attack,
    scenario_benign_activity,
]
