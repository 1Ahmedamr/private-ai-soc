# tests/unit/test_port_scan.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.port_scan import detect_port_scan


def make_conn_event(dst_port, ts, src_ip="10.0.0.15", dst_ip="10.0.0.50", conn_state="S0"):
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.ZEEK,
        event_type=EventType.NETWORK_CONNECTION,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="tcp",
        conn_state=conn_state,
    )


def test_port_scan_triggers_with_enough_unique_ports():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(seconds=i))
        for i, p in enumerate([21, 22, 23, 80, 443, 3389])
    ]
    result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
    assert result.triggered is True
    assert result.mitre_technique == "T1046"


def test_port_scan_does_not_trigger_below_threshold():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(seconds=i))
        for i, p in enumerate([80, 443])
    ]
    result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
    assert result.triggered is False


def test_port_scan_ignores_successful_connections():
    """
    conn_state = 'SF' means a NORMAL, successfully completed connection.
    A host visiting many ports with successful, legitimate connections
    (e.g. a monitoring tool) should NOT be flagged as scanning.
    """
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(seconds=i), conn_state="SF")
        for i, p in enumerate([21, 22, 23, 80, 443, 3389])
    ]
    result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
    assert result.triggered is False


def test_port_scan_repeated_same_port_does_not_trigger():
    """
    Many connection attempts to the SAME port (not many different ports)
    should NOT count as scanning - e.g. a service that's down and being
    retried isn't reconnaissance.
    """
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=443, ts=base_time + timedelta(seconds=i))
        for i in range(8)
    ]
    result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
    assert result.triggered is False