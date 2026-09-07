# tests/unit/test_port_scan.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.port_scan import detect_port_scan, detect_slow_port_scan
from src.detection.engine import DetectionEngine


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


# --- Fast port scan tests (Day 7) ---

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
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(seconds=i), conn_state="SF")
        for i, p in enumerate([21, 22, 23, 80, 443, 3389])
    ]
    result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
    assert result.triggered is False


def test_port_scan_repeated_same_port_does_not_trigger():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=443, ts=base_time + timedelta(seconds=i))
        for i in range(8)
    ]
    result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
    assert result.triggered is False


# --- Slow / low-and-slow port scan tests (Day 9) ---

def test_slow_scan_detects_pattern_spread_across_hours():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(hours=i))
        for i, p in enumerate([21, 22, 23, 80, 443])
    ]
    result = detect_slow_port_scan(events, unique_ports_threshold=5, window_hours=6)
    assert result.triggered is True
    assert result.severity == "medium"  # upgraded from "low" - see policy fix


def test_slow_scan_does_not_trigger_outside_window():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(hours=i * 3))
        for i, p in enumerate([21, 22, 23, 80, 443])
    ]
    result = detect_slow_port_scan(events, unique_ports_threshold=5, window_hours=6)
    assert result.triggered is False


def test_fast_and_slow_scan_do_not_both_fire_for_same_fast_pattern():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events = [
        make_conn_event(dst_port=p, ts=base_time + timedelta(seconds=i))
        for i, p in enumerate([21, 22, 23, 80, 443])
    ]
    engine = DetectionEngine()
    results = engine.run_batch_rules(events)

    scan_detections = [r for r in results if "Port Scan" in r.rule_name]
    assert len(scan_detections) == 1
    assert scan_detections[0].rule_name == "Port Scan Detection (Fast)"