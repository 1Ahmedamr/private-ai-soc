# tests/unit/test_c2_beacon.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.c2_beacon import detect_c2_beacon


def make_conn_event(ts, src_ip="10.0.0.5", dst_ip="185.220.101.5"):
    return NormalizedEvent(
        timestamp=ts, source=EventSource.ZEEK, event_type=EventType.NETWORK_CONNECTION,
        src_ip=src_ip, dst_ip=dst_ip, dst_port=443, protocol="tcp", conn_state="SF",
    )


def test_periodic_connections_trigger():
    base = datetime(2026, 9, 1, 10, 0, 0)
    events = [make_conn_event(base + timedelta(seconds=i * 60)) for i in range(8)]
    result = detect_c2_beacon(events, min_connections=5, max_interval_variance_ratio=0.15)
    assert result.triggered is True
    assert result.severity == "critical"
    assert result.mitre_technique == "T1071"


def test_irregular_connections_do_not_trigger():
    base = datetime(2026, 9, 1, 10, 0, 0)
    irregular = [0, 15, 300, 45, 180, 5, 240, 90]
    events = [make_conn_event(base + timedelta(seconds=s)) for s in irregular]
    result = detect_c2_beacon(events, min_connections=5, max_interval_variance_ratio=0.15)
    assert result.triggered is False


def test_below_min_connections_does_not_trigger():
    base = datetime(2026, 9, 1, 10, 0, 0)
    events = [make_conn_event(base + timedelta(seconds=i * 60)) for i in range(3)]
    result = detect_c2_beacon(events, min_connections=5, max_interval_variance_ratio=0.15)
    assert result.triggered is False


def test_different_destinations_grouped_separately():
    base = datetime(2026, 9, 1, 10, 0, 0)
    events_a = [make_conn_event(base + timedelta(seconds=i * 60), dst_ip="1.2.3.4") for i in range(6)]
    events_b = [make_conn_event(base + timedelta(seconds=i * 17), dst_ip="5.6.7.8") for i in range(6)]
    result = detect_c2_beacon(events_a + events_b, min_connections=5, max_interval_variance_ratio=0.15)
    assert result.triggered is True
