# tests/unit/test_multi_source_pipeline.py

from datetime import datetime, timedelta
from src.ingestion.windows_parser import parse_windows_events
from src.ingestion.zeek_parser import parse_zeek_conn_logs
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore


def test_windows_and_zeek_events_both_produce_incidents_via_same_engine():
    """
    The core proof: Detection Engine and Incident Engine handle BOTH
    Windows and Zeek-sourced events without any source-specific branching
    in those engines.
    """
    windows_raw = [
        {"timestamp": f"2026-09-05T10:00:{i:02d}", "event_id": 4625, "username": "admin", "src_ip": "10.0.0.10"}
        for i in range(6)
    ]
    zeek_raw = [
        {"ts": 1725600000.0 + i, "id.orig_h": "10.0.0.15", "id.orig_p": 51000 + i,
         "id.resp_h": "10.0.0.50", "id.resp_p": p, "proto": "tcp", "conn_state": "S0"}
        for i, p in enumerate([21, 22, 23, 80, 443, 3389])
    ]

    windows_events = parse_windows_events(windows_raw)
    zeek_events = parse_zeek_conn_logs(zeek_raw)

    engine = DetectionEngine()
    store = IncidentStore()
    incident_engine = IncidentEngine(store)

    windows_detections = engine.analyze(windows_events)
    incident_engine.process(windows_events, windows_detections)

    zeek_detections = engine.analyze(zeek_events)
    incident_engine.process(zeek_events, zeek_detections)

    # Both should have produced exactly one incident each - two total,
    # correlated by different keys (user:admin vs ip:10.0.0.15)
    assert store.count() == 2

    correlation_keys = {i.correlation_key for i in store.get_all()}
    assert "user:admin" in correlation_keys
    assert "ip:10.0.0.15" in correlation_keys