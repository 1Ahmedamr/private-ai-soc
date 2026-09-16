# tests/unit/test_timeline.py

from datetime import datetime, timedelta
from src.models.incident_schema import Incident, IncidentPriority
from src.models.event_schema import Severity, NormalizedEvent, EventSource, EventType
from src.models.detection_schema import DetectionResult
from src.dashboard.timeline import build_timeline_entries


def test_timeline_sorts_events_and_detections_chronologically():
    base = datetime(2026, 9, 1, 10, 0, 0)
    incident = Incident(
        title="Test", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key="user:admin", first_seen=base, last_seen=base + timedelta(minutes=5),
        events=[
            NormalizedEvent(timestamp=base, source=EventSource.WINDOWS, event_type=EventType.AUTHENTICATION, user="admin"),
            NormalizedEvent(timestamp=base + timedelta(minutes=2), source=EventSource.WINDOWS, event_type=EventType.AUTHENTICATION, user="admin"),
        ],
        detections=[DetectionResult(rule_name="Test Rule", rule_id="X", triggered=True, severity=Severity.HIGH, description="test")],
    )

    timeline = build_timeline_entries(incident)
    timestamps = [e["timestamp"] for e in timeline]
    assert timestamps == sorted(timestamps)


def test_timeline_includes_both_events_and_detections():
    base = datetime(2026, 9, 1, 10, 0, 0)
    incident = Incident(
        title="Test", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key="user:admin", first_seen=base, last_seen=base,
        events=[NormalizedEvent(timestamp=base, source=EventSource.WINDOWS, event_type=EventType.AUTHENTICATION, user="admin")],
        detections=[DetectionResult(rule_name="Test Rule", rule_id="X", triggered=True, severity=Severity.HIGH, description="test")],
    )

    timeline = build_timeline_entries(incident)
    types = {e["type"] for e in timeline}
    assert types == {"event", "detection"}