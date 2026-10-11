# tests/unit/test_replay_idempotence.py
"""Processing the same file twice must give the same result as processing it once."""

from datetime import datetime, timedelta

import pytest

from src.assets.inventory import AssetInventory
from src.incidents.store import IncidentStore
from src.models.detection_schema import DetectionResult
from src.models.event_schema import EventSource, EventType, NormalizedEvent, Severity
from src.models.incident_schema import Incident, IncidentPriority
from src.pipeline.orchestrator import PipelineOrchestrator
from src.storage.event_store import EventStore

T0 = datetime(2026, 10, 6, 10, 0, 0)


def make_incident():
    return Incident(
        title="Test Incident", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key="user:admin", first_seen=T0, last_seen=T0,
    )


def make_detection(description="Brute force pattern detected: 8 failed login attempts."):
    return DetectionResult(
        rule_name="Brute Force Detection", rule_id="SOC-BF-001", triggered=True,
        severity=Severity.HIGH, description=description,
    )


def test_adding_the_same_detection_twice_keeps_one():
    incident = make_incident()
    incident.add_detection(make_detection())
    incident.add_detection(make_detection())
    assert len(incident.detections) == 1


def test_a_detection_with_new_wording_is_still_recorded():
    incident = make_incident()
    incident.add_detection(make_detection())
    incident.add_detection(make_detection("Brute force pattern detected: 12 failed login attempts."))
    assert len(incident.detections) == 2


def batch(n):
    return [
        NormalizedEvent(
            timestamp=T0 + timedelta(seconds=20 * i), source=EventSource.WINDOWS,
            event_type=EventType.AUTHENTICATION, host="WS01", user="admin",
            src_ip="203.0.113.9", event_id="4625", status="failure",
        )
        for i in range(n)
    ]


def snapshot(events, incidents):
    return (
        len(events.get_events_by_correlation_key("user:admin")),
        [(i.title, i.risk_score, [(d.rule_id, d.description) for d in i.detections])
         for i in incidents.get_all()],
    )


@pytest.mark.parametrize("failures", [1, 3, 5, 8])
def test_replaying_a_file_changes_nothing(failures, monkeypatch):
    monkeypatch.setattr(PipelineOrchestrator, "investigate_incident", lambda self, incident, store: None)
    events, incidents = EventStore(), IncidentStore()
    orchestrator = PipelineOrchestrator(events, incidents, AssetInventory())

    orchestrator.ingest(batch(failures))
    first = snapshot(events, incidents)
    orchestrator.ingest(batch(failures))
    assert snapshot(events, incidents) == first


def test_two_rules_sharing_an_id_and_wording_are_both_recorded():
    incident = make_incident()
    rule_a = make_detection().model_copy(update={"rule_name": "Rule A"})
    rule_b = make_detection().model_copy(update={"rule_name": "Rule B"})
    incident.add_detection(rule_a)
    incident.add_detection(rule_b)
    assert len(incident.detections) == 2


def test_same_rule_with_larger_evidence_is_new_information():
    incident = make_incident()
    small = make_detection().model_copy(update={"evidence_event_count": 100, "evidence_duration_seconds": 60.0})
    incident.add_detection(small)
    incident.add_detection(small.model_copy(update={"evidence_event_count": 400}))
    assert len(incident.detections) == 2


def test_same_rule_with_identical_evidence_is_recorded_once():
    incident = make_incident()
    detection = make_detection().model_copy(update={"evidence_event_count": 100, "evidence_duration_seconds": 60.0})
    incident.add_detection(detection)
    incident.add_detection(detection.model_copy())
    assert len(incident.detections) == 1
