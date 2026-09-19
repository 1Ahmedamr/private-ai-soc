# tests/unit/test_risk_scoring.py

from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority
from src.models.detection_schema import DetectionResult
from src.models.event_schema import Severity, NormalizedEvent, EventSource, EventType
from src.risk.scoring import calculate_risk_score


def make_incident(severity=Severity.HIGH, detections=None, events=None):
    return Incident(
        title="Test Incident",
        priority=IncidentPriority.P2_HIGH,
        severity=severity,
        correlation_key="user:admin",
        detections=detections or [],
        events=events or [],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )


def make_detection(confidence=1.0):
    return DetectionResult(
        rule_name="Test Rule", rule_id="TEST-001", triggered=True,
        severity=Severity.HIGH, description="test", confidence=confidence,
    )


def make_event():
    return NormalizedEvent(
        timestamp=datetime.now(), source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION, user="admin", event_id="4625", status="failure",
    )


def test_higher_severity_gives_higher_base_score():
    low_incident = make_incident(severity=Severity.LOW, detections=[make_detection()])
    high_incident = make_incident(severity=Severity.HIGH, detections=[make_detection()])
    assert calculate_risk_score(high_incident) > calculate_risk_score(low_incident)


def test_more_evidence_increases_score():
    single = make_incident(detections=[make_detection()])
    multiple = make_incident(detections=[make_detection(), make_detection()])
    assert calculate_risk_score(multiple) >= calculate_risk_score(single)


def test_low_confidence_reduces_score():
    high_conf = make_incident(detections=[make_detection(confidence=1.0)])
    low_conf = make_incident(detections=[make_detection(confidence=0.3)])
    assert calculate_risk_score(high_conf) > calculate_risk_score(low_conf)


def test_critical_asset_boosts_score():
    incident = make_incident(detections=[make_detection()])
    normal = calculate_risk_score(incident, is_critical_asset=False)
    critical = calculate_risk_score(incident, is_critical_asset=True)
    assert critical > normal


def test_score_never_exceeds_100():
    incident = make_incident(
        severity=Severity.CRITICAL,
        detections=[make_detection(confidence=1.0) for _ in range(10)],
        events=[make_event() for _ in range(2000)],
    )
    assert calculate_risk_score(incident, is_critical_asset=True) <= 100


def test_score_never_negative():
    incident = make_incident(severity=Severity.INFO, detections=[])
    assert calculate_risk_score(incident) >= 0


def test_high_volume_events_increase_score():
    """Volume bonus should make a high-event-count incident score higher."""
    few_events = make_incident(
        detections=[make_detection()],
        events=[make_event() for _ in range(5)],
    )
    many_events = make_incident(
        detections=[make_detection()],
        events=[make_event() for _ in range(1500)],
    )
    assert calculate_risk_score(many_events) > calculate_risk_score(few_events)
