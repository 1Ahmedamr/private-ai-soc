# tests/unit/test_incident_engine.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore
from src.incidents.policy import should_open_incident
from src.incidents.correlation_key import extract_correlation_key


def make_event(user="admin", src_ip="10.0.0.5", ts=None):
    return NormalizedEvent(
        timestamp=ts or datetime.now(),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user=user,
        src_ip=src_ip,
        event_id="4625",
        status="failure",
    )


def make_detection(severity=Severity.HIGH, rule_name="Test Rule", mitre="T1110"):
    return DetectionResult(
        rule_name=rule_name,
        rule_id="TEST-001",
        triggered=True,
        severity=severity,
        mitre_technique=mitre,
        description="test detection",
    )


# --- Policy Tests ---

def test_low_severity_does_not_qualify_for_incident():
    detection = make_detection(severity=Severity.LOW)
    assert should_open_incident(detection) is False


def test_medium_severity_qualifies_for_incident():
    detection = make_detection(severity=Severity.MEDIUM)
    assert should_open_incident(detection) is True


def test_high_severity_qualifies_for_incident():
    detection = make_detection(severity=Severity.HIGH)
    assert should_open_incident(detection) is True


# --- Correlation Key Tests ---

def test_correlation_key_uses_user_first():
    events = [make_event(user="admin", src_ip="10.0.0.5")]
    key = extract_correlation_key(events)
    assert key == "user:admin"


def test_correlation_key_falls_back_to_ip():
    events = [make_event(user=None, src_ip="10.0.0.5")]
    key = extract_correlation_key(events)
    assert key == "ip:10.0.0.5"


# --- Incident Engine Tests ---

def test_low_severity_detection_does_not_create_incident():
    store = IncidentStore()
    engine = IncidentEngine(store)
    events = [make_event()]
    detections = [make_detection(severity=Severity.LOW)]

    incidents = engine.process(events, detections)

    assert len(incidents) == 0
    assert store.count() == 0


def test_high_severity_detection_creates_incident():
    store = IncidentStore()
    engine = IncidentEngine(store)
    events = [make_event()]
    detections = [make_detection(severity=Severity.HIGH)]

    incidents = engine.process(events, detections)

    assert len(incidents) == 1
    assert store.count() == 1
    assert incidents[0].severity == Severity.HIGH
    assert "T1110" in incidents[0].mitre_techniques


def test_duplicate_detections_update_same_incident_not_create_new():
    """
    ده أهم test هنا - بيتأكد إن الـdeduplication شغالة فعليًا.
    """
    store = IncidentStore()
    engine = IncidentEngine(store)
    events = [make_event(user="admin")]

    # أول detection
    detections_1 = [make_detection(severity=Severity.MEDIUM, rule_name="Rule A")]
    engine.process(events, detections_1)

    # تاني detection لنفس الـuser
    detections_2 = [make_detection(severity=Severity.HIGH, rule_name="Rule B")]
    engine.process(events, detections_2)

    # المفروض لسه incident واحد بس، مش اتنين
    assert store.count() == 1

    incident = store.get_all()[0]
    # لكن الـseverity اتصعدت للـHIGH (escalation)
    assert incident.severity == Severity.HIGH
    # وعنده الـ2 detections مسجلين
    assert len(incident.detections) == 2


def test_different_users_create_separate_incidents():
    store = IncidentStore()
    engine = IncidentEngine(store)

    events_user1 = [make_event(user="admin")]
    events_user2 = [make_event(user="john")]

    detections = [make_detection(severity=Severity.HIGH)]

    engine.process(events_user1, detections)
    engine.process(events_user2, detections)

    # المفروض 2 incidents منفصلين - لأن الـcorrelation key مختلف
    assert store.count() == 2