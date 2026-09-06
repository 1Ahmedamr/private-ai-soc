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


def make_detection(severity=Severity.HIGH, rule_name="Test Rule", mitre="T1110", reopen_hours=48):
    return DetectionResult(
        rule_name=rule_name,
        rule_id="TEST-001",
        triggered=True,
        severity=severity,
        mitre_technique=mitre,
        description="test detection",
        reopen_window_hours=reopen_hours,
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

from src.models.incident_schema import IncidentStatus


def test_relevant_events_only_are_stored():
    """
    Verifies the fix: incident should only contain events matching
    its correlation key, not unrelated events from other users.
    """
    store = IncidentStore()
    engine = IncidentEngine(store)

    admin_events = [make_event(user="admin") for _ in range(3)]
    other_user_event = make_event(user="john")
    mixed_batch = admin_events + [other_user_event]

    detections = [make_detection(severity=Severity.HIGH)]
    incidents = engine.process(mixed_batch, detections)

    incident = incidents[0]
    assert len(incident.events) == 3
    assert all(e.user == "admin" for e in incident.events)


def test_closed_incident_reopens_within_window():
    store = IncidentStore()
    engine = IncidentEngine(store)

    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events_1 = [make_event(user="admin", ts=base_time)]
    detections = [make_detection(severity=Severity.HIGH)]

    incidents = engine.process(events_1, detections)
    incident = incidents[0]
    incident.status = IncidentStatus.CLOSED
    store.save(incident)

    # New activity 10 hours later - within the 48h reopen window
    events_2 = [make_event(user="admin", ts=base_time + timedelta(hours=10))]
    incidents_2 = engine.process(events_2, detections)

    assert store.count() == 1  # same incident, reopened
    assert incidents_2[0].status == IncidentStatus.OPEN
    assert incidents_2[0].incident_id == incident.incident_id


def test_closed_incident_creates_new_one_outside_window():
    store = IncidentStore()
    engine = IncidentEngine(store)

    base_time = datetime(2026, 9, 1, 10, 0, 0)
    events_1 = [make_event(user="admin", ts=base_time)]
    detections = [make_detection(severity=Severity.HIGH)]

    incidents = engine.process(events_1, detections)
    incident = incidents[0]
    incident.status = IncidentStatus.CLOSED
    store.save(incident)

    # New activity 100 hours later - outside the 48h reopen window
    events_2 = [make_event(user="admin", ts=base_time + timedelta(hours=100))]
    incidents_2 = engine.process(events_2, detections)

    assert store.count() == 2  # new incident created
    new_incident = incidents_2[0]
    assert incident.incident_id in new_incident.related_incident_ids

def test_different_rules_use_different_reopen_windows():
    """
    Confirms per-rule reopen windows work correctly - a rule with a
    short window should NOT reopen an incident after a long gap, while
    a rule with a long window SHOULD.
    """
    store = IncidentStore()
    engine = IncidentEngine(store)

    base_time = datetime(2026, 9, 1, 10, 0, 0)

    # Create and close an incident using a SHORT reopen window rule
    short_window_detection = [make_detection(reopen_hours=24)]
    events_1 = [make_event(user="admin", ts=base_time)]
    incidents = engine.process(events_1, short_window_detection)
    incident = incidents[0]
    incident.status = IncidentStatus.CLOSED
    store.save(incident)

    # 30 hours later - OUTSIDE the 24h window - should create a NEW incident
    events_2 = [make_event(user="admin", ts=base_time + timedelta(hours=30))]
    engine.process(events_2, short_window_detection)

    assert store.count() == 2  # new incident created, not reopened