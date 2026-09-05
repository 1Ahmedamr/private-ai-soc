# tests/unit/test_detection_engine.py

from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from src.detection.rules.failed_login import detect_failed_login
from src.detection.rules.brute_force import detect_brute_force
from src.detection.engine import DetectionEngine


def make_failed_login_event(user="admin", src_ip="10.0.0.5", ts=None):
    """Helper function - عشان مانكررش نفس الكود في كل test."""
    return NormalizedEvent(
        timestamp=ts or datetime.now(),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user=user,
        src_ip=src_ip,
        event_id="4625",
        status="failure",
    )


def test_single_failed_login_triggers():
    event = make_failed_login_event()
    result = detect_failed_login(event)
    assert result.triggered is True
    assert result.severity == Severity.LOW


def test_successful_login_does_not_trigger():
    event = make_failed_login_event()
    event.status = "success"
    result = detect_failed_login(event)
    assert result.triggered is False


def test_brute_force_triggers_with_enough_attempts():
    from datetime import timedelta
    base_time = datetime(2026, 9, 5, 10, 0, 0)
    events = [
        make_failed_login_event(ts=base_time + timedelta(seconds=i * 20))
        for i in range(6)
    ]
    result = detect_brute_force(events, threshold=5, window_minutes=5)
    assert result.triggered is True
    assert result.severity == Severity.HIGH


def test_brute_force_does_not_trigger_below_threshold():
    events = [make_failed_login_event() for _ in range(3)]
    result = detect_brute_force(events, threshold=5, window_minutes=5)
    assert result.triggered is False


def test_engine_combines_both_rules():
    from datetime import timedelta
    base_time = datetime(2026, 9, 5, 10, 0, 0)
    events = [
        make_failed_login_event(ts=base_time + timedelta(seconds=i * 20))
        for i in range(6)
    ]
    engine = DetectionEngine()
    results = engine.analyze(events)

    rule_names = [r.rule_name for r in results]
    assert "Single Failed Login Attempt" in rule_names
    assert "Brute Force Detection" in rule_names