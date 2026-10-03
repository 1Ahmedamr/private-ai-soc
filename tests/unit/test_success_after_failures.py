# tests/unit/test_success_after_failures.py

from datetime import datetime, timedelta

from src.detection.rules.success_after_failures import detect_success_after_failures
from src.models.event_schema import EventSource, EventType, NormalizedEvent

START = datetime(2026, 10, 2, 10, 15, 0)


def _auth(offset_seconds, status, user="administrator", ip="185.220.101.45", host="WIN10-CLIENT"):
    return NormalizedEvent(
        timestamp=START + timedelta(seconds=offset_seconds),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user=user, src_ip=ip, host=host, status=status,
    )


def test_success_after_enough_failures_triggers():
    events = [_auth(i * 4, "failure") for i in range(8)] + [_auth(120, "success")]
    result = detect_success_after_failures(events)
    assert result.triggered and result.mitre_technique == "T1078"
    assert "user 'administrator'" in result.description and "host 'WIN10-CLIENT'" in result.description
    assert "185.220.101.45" in result.description and "8 failed" in result.description
    assert "same source IP" in result.description


def test_success_after_few_failures_does_not_trigger():
    events = [_auth(i * 4, "failure") for i in range(3)] + [_auth(60, "success")]
    assert not detect_success_after_failures(events).triggered


def test_failures_after_the_success_do_not_count():
    events = [_auth(0, "success")] + [_auth(10 + i * 4, "failure") for i in range(8)]
    assert not detect_success_after_failures(events).triggered


def test_old_failures_outside_the_lookback_do_not_count():
    events = [_auth(i * 4, "failure") for i in range(8)] + [_auth(3600, "success")]
    assert not detect_success_after_failures(events).triggered


def test_failures_for_a_different_user_do_not_count():
    events = [_auth(i * 4, "failure", user="bob") for i in range(8)] + [_auth(60, "success")]
    assert not detect_success_after_failures(events).triggered