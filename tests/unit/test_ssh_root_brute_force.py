# tests/unit/test_ssh_root_brute_force.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.ssh_root_brute_force import detect_ssh_root_brute_force


def make_ssh_event(user, ts, src_ip="45.33.12.99"):
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.LINUX,
        event_type=EventType.AUTHENTICATION,
        user=user,
        src_ip=src_ip,
        event_id="failed_password",
        status="failure",
    )


def test_root_brute_force_triggers():
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    events = [make_ssh_event("root", base_time + timedelta(seconds=i * 20)) for i in range(5)]
    result = detect_ssh_root_brute_force(events, threshold=4, window_minutes=5)
    assert result.triggered is True
    assert result.severity == "high"


def test_non_root_user_does_not_trigger_this_rule():
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    events = [make_ssh_event("john", base_time + timedelta(seconds=i * 20)) for i in range(5)]
    result = detect_ssh_root_brute_force(events, threshold=4, window_minutes=5)
    assert result.triggered is False


def test_below_threshold_does_not_trigger():
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    events = [make_ssh_event("root", base_time + timedelta(seconds=i * 20)) for i in range(2)]
    result = detect_ssh_root_brute_force(events, threshold=4, window_minutes=5)
    assert result.triggered is False


def test_windows_events_are_ignored_by_this_rule():
    """A Windows source event with user='root' should NOT trigger - this rule is Linux-source-specific."""
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 20),
            source=EventSource.WINDOWS,
            event_type=EventType.AUTHENTICATION,
            user="root",
            event_id="4625",
            status="failure",
        )
        for i in range(5)
    ]
    result = detect_ssh_root_brute_force(events, threshold=4, window_minutes=5)
    assert result.triggered is False