# tests/unit/test_brute_force_sliding_window.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.brute_force import detect_brute_force


def make_event(ts, user="admin"):
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user=user,
        event_id="4625",
        status="failure",
    )


def test_recent_burst_detected_despite_old_unrelated_history():
    """
    The exact regression the sliding-window fix addresses: a long history
    (old noise + a real recent burst) should still surface the burst.
    """
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    old_noise = [make_event(base_time + timedelta(days=i)) for i in range(3)]
    recent_burst = [make_event(base_time + timedelta(days=10, seconds=i * 20)) for i in range(6)]

    result = detect_brute_force(old_noise + recent_burst, threshold=5, window_minutes=5)
    assert result.triggered is True


def test_scattered_events_without_a_true_burst_do_not_trigger():
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    scattered = [make_event(base_time + timedelta(hours=i * 3)) for i in range(6)]

    result = detect_brute_force(scattered, threshold=5, window_minutes=5)
    assert result.triggered is False