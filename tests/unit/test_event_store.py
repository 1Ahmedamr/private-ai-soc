# tests/unit/test_event_store.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.storage.event_store import EventStore


def make_event(user, ts):
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user=user,
        event_id="4625",
        status="failure",
    )


def test_save_and_retrieve_events_by_user():
    store = EventStore(":memory:")
    base_time = datetime(2026, 9, 1, 10, 0, 0)
    store.save_events([make_event("admin", base_time)])

    results = store.get_events_by_correlation_key("user:admin")
    assert len(results) == 1
    assert results[0].user == "admin"


def test_since_filter_excludes_old_events():
    store = EventStore(":memory:")
    base_time = datetime(2026, 9, 1, 10, 0, 0)

    store.save_events([make_event("admin", base_time)])
    store.save_events([make_event("admin", base_time + timedelta(days=10))])

    recent_only = store.get_events_by_correlation_key(
        "user:admin", since=base_time + timedelta(days=5)
    )
    assert len(recent_only) == 1


def test_unknown_correlation_key_returns_empty():
    store = EventStore(":memory:")
    results = store.get_events_by_correlation_key("user:nonexistent")
    assert results == []