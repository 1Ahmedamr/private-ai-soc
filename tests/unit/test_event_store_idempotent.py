# tests/unit/test_event_store_idempotent.py
"""Saving events is idempotent: replaying a file adds nothing, but a real burst of
identical events inside one file is never collapsed."""

from datetime import datetime, timedelta

from src.models.event_schema import EventSource, EventType, NormalizedEvent
from src.storage.event_store import EventStore

T0 = datetime(2026, 10, 6, 10, 0, 0)


def make_event(i=0, **record):
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=i), source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION, host="WS01", user="admin",
        src_ip="203.0.113.9", event_id="4625", status="failure", raw_data=record,
    )


def stored(store):
    return len(store.get_events_by_correlation_key("user:admin"))


def test_saving_the_same_batch_twice_stores_it_once():
    store = EventStore(":memory:")
    for _ in range(2):
        store.save_events([make_event(i) for i in range(8)])
    assert stored(store) == 8


def test_overlapping_batch_adds_only_the_new_events():
    store = EventStore(":memory:")
    store.save_events([make_event(i) for i in range(5)])
    store.save_events([make_event(i) for i in range(8)])
    assert stored(store) == 8


def test_identical_events_inside_one_batch_are_all_kept():
    store = EventStore(":memory:")
    store.save_events([make_event(0) for _ in range(50)])
    assert stored(store) == 50


def test_replaying_a_burst_of_identical_events_adds_nothing():
    store = EventStore(":memory:")
    for _ in range(2):
        store.save_events([make_event(0) for _ in range(50)])
    assert stored(store) == 50


def test_a_larger_identical_burst_adds_only_the_surplus():
    store = EventStore(":memory:")
    store.save_events([make_event(0) for _ in range(3)])
    store.save_events([make_event(0) for _ in range(5)])
    assert stored(store) == 5


def test_events_that_differ_only_in_the_original_record_are_both_kept():
    store = EventStore(":memory:")
    for _ in range(2):
        store.save_events([make_event(0, record=1), make_event(0, record=2)])
    assert stored(store) == 2
