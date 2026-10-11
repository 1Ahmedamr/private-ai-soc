# tests/unit/test_incident_id_guard.py
"""Saving must never silently overwrite a different incident that shares an ID."""

from datetime import datetime

import pytest

from src.incidents.store import IncidentStore
from src.models.event_schema import Severity
from src.models.incident_schema import Incident, IncidentPriority


def make_incident(key="user:admin"):
    return Incident(
        title="Test Incident",
        priority=IncidentPriority.P2_HIGH,
        severity=Severity.HIGH,
        correlation_key=key,
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )


def clash_with(original):
    clash = make_incident("ip:203.0.113.9")
    clash.incident_id = original.incident_id
    return clash


def test_same_id_for_a_different_identity_is_refused():
    store = IncidentStore(":memory:")
    original = make_incident("user:admin")
    store.save(original)
    with pytest.raises(RuntimeError, match=original.incident_id):
        store.save(clash_with(original))


def test_refused_save_leaves_the_original_untouched():
    store = IncidentStore(":memory:")
    original = make_incident("user:admin")
    store.save(original)
    try:
        store.save(clash_with(original))
    except RuntimeError:
        pass
    assert store.get_by_id(original.incident_id).correlation_key == "user:admin"
    assert store.count() == 1


def test_resaving_the_same_incident_still_updates_it():
    store = IncidentStore(":memory:")
    incident = make_incident()
    store.save(incident)
    incident.title = "Updated title"
    store.save(incident)
    assert store.count() == 1
    assert store.get_by_id(incident.incident_id).title == "Updated title"
