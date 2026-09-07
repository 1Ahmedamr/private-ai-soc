# tests/unit/test_incident_store_persistence.py

from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority
from src.models.event_schema import Severity
from src.incidents.store import IncidentStore


def make_incident():
    return Incident(
        title="Test Incident",
        priority=IncidentPriority.P2_HIGH,
        severity=Severity.HIGH,
        correlation_key="user:admin",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )


def test_incident_round_trips_through_sqlite():
    store = IncidentStore(":memory:")
    incident = make_incident()
    store.save(incident)

    retrieved = store.get_by_id(incident.incident_id)
    assert retrieved is not None
    assert retrieved.incident_id == incident.incident_id
    assert retrieved.severity == Severity.HIGH


def test_default_store_is_isolated_in_memory():
    """Each IncidentStore() with no path gets its own isolated db - critical for test independence."""
    store_a = IncidentStore()
    store_b = IncidentStore()
    store_a.save(make_incident())

    assert store_a.count() == 1
    assert store_b.count() == 0