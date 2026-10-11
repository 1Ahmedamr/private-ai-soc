# tests/unit/test_postgres_incident_id_guard.py
"""Same collision guard as the SQLite store: never overwrite a different incident."""

from datetime import datetime

import pytest

from src.models.event_schema import Severity
from src.models.incident_schema import Incident, IncidentPriority
from src.storage.postgres_incident_store import PostgresIncidentStore

pytestmark = pytest.mark.postgres  # needs the docker compose postgres container


@pytest.fixture
def store():
    s = PostgresIncidentStore(dbname="private_ai_soc")
    with s.conn.cursor() as cur:
        cur.execute("DELETE FROM incidents")
    s.conn.commit()
    return s


def make_incident(key="user:admin"):
    return Incident(
        title="Test Incident", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key=key, first_seen=datetime.now(), last_seen=datetime.now(),
    )


def clash_with(original):
    clash = make_incident("ip:203.0.113.9")
    clash.incident_id = original.incident_id
    return clash


def test_same_id_for_a_different_identity_is_refused(store):
    original = make_incident("user:admin")
    store.save(original)
    with pytest.raises(RuntimeError, match=original.incident_id):
        store.save(clash_with(original))


def test_refused_save_leaves_the_original_untouched(store):
    original = make_incident("user:admin")
    store.save(original)
    try:
        store.save(clash_with(original))
    except RuntimeError:
        pass
    assert store.get_by_id(original.incident_id).correlation_key == "user:admin"
    assert store.count() == 1


def test_resaving_the_same_incident_still_updates_it(store):
    incident = make_incident()
    store.save(incident)
    incident.title = "Updated title"
    store.save(incident)
    assert store.count() == 1
    assert store.get_by_id(incident.incident_id).title == "Updated title"
