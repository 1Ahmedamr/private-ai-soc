# tests/unit/test_postgres_stores.py
import pytest
from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.models.incident_schema import Incident, IncidentPriority, Severity
from src.storage.postgres_event_store import PostgresEventStore
from src.storage.postgres_incident_store import PostgresIncidentStore

pytestmark = pytest.mark.postgres  # marks these as requiring a live DB


@pytest.fixture
def event_store():
    store = PostgresEventStore(dbname="private_ai_soc")
    with store.conn.cursor() as cur:
        cur.execute("DELETE FROM events")
    store.conn.commit()
    return store


@pytest.fixture
def incident_store():
    store = PostgresIncidentStore(dbname="private_ai_soc")
    with store.conn.cursor() as cur:
        cur.execute("DELETE FROM incidents")
    store.conn.commit()
    return store


def test_save_and_retrieve_event(event_store):
    event = NormalizedEvent(
        timestamp=datetime.now(), source=EventSource.LINUX, event_type=EventType.AUTHENTICATION,
        user="root", event_id="failed_password", status="failure",
    )
    event_store.save_events([event])
    results = event_store.get_events_by_correlation_key("user:root")
    assert len(results) == 1


def test_incident_round_trip(incident_store):
    incident = Incident(
        title="Test", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key="user:root", first_seen=datetime.now(), last_seen=datetime.now(),
    )
    incident_store.save(incident)
    assert incident_store.get_by_id(incident.incident_id) is not None