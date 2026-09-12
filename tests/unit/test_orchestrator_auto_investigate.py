# tests/unit/test_orchestrator_auto_investigate.py

from unittest.mock import patch
from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator


def make_brute_force_events():
    base_time = datetime(2026, 9, 10, 10, 0, 0)
    return [
        NormalizedEvent(
            timestamp=base_time, source=EventSource.WINDOWS, event_type=EventType.AUTHENTICATION,
            user="admin", event_id="4625", status="failure",
        )
        for _ in range(6)
    ]


@patch("src.pipeline.orchestrator.PipelineOrchestrator.investigate_incident")
def test_high_risk_incident_triggers_auto_investigation(mock_investigate):
    orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), AssetInventory())
    orchestrator.ingest(make_brute_force_events())

    assert mock_investigate.called


@patch("src.pipeline.orchestrator.PipelineOrchestrator.investigate_incident")
def test_low_risk_single_event_does_not_trigger_investigation(mock_investigate):
    """A single failed login (LOW severity) never even becomes an
    incident per Day 3's policy, so investigate_incident should never
    be called at all for this input."""
    orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), AssetInventory())
    single_event = [
        NormalizedEvent(
            timestamp=datetime.now(), source=EventSource.WINDOWS, event_type=EventType.AUTHENTICATION,
            user="john", event_id="4625", status="failure",
        )
    ]
    orchestrator.ingest(single_event)

    assert not mock_investigate.called