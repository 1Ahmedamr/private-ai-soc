# src/pipeline/orchestrator.py

from datetime import timedelta
from typing import List
from src.models.event_schema import NormalizedEvent
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore
from src.storage.event_store import EventStore
from src.incidents.correlation_key import extract_correlation_key


# 7 days is generous, and safe now: our sliding-window fixes mean a long
# history no longer breaks brute-force or fast-scan detection accuracy.
HISTORY_LOOKBACK_HOURS = 24 * 7


class PipelineOrchestrator:
    """
    Ties persistent storage + detection + incident management together.
    This is what makes detection possible ACROSS separate ingestion runs,
    not just within one in-memory batch.
    """

    def __init__(self, event_store: EventStore, incident_store: IncidentStore):
        self.event_store = event_store
        self.detection_engine = DetectionEngine()
        self.incident_engine = IncidentEngine(incident_store)

    def ingest(self, new_events: List[NormalizedEvent], is_critical_asset: bool = False):
        if not new_events:
            return []

        # Step 1: persist immediately - this is what survives process restarts
        self.event_store.save_events(new_events)

        # Step 2: identify who these new events belong to
        correlation_key = extract_correlation_key(new_events)

        # Step 3: pull the FULL relevant history for that identity - not
        # just what arrived just now. We anchor the lookback to the
        # latest new event's own timestamp (not datetime.now()) so this
        # works correctly with historical/simulated data, not just live traffic.
        latest_event_time = max(e.timestamp for e in new_events)
        since = latest_event_time - timedelta(hours=HISTORY_LOOKBACK_HOURS)
        full_history = self.event_store.get_events_by_correlation_key(correlation_key, since=since)

        # Step 4: run detection on the FULL history
        detections = self.detection_engine.analyze(full_history)

        # Step 5: correlate into incidents as usual
        return self.incident_engine.process(full_history, detections, is_critical_asset)