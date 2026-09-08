# src/pipeline/orchestrator.py

from datetime import timedelta
from typing import List
from src.models.event_schema import NormalizedEvent
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore
from src.storage.event_store import EventStore
from src.incidents.correlation_key import extract_correlation_key
from src.assets.inventory import AssetInventory

HISTORY_LOOKBACK_HOURS = 24 * 7


class PipelineOrchestrator:
    def __init__(
        self,
        event_store: EventStore,
        incident_store: IncidentStore,
        asset_inventory: AssetInventory,
    ):
        self.event_store = event_store
        self.detection_engine = DetectionEngine()
        self.incident_engine = IncidentEngine(incident_store)
        self.asset_inventory = asset_inventory

    def ingest(self, new_events: List[NormalizedEvent]):
        """
        Note: is_critical_asset is no longer a parameter here. It's now
        DERIVED automatically from the events themselves via the asset
        inventory - this is today's actual fix.
        """
        if not new_events:
            return []

        self.event_store.save_events(new_events)

        correlation_key = extract_correlation_key(new_events)

        latest_event_time = max(e.timestamp for e in new_events)
        since = latest_event_time - timedelta(hours=HISTORY_LOOKBACK_HOURS)
        full_history = self.event_store.get_events_by_correlation_key(correlation_key, since=since)

        detections = self.detection_engine.analyze(full_history)

        # Determine criticality from whatever host/ip appears in the
        # affected events - checking dst_ip too, since for network
        # events the DESTINATION being scanned/attacked matters more
        # than the source.
        is_critical = self._resolve_criticality(full_history)

        return self.incident_engine.process(full_history, detections, is_critical_asset=is_critical)

    def _resolve_criticality(self, events: List[NormalizedEvent]) -> bool:
        for event in events:
            if self.asset_inventory.is_critical_or_important(event.host, event.dst_ip):
                return True
            if self.asset_inventory.is_critical_or_important(event.host, event.src_ip):
                return True
        return False