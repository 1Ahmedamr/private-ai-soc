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
from src.ai.evidence import build_evidence
from src.ai.ollama_client import investigate
from src.ai.policy import should_auto_investigate

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

        incidents = self.incident_engine.process(full_history, detections, is_critical_asset=is_critical)

        for incident in incidents:
            if should_auto_investigate(incident):
                self.investigate_incident(incident, self.incident_engine.store)

        return incidents
    def ingest_pcap(self, pcap_path: str, is_critical_asset: bool = False) -> list:
        """
        PCAP-specific ingestion: unlike single-source log files where all
        events share one identity, a PCAP contains traffic from MANY hosts.
        We must split events by (src_ip, dst_ip) identity groups and run
        detection on each group independently, otherwise the correlation
        key picks the first host and discards everyone else's traffic.
        """
        from src.pipeline.pcap_processor import process_pcap
        from src.incidents.correlation_key import extract_correlation_key

        all_events = process_pcap(pcap_path)
        if not all_events:
            return []

        # Group events by src_ip — each unique source is a separate
        # "actor" that needs independent detection
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for event in all_events:
            key = event.src_ip or event.host or "unknown"
            groups[key].append(event)

        print(f"[PCAP Orchestrator] Processing {len(all_events)} events "
              f"across {len(groups)} unique source IPs")

        all_incidents = []
        for src_ip, group_events in groups.items():
            if len(group_events) < 2:
                continue  # skip single-packet sources, not worth correlating

            detections = self.detection_engine.analyze(group_events)
            qualifying = [d for d in detections if d.triggered]
            if not qualifying:
                continue

            # Use the actual src_ip as correlation key directly
            from src.incidents.correlation_key import filter_events_by_correlation_key
            correlation_key = f"ip:{src_ip}"

            self.event_store.save_events(group_events)

            incidents = self.incident_engine.process(
                group_events, qualifying, is_critical_asset
            )
            all_incidents.extend(incidents)

        print(f"[PCAP Orchestrator] Created {len(all_incidents)} incident(s)")
        return all_incidents
    def _resolve_criticality(self, events: List[NormalizedEvent]) -> bool:
        for event in events:
            if self.asset_inventory.is_critical_or_important(event.host, event.dst_ip):
                return True
            if self.asset_inventory.is_critical_or_important(event.host, event.src_ip):
                return True
        return False
    def investigate_incident(self, incident, incident_store) -> None:
        """
        Optional enhancement step - call this separately from ingest(),
        not automatically inline. Detection/Incident/Risk must always be
        able to run completely on their own, per Day 3's architecture
        decision. This method is how an analyst (or a scheduled job)
        chooses to enrich an incident with AI reasoning, on demand.
        """
        evidence = build_evidence(incident)
        verdict = investigate(evidence)

        if verdict is None:
            return  # AI unavailable or failed - incident remains valid without it

        incident.ai_verdict = verdict.summary
        incident.recommended_actions = verdict.recommended_actions
        incident_store.save(incident)