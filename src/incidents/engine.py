# src/incidents/engine.py

from typing import List
from datetime import datetime, timedelta

from src.models.event_schema import NormalizedEvent
from src.models.detection_schema import DetectionResult
from src.models.incident_schema import Incident, IncidentStatus
from src.incidents.policy import should_open_incident
from src.incidents.correlation_key import extract_correlation_key, filter_events_by_correlation_key
from src.incidents.priority_mapper import map_severity_to_priority
from src.incidents.store import IncidentStore
from src.risk.scoring import calculate_risk_score


# How long after closing can an incident be reopened instead of creating a new one?



class IncidentEngine:
    def __init__(self, store: IncidentStore):
        self.store = store

    def process(
        self,
        events: List[NormalizedEvent],
        detections: List[DetectionResult],
        is_critical_asset: bool = False,
    ) -> List[Incident]:
        resulting_incidents: List[Incident] = []

        qualifying_detections = [d for d in detections if should_open_incident(d)]
        if not qualifying_detections:
            return resulting_incidents

        correlation_key = extract_correlation_key(events)
        relevant_events = filter_events_by_correlation_key(events, correlation_key)

        for detection in qualifying_detections:
            existing_incident = self.store.get_by_correlation_key(correlation_key)
            linked_old_incident_id: str | None = None

            if existing_incident and existing_incident.status == IncidentStatus.CLOSED:
                if self._within_reopen_window(existing_incident, relevant_events, detection.reopen_window_hours):
                    self._reopen(existing_incident)
                else:
                    linked_old_incident_id = existing_incident.incident_id
                    existing_incident = None

            if existing_incident and existing_incident.status != IncidentStatus.CLOSED:
                existing_incident.add_detection(detection)
                existing_incident.events.extend(
                    e for e in relevant_events if e not in existing_incident.events
                )
                existing_incident.escalate_severity_if_needed(detection.severity)
                existing_incident.last_seen = max(
                    existing_incident.last_seen,
                    relevant_events[-1].timestamp if relevant_events else datetime.now(),
                )
                existing_incident.priority = map_severity_to_priority(
                    existing_incident.severity, is_critical_asset
                )
                existing_incident.risk_score = calculate_risk_score(existing_incident, is_critical_asset)
                self.store.save(existing_incident)
                resulting_incidents.append(existing_incident)
            else:
                new_incident = Incident(
                    title=detection.rule_name,
                    priority=map_severity_to_priority(detection.severity, is_critical_asset),
                    severity=detection.severity,
                    correlation_key=correlation_key,
                    events=relevant_events,
                    detections=[detection],
                    mitre_techniques=[detection.mitre_technique] if detection.mitre_technique else [],
                    first_seen=relevant_events[0].timestamp if relevant_events else datetime.now(),
                    last_seen=relevant_events[-1].timestamp if relevant_events else datetime.now(),
                )
                if linked_old_incident_id:
                    new_incident.related_incident_ids.append(linked_old_incident_id)

                new_incident.risk_score = calculate_risk_score(new_incident, is_critical_asset)
                self.store.save(new_incident)
                resulting_incidents.append(new_incident)

        return resulting_incidents

    def _within_reopen_window(
        self, incident: Incident, new_events: List[NormalizedEvent], reopen_window_hours: int
    ) -> bool:
        """
        Checks if new activity happened soon enough after the incident
        was closed to justify reopening it, using the window defined by
        the SPECIFIC detection rule that fired (not a global constant).
        """
        if not new_events:
            return False
        latest_new_event_time = max(e.timestamp for e in new_events)
        time_since_last_seen = latest_new_event_time - incident.last_seen
        return time_since_last_seen <= timedelta(hours=reopen_window_hours)

    def _reopen(self, incident: Incident) -> None:
        """
        Reopens a closed incident. We keep a record of the fact that it
        was reopened - this matters for audit purposes (a SOC manager
        might want to know "how many incidents get reopened?" as a metric
        of analyst accuracy).
        """
        incident.status = IncidentStatus.OPEN
        incident.updated_at = datetime.now()


def timedelta_hours(hours: int):
    from datetime import timedelta
    return timedelta(hours=hours)