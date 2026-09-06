# src/incidents/engine.py

from typing import List
from datetime import datetime

from src.models.event_schema import NormalizedEvent
from src.models.detection_schema import DetectionResult
from src.models.incident_schema import Incident, IncidentStatus
from src.incidents.policy import should_open_incident
from src.incidents.correlation_key import extract_correlation_key
from src.incidents.priority_mapper import map_severity_to_priority
from src.incidents.store import IncidentStore


class IncidentEngine:
    """
    المسؤول عن تحويل (events + detections) إلى Incidents فعلية،
    مع تطبيق الـdeduplication (منع تكرار نفس الـincident).
    """

    def __init__(self, store: IncidentStore):
        self.store = store

    def process(
        self,
        events: List[NormalizedEvent],
        detections: List[DetectionResult],
        is_critical_asset: bool = False,
    ) -> List[Incident]:
        """
        نقطة الدخول الرئيسية.

        الخطوات:
        1. فلترة الـdetections اللي تستاهل incident (باستخدام الـpolicy)
        2. لكل detection مؤهل، تحديد الـcorrelation_key
        3. لو فيه incident مفتوح بنفس الـkey → نضيف الـdetection ليه (تحديث)
        4. لو مفيش → نفتح incident جديد
        """
        resulting_incidents: List[Incident] = []

        qualifying_detections = [d for d in detections if should_open_incident(d)]

        if not qualifying_detections:
            return resulting_incidents

        correlation_key = extract_correlation_key(events)

        for detection in qualifying_detections:
            existing_incident = self.store.get_by_correlation_key(correlation_key)

            if existing_incident and existing_incident.status != IncidentStatus.CLOSED:
                # --- تحديث incident موجود (Deduplication) ---
                existing_incident.add_detection(detection)
                existing_incident.escalate_severity_if_needed(detection.severity)
                existing_incident.last_seen = max(existing_incident.last_seen, datetime.now())
                existing_incident.priority = map_severity_to_priority(
                    existing_incident.severity, is_critical_asset
                )
                self.store.save(existing_incident)
                resulting_incidents.append(existing_incident)
            else:
                # --- فتح incident جديد ---
                new_incident = Incident(
                    title=detection.rule_name,
                    priority=map_severity_to_priority(detection.severity, is_critical_asset),
                    severity=detection.severity,
                    correlation_key=correlation_key,
                    events=events,
                    detections=[detection],
                    mitre_techniques=[detection.mitre_technique] if detection.mitre_technique else [],
                    first_seen=events[0].timestamp if events else datetime.now(),
                    last_seen=events[-1].timestamp if events else datetime.now(),
                )
                self.store.save(new_incident)
                resulting_incidents.append(new_incident)

        return resulting_incidents