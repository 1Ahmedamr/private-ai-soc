# src/incidents/priority_mapper.py

from src.models.event_schema import Severity
from src.models.incident_schema import IncidentPriority


def map_severity_to_priority(severity: Severity, is_critical_asset: bool = False) -> IncidentPriority:
    """
    يحول الـseverity التقنية لـpriority تشغيلية.

    ليه فيه is_critical_asset منفصل عن الـseverity؟
    لأن نفس الـseverity (HIGH مثلًا) على Domain Controller أخطر بكتير
    من نفس الـseverity على جهاز موظف عادي في المحاسبة.
    ده تطبيق فعلي لمفهوم "Asset Importance" اللي ذكرته في الـroadmap
    بتاعك تحت مرحلة الـRisk Scoring.
    """

    mapping = {
        Severity.CRITICAL: IncidentPriority.P1_CRITICAL,
        Severity.HIGH: IncidentPriority.P2_HIGH,
        Severity.MEDIUM: IncidentPriority.P3_MEDIUM,
        Severity.LOW: IncidentPriority.P4_LOW,
        Severity.INFO: IncidentPriority.P4_LOW,
    }

    priority = mapping[severity]

    # لو الأصل حرج، نرفّع الـpriority درجة واحدة على الأقل
    if is_critical_asset:
        escalation_map = {
            IncidentPriority.P4_LOW: IncidentPriority.P3_MEDIUM,
            IncidentPriority.P3_MEDIUM: IncidentPriority.P2_HIGH,
            IncidentPriority.P2_HIGH: IncidentPriority.P1_CRITICAL,
            IncidentPriority.P1_CRITICAL: IncidentPriority.P1_CRITICAL,
        }
        priority = escalation_map[priority]

    return priority