# src/incidents/policy.py

from src.models.event_schema import Severity
from src.models.detection_schema import DetectionResult


# الـthreshold اللي اتفقنا عليه: أقل severity تفتح incident
MINIMUM_SEVERITY_FOR_INCIDENT = Severity.MEDIUM

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def should_open_incident(detection: DetectionResult) -> bool:
    """
    القرار اللي اتخدناه إمبارح، مطبّق هنا كـsingle source of truth.

    ليه دالة منفصلة بدل ما نحط الشرط جوه كل حتة تانية؟
    عشان لو بكرة قررنا نغيّر الـthreshold (من MEDIUM لـHIGH مثلًا)،
    نغيره في مكان واحد بس - مش نروح ندور في كل الملفات.
    ده مبدأ اسمه "Single Source of Truth".
    """
    return _SEVERITY_ORDER[detection.severity] >= _SEVERITY_ORDER[MINIMUM_SEVERITY_FOR_INCIDENT]