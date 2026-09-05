# src/detection/rules/failed_login.py

from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult


def detect_failed_login(event: NormalizedEvent) -> DetectionResult:
    """
    Rule: Single Failed Authentication Attempt

    ليه القاعدة دي أول حاجة نبنيها؟
    لأنها أبسط حالة ممكنة: event واحد، شرط واحد.
    هنبني عليها بعدين قواعد أعقد (زي "47 failed logins في دقيقة").

    منطق القاعدة:
    - لو event_type = authentication
    - و status = failure
    → القاعدة تتفعّل بseverity منخفضة (لأن failed login واحد مش خطر لوحده)
    """

    if event.event_type == EventType.AUTHENTICATION and event.status == "failure":
        return DetectionResult(
            rule_name="Single Failed Login Attempt",
            rule_id="SOC-AUTH-001",
            triggered=True,
            severity=Severity.LOW,   # لسه مش خطر - event واحد بس
            mitre_technique="T1110",
            mitre_tactic="Credential Access",
            description=(
                f"Failed authentication attempt detected for user "
                f"'{event.user}' from source IP '{event.src_ip}'."
            ),
            confidence=1.0,  # القاعدة نفسها deterministic 100% - لو الشرط تحقق، متأكدين
        )

    # لو الشرط متحققش، نرجع نتيجة "مفيش تفعيل"
    return DetectionResult(
        rule_name="Single Failed Login Attempt",
        rule_id="SOC-AUTH-001",
        triggered=False,
        severity=Severity.INFO,
        description="No failed authentication pattern matched.",
        confidence=1.0,
    )