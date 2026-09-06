# src/detection/rules/brute_force.py

from datetime import timedelta
from typing import List
from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique


def detect_brute_force(
    events: List[NormalizedEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> DetectionResult:
    """
    Rule: Brute Force Login Attempt

    ليه القاعدة دي محتاجة List[NormalizedEvent] مش event واحد؟
    لأن brute force بطبيعته مش حدث واحد - هو *نمط* (pattern) عبر events متعددة
    خلال فترة زمنية معينة. مفيش طريقة تكتشفه من event واحد لوحده.

    منطق القاعدة:
    1. فلترة الـevents اللي هي failed logins بس
    2. تجميعهم حسب user (أو src_ip لو الـuser مش متاح - نفس منطق fallback
       اللي اتفقنا عليه في الـnormalization)
    3. لو عدد المحاولات لنفس الـuser/IP خلال `window_minutes` أكبر من أو
       يساوي `threshold` → القاعدة تتفعّل بseverity عالية
    """

    # الخطوة 1: فلترة الـfailed logins فقط
    failed_logins = [
        e for e in events
        if e.event_type == EventType.AUTHENTICATION and e.status == "failure"
    ]

    if len(failed_logins) < threshold:
        return DetectionResult(
            rule_name="Brute Force Detection",
            rule_id="SOC-AUTH-002",
            triggered=False,
            severity=Severity.INFO,
            description=f"Only {len(failed_logins)} failed attempts found; below threshold ({threshold}).",
            confidence=1.0,
        )

    # الخطوة 2: تحديد identity key - fallback logic
    # ده تطبيق عملي لقرارنا إمبارح: لو user مفقود، استخدم src_ip بدل ما نرفض الـevent
    def get_identity_key(event: NormalizedEvent) -> str:
        return event.user or event.src_ip or "unknown"

    # الخطوة 3: تجميع حسب identity + التأكد إنهم في نفس الـtime window
    failed_logins.sort(key=lambda e: e.timestamp)

    grouped: dict[str, list[NormalizedEvent]] = {}
    for event in failed_logins:
        key = get_identity_key(event)
        grouped.setdefault(key, []).append(event)

    # الخطوة 4: فحص كل مجموعة - هل عدد المحاولات ضمن الـwindow يتخطى الـthreshold
    for identity, group_events in grouped.items():
        if len(group_events) < threshold:
            continue

        first_time = group_events[0].timestamp
        last_time = group_events[-1].timestamp
        duration = last_time - first_time

        if duration <= timedelta(minutes=window_minutes):
            return DetectionResult(
                rule_name="Brute Force Detection",
                rule_id="SOC-AUTH-002",
                triggered=True,
                severity=Severity.HIGH,
                mitre_technique=get_technique("T1110").technique_id,
                mitre_tactic=get_technique("T1110").tactic,
                description=(
                    f"Brute force pattern detected: {len(group_events)} failed login "
                    f"attempts for identity '{identity}' within "
                    f"{duration.total_seconds() / 60:.1f} minutes."
                ),
                confidence=0.95,
                reopen_window_hours=48,  # brute force attempts typically retry within hours-to-days
            )

    return DetectionResult(
        rule_name="Brute Force Detection",
        rule_id="SOC-AUTH-002",
        triggered=False,
        severity=Severity.INFO,
        description="Failed attempts found but not within the required time window.",
        confidence=1.0,
    )