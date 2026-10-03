# src/detection/rules/success_after_failures.py

from bisect import bisect_left
from datetime import timedelta
from typing import List

from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique

FAILURE_THRESHOLD = 5                  # same threshold as the brute-force rule
LOOKBACK = timedelta(minutes=30)       # how far back failures still count


def detect_success_after_failures(
    events: List[NormalizedEvent],
    threshold: int = FAILURE_THRESHOLD,
    lookback: timedelta = LOOKBACK,
) -> DetectionResult:
    """
    Rule: Successful Logon After Repeated Failures

    A successful logon for the same account shortly after many failed attempts is the
    point where a brute-force attempt may have worked. Only failures BEFORE the success
    count. Alerts once, for the first success that qualifies.
    """
    auth = sorted(
        (e for e in events if e.event_type == EventType.AUTHENTICATION and e.user),
        key=lambda e: e.timestamp,
    )
    failures_by_user: dict = {}
    for event in auth:
        if event.status == "failure":
            failures_by_user.setdefault(event.user, []).append(event)
    failure_times = {user: [f.timestamp for f in group] for user, group in failures_by_user.items()}

    for event in auth:
        if event.status != "success" or event.user not in failures_by_user:
            continue
        times = failure_times[event.user]
        first = bisect_left(times, event.timestamp - lookback)
        last = bisect_left(times, event.timestamp)          # failures strictly before the success
        recent = failures_by_user[event.user][first:last]
        if len(recent) < threshold:
            continue

        same_source = bool(event.src_ip) and event.src_ip in {f.src_ip for f in recent}
        details = [f"user '{event.user}'"]
        if event.host:
            details.append(f"host '{event.host}'")
        if event.src_ip:
            details.append(f"source IP {event.src_ip}")

        technique = get_technique("T1078")
        minutes = int(lookback.total_seconds() // 60)
        return DetectionResult(
            rule_name="Successful Logon After Repeated Failures",
            rule_id="SOC-AUTH-010",
            triggered=True,
            severity=Severity.HIGH,
            mitre_technique=technique.technique_id if technique else "T1078",
            mitre_tactic="Initial Access",
            description=(
                f"Successful logon ({', '.join(details)}) at {event.timestamp.isoformat()} followed "
                f"{len(recent)} failed attempts in the preceding {minutes} minutes"
                f"{' from the same source IP' if same_source else ''}."
            ),
            confidence=0.9,
            reopen_window_hours=48,
        )

    return DetectionResult(
        rule_name="Successful Logon After Repeated Failures",
        rule_id="SOC-AUTH-010",
        triggered=False,
        severity=Severity.INFO,
        description="No successful logon preceded by repeated failures.",
        confidence=1.0,
    )