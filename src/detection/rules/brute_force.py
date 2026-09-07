# src/detection/rules/brute_force.py

from datetime import timedelta
from typing import List, Optional
from collections import deque
from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique


def _find_burst_window(
    events_sorted: List[NormalizedEvent], threshold: int, window: timedelta
) -> Optional[List[NormalizedEvent]]:
    """
    Sliding-window scan: finds the first stretch of at least `threshold`
    events that all fall within `window` of each other, no matter where
    in a longer history that stretch occurs.

    Why not just check the group's overall first-to-last span?
    Because once we feed this rule a multi-day history (from the new
    persistent Event Store), a group might contain old, unrelated noise
    AND a real recent burst mixed together. Checking only the overall
    span would let a tight, real burst get diluted by unrelated old
    events sitting at the edges of the list.
    """
    window_queue: deque = deque()

    for event in events_sorted:
        window_queue.append(event)
        while window_queue[0].timestamp < event.timestamp - window:
            window_queue.popleft()
        if len(window_queue) >= threshold:
            return list(window_queue)

    return None


def detect_brute_force(
    events: List[NormalizedEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> DetectionResult:
    """Rule: Brute Force Login Attempt (sliding-window version)."""

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

    def get_identity_key(event: NormalizedEvent) -> str:
        return event.user or event.src_ip or "unknown"

    failed_logins.sort(key=lambda e: e.timestamp)
    grouped: dict[str, list[NormalizedEvent]] = {}
    for event in failed_logins:
        key = get_identity_key(event)
        grouped.setdefault(key, []).append(event)

    window = timedelta(minutes=window_minutes)

    for identity, group_events in grouped.items():
        burst = _find_burst_window(group_events, threshold, window)
        if burst:
            technique = get_technique("T1110")
            return DetectionResult(
                rule_name="Brute Force Detection",
                rule_id="SOC-AUTH-002",
                triggered=True,
                severity=Severity.HIGH,
                mitre_technique=technique.technique_id if technique else "T1110",
                mitre_tactic=technique.tactic if technique else "Credential Access",
                description=(
                    f"Brute force pattern detected: {len(burst)} failed login "
                    f"attempts for identity '{identity}' within a "
                    f"{window_minutes}-minute window."
                ),
                confidence=0.95,
                reopen_window_hours=48,
            )

    return DetectionResult(
        rule_name="Brute Force Detection",
        rule_id="SOC-AUTH-002",
        triggered=False,
        severity=Severity.INFO,
        description="Failed attempts found but not within the required time window.",
        confidence=1.0,
    )