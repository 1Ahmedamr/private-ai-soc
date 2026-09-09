# src/detection/rules/ssh_root_brute_force.py

from datetime import timedelta
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique


def detect_ssh_root_brute_force(
    events: List[NormalizedEvent],
    threshold: int = 4,
    window_minutes: int = 5,
) -> DetectionResult:
    """
    Rule: SSH Brute Force Targeting Root

    Why a SEPARATE rule from the generic detect_brute_force, instead of
    just letting the generic rule handle this too?
    Targeting 'root' specifically is a stronger, more specific signal
    than brute-forcing a random named account - attackers universally
    try root first because it's guaranteed to exist on most Linux boxes
    and has full privileges. This deserves a LOWER threshold (4, not 5)
    and HIGHER confidence than the generic rule, precisely because the
    target itself is inherently suspicious regardless of volume.
    """
    root_attempts = [
        e for e in events
        if e.source == EventSource.LINUX
        and e.event_type == EventType.AUTHENTICATION
        and e.status == "failure"
        and e.user == "root"
    ]

    if len(root_attempts) < threshold:
        return DetectionResult(
            rule_name="SSH Root Brute Force",
            rule_id="SOC-AUTH-003",
            triggered=False,
            severity=Severity.INFO,
            description=f"Only {len(root_attempts)} root SSH failures found; below threshold ({threshold}).",
            confidence=1.0,
        )

    root_attempts.sort(key=lambda e: e.timestamp)
    window = timedelta(minutes=window_minutes)

    # Same sliding-window logic pattern as brute_force.py - reused
    # deliberately for consistency, not copy-pasted blindly.
    left = 0
    for right in range(len(root_attempts)):
        while root_attempts[right].timestamp - root_attempts[left].timestamp > window:
            left += 1
        if (right - left + 1) >= threshold:
            technique = get_technique("T1110")
            span = root_attempts[right].timestamp - root_attempts[left].timestamp
            return DetectionResult(
                rule_name="SSH Root Brute Force",
                rule_id="SOC-AUTH-003",
                triggered=True,
                severity=Severity.HIGH,
                mitre_technique=technique.technique_id if technique else "T1110",
                mitre_tactic=technique.tactic if technique else "Credential Access",
                description=(
                    f"SSH brute force against 'root' detected: "
                    f"{right - left + 1} failed attempts from "
                    f"'{root_attempts[left].src_ip}' within {span.total_seconds():.0f} seconds."
                ),
                confidence=0.97,  # slightly higher than generic brute force - root targeting is rarely benign
                reopen_window_hours=48,
            )

    return DetectionResult(
        rule_name="SSH Root Brute Force",
        rule_id="SOC-AUTH-003",
        triggered=False,
        severity=Severity.INFO,
        description="Root SSH failures found but not within the required time window.",
        confidence=1.0,
    )