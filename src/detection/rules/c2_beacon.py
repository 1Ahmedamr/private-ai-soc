# src/detection/rules/c2_beacon.py

"""
PLACEHOLDER RULE - not yet wired into the Detection Engine.

This exists purely to validate our reopen-window design against a
contrasting real-world case: C2 (Command & Control) beaconing behavior
often has long, irregular retry cycles (sometimes days-to-weeks), unlike
brute force which retries quickly. We'll implement the actual detection
logic once network/DNS event parsing (Zeek) is built (Phase 5 of the roadmap).
"""

from src.models.detection_schema import DetectionResult
from src.models.event_schema import Severity
from src.mitre.techniques import get_technique


def detect_c2_beacon_placeholder() -> DetectionResult:
    """
    Placeholder showing intended configuration for a future C2 detection rule.
    Notice reopen_window_hours=336 (14 days) vs brute force's 48 hours -
    this is the direct implementation of yesterday's decision.
    """
    return DetectionResult(
        rule_name="C2 Beacon Pattern (Placeholder)",
        rule_id="SOC-NET-001",
        triggered=False,  # always false - not real yet
        severity=Severity.CRITICAL,
        description="Placeholder rule - not yet implemented.",
        confidence=0.0,
        reopen_window_hours=336,  # 14 days - C2 malware often has long sleep/retry cycles
    )