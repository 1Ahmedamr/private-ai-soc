# src/detection/rules/suricata_signature_match.py

from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from src.models.detection_schema import DetectionResult


def detect_suricata_alerts(events: List[NormalizedEvent]) -> DetectionResult:
    """
    Unlike our other rules, this doesn't invent a threshold - a SINGLE
    Suricata alert already represents a signature match against known
    malicious traffic patterns (Suricata's own job). Our role here is
    just to surface it into the same Incident/Risk/AI pipeline as
    everything else, not to second-guess Suricata's detection logic.
    """
    suricata_events = [e for e in events if e.source == EventSource.SURICATA and e.event_type == EventType.ALERT]

    if not suricata_events:
        return DetectionResult(
            rule_name="Suricata Signature Match", rule_id="SOC-IDS-001",
            triggered=False, severity=Severity.INFO,
            description="No Suricata alerts found.", confidence=1.0,
        )

    highest_severity = max((e.severity for e in suricata_events), key=lambda s: ["info","low","medium","high","critical"].index(s))
    signature = suricata_events[0].event_id

    return DetectionResult(
        rule_name="Suricata Signature Match", rule_id="SOC-IDS-001",
        triggered=True, severity=highest_severity,
        description=f"Suricata matched signature '{signature}' ({len(suricata_events)} occurrence(s)).",
        confidence=0.9, reopen_window_hours=48,
    )