# src/detection/rules/suricata_signature_match.py

from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from src.models.detection_schema import DetectionResult


# Maps Suricata signature keywords to MITRE ATT&CK techniques
# Based on ET ruleset category conventions
_SIGNATURE_MITRE_MAP = [
    ("BackConnect",        "T1071", "Command and Control"),
    ("CnC",                "T1071", "Command and Control"),
    ("C2",                 "T1071", "Command and Control"),
    ("Beacon",             "T1071", "Command and Control"),
    ("Cobalt Strike",      "T1071.001", "Command and Control"),
    ("Meterpreter",        "T1071", "Command and Control"),
    ("PE EXE or DLL",      "T1105", "Command and Control"),
    ("file download",      "T1105", "Command and Control"),
    ("VNC",                "T1021.005", "Lateral Movement"),
    ("RDP",                "T1021.001", "Lateral Movement"),
    ("SMB",                "T1021.002", "Lateral Movement"),
    ("DNS Query",          "T1071.004", "Command and Control"),
    ("Phishing",           "T1566", "Initial Access"),
    ("SQL",                "T1190", "Initial Access"),
    ("Port Scan",          "T1046", "Discovery"),
    ("Scan",               "T1046", "Discovery"),
    ("Mimikatz",           "T1003", "Credential Access"),
    ("Pass-the-Hash",      "T1550.002", "Lateral Movement"),
    ("Brute Force",        "T1110", "Credential Access"),
    ("PowerShell",         "T1059.001", "Execution"),
]


def _get_mitre_for_signature(signature: str):
    """
    Maps a Suricata signature name to a MITRE technique.
    Uses keyword matching — imperfect but far better than 'None mapped'.
    Returns (technique_id, tactic) or (None, None) if no match.
    """
    sig_lower = signature.lower()
    for keyword, technique, tactic in _SIGNATURE_MITRE_MAP:
        if keyword.lower() in sig_lower:
            return technique, tactic
    return None, None


def detect_suricata_alerts(events: List[NormalizedEvent]) -> DetectionResult:
    suricata_events = [
        e for e in events
        if e.source == EventSource.SURICATA and e.event_type == EventType.ALERT
    ]

    if not suricata_events:
        return DetectionResult(
            rule_name="Suricata Signature Match", rule_id="SOC-IDS-001",
            triggered=False, severity=Severity.INFO,
            description="No Suricata alerts found.", confidence=1.0,
        )

    severity_order = ["info", "low", "medium", "high", "critical"]
    highest_severity = max(
        (e.severity for e in suricata_events),
        key=lambda s: severity_order.index(s) if s in severity_order else 0,
    )
    signature = suricata_events[0].event_id
    mitre_technique, mitre_tactic = _get_mitre_for_signature(signature)

    return DetectionResult(
        rule_name="Suricata Signature Match",
        rule_id="SOC-IDS-001",
        triggered=True,
        severity=highest_severity,
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        description=f"Suricata matched signature '{signature}' ({len(suricata_events)} occurrence(s)).",
        confidence=0.9,
        reopen_window_hours=48,
    )
