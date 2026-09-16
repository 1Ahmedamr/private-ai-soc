# src/detection/rules/suspicious_powershell.py

from typing import List
from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique

_SUSPICIOUS_FLAGS = ["-enc", "-encodedcommand", "-nop", "-noprofile", "-windowstyle hidden", "-exec bypass"]


def detect_suspicious_powershell(events: List[NormalizedEvent]) -> DetectionResult:
    for event in events:
        if event.event_type != EventType.PROCESS_EXECUTION:
            continue
        if event.process and "powershell" in event.process.lower():
            command_lower = (event.command or "").lower()
            matched_flags = [f for f in _SUSPICIOUS_FLAGS if f in command_lower]
            if matched_flags:
                technique = get_technique("T1059.001")
                return DetectionResult(
                    rule_name="Suspicious PowerShell Execution",
                    rule_id="SOC-PROC-001",
                    triggered=True,
                    severity=Severity.HIGH,
                    mitre_technique=technique.technique_id if technique else "T1059.001",
                    mitre_tactic=technique.tactic if technique else "Execution",
                    description=f"PowerShell launched with suspicious flags {matched_flags} by user '{event.user}' on host '{event.host}'.",
                    confidence=0.85,
                    reopen_window_hours=48,
                )

    return DetectionResult(
        rule_name="Suspicious PowerShell Execution", rule_id="SOC-PROC-001",
        triggered=False, severity=Severity.INFO, description="No suspicious PowerShell execution found.", confidence=1.0,
    )