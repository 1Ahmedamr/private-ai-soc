# src/detection/rules/windows_persistence.py

from typing import List

from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique
from src.detection.rules.suspicious_powershell import _SUSPICIOUS_FLAGS

# Folders any normal user can write to. Services and tasks running from
# here are a classic persistence pattern.
_USER_WRITABLE_MARKERS = [
    "\\users\\public\\",
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\perflogs\\",
]

_LOLBINS = ["mshta", "rundll32", "regsvr32", "wscript", "cscript", "certutil", "bitsadmin"]


def _norm(value) -> str:
    return (value or "").lower().replace("/", "\\")


def _writable_path(command: str) -> bool:
    return any(marker in command for marker in _USER_WRITABLE_MARKERS)


def _tech(technique_id: str, fallback_tactic: str):
    technique = get_technique(technique_id)
    if technique:
        return technique.technique_id, technique.tactic
    return technique_id, fallback_tactic


def detect_windows_persistence(events: List[NormalizedEvent]) -> List[DetectionResult]:
    """
    4698 (scheduled task created) and 7045 (service installed).
    Only alerts when the thing being installed looks suspicious, so normal
    software installs do not create noise.
    One result per event id (task / service) to avoid duplicate alerts.
    """
    results: List[DetectionResult] = []
    seen = set()

    for event in events:
        if event.event_type != EventType.PROCESS_EXECUTION:
            continue
        event_id = str(event.event_id)
        if event_id not in ("4698", "7045") or event_id in seen:
            continue

        command = _norm(event.command)
        name = event.process or "unknown"
        reasons = []

        flags = [f for f in _SUSPICIOUS_FLAGS if f in command]
        if "powershell" in command and flags:
            reasons.append(f"PowerShell with suspicious flags {flags}")
        if _writable_path(command):
            reasons.append("runs from a user-writable folder")
        lolbins = [b for b in _LOLBINS if b in command]
        if lolbins:
            reasons.append(f"uses living-off-the-land binary {lolbins}")

        if not reasons:
            continue

        seen.add(event_id)

        if event_id == "4698":
            technique_id, _ = _tech("T1053.005", "Persistence")
            tactic = "Persistence"  # the technique table lists several tactics; the evidence shows persistence
            rule_name = "Suspicious Scheduled Task Created"
            rule_id = "SOC-PERSIST-001"
            what = f"Scheduled task '{name}' was created"
            confidence = 0.9 if len(reasons) > 1 or "PowerShell" in reasons[0] else 0.8
        else:
            technique_id, _ = _tech("T1543.003", "Persistence")
            tactic = "Persistence"
            rule_name = "Suspicious Service Installed"
            rule_id = "SOC-PERSIST-002"
            what = f"Service '{name}' was installed"
            confidence = 0.85

        user_text = (
            f"user '{event.user}'" if event.user
            else "an unrecorded account (service installs usually run as SYSTEM)"
        )

        results.append(DetectionResult(
            rule_name=rule_name,
            rule_id=rule_id,
            triggered=True,
            severity=Severity.HIGH,
            mitre_technique=technique_id,
            mitre_tactic=tactic,
            description=(
                f"{what} on host '{event.host}' by {user_text}; "
                f"{'; '.join(reasons)}. Command: {event.command}"
            ),
            confidence=confidence,
            reopen_window_hours=48,
        ))

    return results