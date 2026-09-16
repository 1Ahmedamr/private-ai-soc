# tests/unit/test_suspicious_powershell.py

from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.suspicious_powershell import detect_suspicious_powershell


def make_process_event(process, command, user="admin", host="WIN-01"):
    return NormalizedEvent(
        timestamp=datetime.now(), source=EventSource.WINDOWS,
        event_type=EventType.PROCESS_EXECUTION, user=user, host=host,
        process=process, command=command,
    )


def test_encoded_powershell_triggers():
    events = [make_process_event("powershell.exe", "powershell -enc SQBuAHYAbwBrAGUA")]
    result = detect_suspicious_powershell(events)
    assert result.triggered is True
    assert result.mitre_technique == "T1059.001"


def test_noprofile_bypass_triggers():
    events = [make_process_event("powershell.exe", "powershell -noprofile -exec bypass -windowstyle hidden")]
    result = detect_suspicious_powershell(events)
    assert result.triggered is True


def test_normal_powershell_does_not_trigger():
    events = [make_process_event("powershell.exe", "powershell Get-ChildItem")]
    result = detect_suspicious_powershell(events)
    assert result.triggered is False


def test_non_powershell_process_ignored():
    events = [make_process_event("cmd.exe", "cmd /c -enc something")]
    result = detect_suspicious_powershell(events)
    assert result.triggered is False


def test_non_process_execution_events_ignored():
    event = NormalizedEvent(
        timestamp=datetime.now(), source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION, user="admin", event_id="4625", status="failure",
    )
    result = detect_suspicious_powershell([event])
    assert result.triggered is False
