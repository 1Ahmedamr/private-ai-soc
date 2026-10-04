# tests/unit/test_windows_persistence.py

from src.detection.rules.windows_persistence import detect_windows_persistence
from src.ingestion.windows_parser import parse_windows_events

BASE = {"timestamp": "2026-10-02T10:17:22Z", "computer": "WIN10-CLIENT", "user": "administrator"}


def _run(*raws):
    return detect_windows_persistence(parse_windows_events(list(raws)))


def test_encoded_powershell_task_is_detected():
    results = _run({**BASE, "event_id": 4698, "task_name": "\\WindowsUpdateCheck",
                    "action": "powershell.exe -EncodedCommand SQBFAFgA"})
    assert len(results) == 1
    assert results[0].mitre_technique == "T1053.005"


def test_service_from_user_writable_path_is_detected():
    results = _run({**BASE, "event_id": 7045, "service_name": "UpdaterSvc",
                    "service_path": "C:\\Users\\Public\\updater.exe"})
    assert len(results) == 1
    assert results[0].mitre_technique == "T1543.003"


def test_normal_service_is_not_detected():
    results = _run({**BASE, "event_id": 7045, "service_name": "Spooler",
                    "service_path": "C:\\Windows\\System32\\spoolsv.exe"})
    assert results == []


def test_normal_task_is_not_detected():
    results = _run({**BASE, "event_id": 4698, "task_name": "\\Backup",
                    "action": "C:\\Program Files\\Backup\\backup.exe"})
    assert results == []



def test_process_event_keeps_its_parent_process():
    events = parse_windows_events([{**BASE, "event_id": 4688, "process_name": "powershell.exe",
                                    "parent_process": "cmd.exe", "command_line": "powershell.exe -enc SQBFAFgA"}])
    assert events[0].parent_process == "cmd.exe"