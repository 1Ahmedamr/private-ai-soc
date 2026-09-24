# tests/unit/test_sysmon_parser.py

from src.ingestion.sysmon_parser import parse_sysmon_event, parse_sysmon_events, _extract_hashes
from src.models.event_schema import EventType


PROCESS_CREATION = {
    "EventID": "1",
    "TimeCreated": "2026-09-25T10:00:00.000Z",
    "Computer": "WORKSTATION-01",
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "CommandLine": "powershell.exe -enc SQBuAHYAbwBrAGUA",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "cmd.exe /c powershell.exe -enc SQBuAHYAbwBrAGUA",
    "User": "CORP\\john.smith",
    "Hashes": "MD5=abc123,SHA256=def456abc789,IMPHASH=ghi789",
    "ProcessGuid": "{12345678-1234-1234-1234-123456789012}",
}

NETWORK_CONNECTION = {
    "EventID": "3",
    "TimeCreated": "2026-09-25T10:01:00.000Z",
    "Computer": "WORKSTATION-01",
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "SourceIp": "10.0.0.5",
    "DestinationIp": "185.220.101.5",
    "DestinationPort": "4444",
    "Protocol": "tcp",
    "Initiated": "true",
    "User": "CORP\\john.smith",
}

DNS_QUERY = {
    "EventID": "22",
    "TimeCreated": "2026-09-25T10:02:00.000Z",
    "Computer": "WORKSTATION-01",
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "QueryName": "a3f8k2p9m1q7.malware-c2.net",
}


def test_parse_process_creation():
    event = parse_sysmon_event(PROCESS_CREATION)
    assert event is not None
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.process == "C:\\Windows\\System32\\powershell.exe"
    assert event.parent_process == "C:\\Windows\\System32\\cmd.exe"
    assert event.user == "john.smith"
    assert event.file_hash == "def456abc789"
    assert event.event_id == "1"


def test_parse_network_connection():
    event = parse_sysmon_event(NETWORK_CONNECTION)
    assert event is not None
    assert event.event_type == EventType.NETWORK_CONNECTION
    assert event.src_ip == "10.0.0.5"
    assert event.dst_ip == "185.220.101.5"
    assert event.dst_port == 4444
    assert event.network_initiated is True


def test_parse_dns_query():
    event = parse_sysmon_event(DNS_QUERY)
    assert event is not None
    assert event.event_type == EventType.DNS_QUERY
    assert event.event_id == "a3f8k2p9m1q7.malware-c2.net"


def test_extract_hashes_prefers_sha256():
    result = _extract_hashes("MD5=abc,SHA256=def456,IMPHASH=ghi")
    assert result == "def456"


def test_extract_hashes_falls_back_to_md5():
    result = _extract_hashes("MD5=abc123,IMPHASH=ghi")
    assert result == "abc123"


def test_unknown_event_id_returns_none():
    event = parse_sysmon_event({"EventID": "99", "TimeCreated": "2026-09-25T10:00:00Z"})
    assert event is None


def test_batch_parse_filters_unknowns():
    events = parse_sysmon_events([PROCESS_CREATION, {"EventID": "99"}, NETWORK_CONNECTION])
    assert len(events) == 2
