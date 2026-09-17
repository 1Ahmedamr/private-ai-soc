# tests/unit/test_format_detector.py

import json
import tempfile
import os
from src.ingestion.format_detector import detect_format


def write_temp(content, suffix=".json"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def test_detects_windows_json():
    content = json.dumps([{"event_id": 4625, "username": "admin", "timestamp": "2026-09-01T10:00:00"}])
    path = write_temp(content, ".json")
    assert detect_format(path, "events.json") == "windows_json"
    os.unlink(path)


def test_detects_zeek_conn_json():
    content = json.dumps({"ts": 1234567890.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8"})
    path = write_temp(content, ".json")
    assert detect_format(path, "conn.log.json") == "zeek_conn_json"
    os.unlink(path)


def test_detects_pcap_by_extension():
    path = write_temp("fake pcap content", ".pcap")
    assert detect_format(path, "capture.pcap") == "pcap"
    os.unlink(path)


def test_unknown_format_returns_unknown():
    path = write_temp("completely unrecognized content here nothing matches", ".log")
    assert detect_format(path, "weird.log") == "unknown"
    os.unlink(path)


def test_detects_firewall_text_by_content():
    content = "Sep 16 10:00:00 firewall DENY 192.168.1.1 -> 10.0.0.5 port 22"
    path = write_temp(content, ".log")
    assert detect_format(path, "firewall.log") == "firewall_text"
    os.unlink(path)