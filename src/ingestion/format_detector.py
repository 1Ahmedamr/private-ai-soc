# src/ingestion/format_detector.py

import json
from pathlib import Path
from typing import Literal, Optional

SupportedFormat = Literal[
    "windows_json",
    "linux_ssh_json",
    "zeek_conn_json",
    "suricata_eve_json",
    "firewall_text",
    "pcap",
    "unknown",
]


def detect_format(file_path: str, original_filename: str) -> SupportedFormat:
    """
    Determines the log format using two strategies:
    1. File extension (fast, cheap, works most of the time)
    2. Content sniffing (reads first few bytes/lines to confirm)

    Why not trust extension alone? In a real SOC, files come renamed,
    exported from tools with wrong extensions, or compressed. Content
    sniffing catches the most common mismatches. We still fail loudly
    with "unknown" rather than guessing at ambiguous content.
    """
    ext = Path(original_filename).suffix.lower()

    if ext in (".pcap", ".pcapng", ".cap"):
        return "pcap"

    if ext == ".json":
        return _sniff_json_format(file_path)

    if ext in (".log", ".txt", ""):
        return _sniff_text_format(file_path)

    return "unknown"


def _sniff_json_format(file_path: str) -> SupportedFormat:
    """Read first valid JSON object to identify source."""
    try:
        with open(file_path) as f:
            content = f.read(4096)

        content = content.strip()
        if content.startswith("["):
            first_obj = json.loads(content)[0]
        else:
            first_obj = json.loads(content.split("\n")[0])

        if "event_id" in first_obj and "username" in first_obj:
            return "windows_json"
        if "action" in first_obj and first_obj.get("action") in ("failed_password", "accepted_password"):
            return "linux_ssh_json"
        if "id.orig_h" in first_obj and "id.resp_h" in first_obj:
            return "zeek_conn_json"
        if "event_type" in first_obj and first_obj.get("event_type") == "alert":
            return "suricata_eve_json"
        if "alert" in first_obj and "signature" in first_obj.get("alert", {}):
            return "suricata_eve_json"

        return "unknown"
    except Exception:
        return "unknown"


def _sniff_text_format(file_path: str) -> SupportedFormat:
    """Read first few lines to identify plain-text firewall/auth logs."""
    try:
        with open(file_path) as f:
            first_lines = [f.readline() for _ in range(5)]
        combined = " ".join(first_lines).lower()

        firewall_keywords = ["deny", "permit", "blocked", "firewall", "asa", "pfsense", "drop", "accept"]
        if any(kw in combined for kw in firewall_keywords):
            return "firewall_text"

        return "unknown"
    except Exception:
        if "EventID" in first_obj and ("Image" in first_obj or "EventData" in first_obj):
            return "sysmon_json"
        if first_obj.get("event_id") in ("1", "3", "7", "10", "22") and "process" in first_obj.get("event_type", ""):
            return "sysmon_json"
        return "unknown"