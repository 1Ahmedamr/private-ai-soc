# src/ingestion/firewall_parser.py

import re
from datetime import datetime
from typing import List, Optional
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity

# Why support only these two formats? Because Cisco ASA and generic
# "DENY/BLOCK" patterns cover the majority of what a small-to-medium
# company exports from a firewall. More formats (Palo Alto, Fortinet,
# Check Point) would require their own parsers - this is honestly
# scoped, not a complete implementation.

_CISCO_ASA_PATTERN = re.compile(
    r"(\w+\s+\d+\s+[\d:]+).*?(\d+\.\d+\.\d+\.\d+)/(\d+).*?(\d+\.\d+\.\d+\.\d+)/(\d+).*?(Deny|Permit|deny|permit)",
    re.IGNORECASE,
)

_GENERIC_DENY_PATTERN = re.compile(
    r".*?(DENY|BLOCK|DROP|REJECT).*?(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def parse_firewall_line(line: str) -> Optional[NormalizedEvent]:
    """
    Attempts to parse a single firewall log line into a NormalizedEvent.
    Returns None for lines that don't match any known pattern (comments,
    headers, malformed lines) - callers skip None results rather than
    crashing on unrecognized content.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _CISCO_ASA_PATTERN.search(line)
    if m:
        action = m.group(6).lower()
        return NormalizedEvent(
            timestamp=datetime.now(),
            source=EventSource.FIREWALL,
            event_type=EventType.NETWORK_CONNECTION,
            src_ip=m.group(2),
            src_port=int(m.group(3)) if m.group(3).isdigit() else None,
            dst_ip=m.group(4),
            dst_port=int(m.group(5)) if m.group(5).isdigit() else None,
            status="failure" if action == "deny" else "success",
            severity=Severity.LOW,
            event_id=f"firewall_{action}",
            raw_data={"raw_line": line},
        )

    m = _GENERIC_DENY_PATTERN.search(line)
    if m:
        return NormalizedEvent(
            timestamp=datetime.now(),
            source=EventSource.FIREWALL,
            event_type=EventType.NETWORK_CONNECTION,
            src_ip=m.group(2),
            dst_ip=m.group(3),
            status="failure",
            severity=Severity.LOW,
            event_id="firewall_deny",
            raw_data={"raw_line": line},
        )

    return None


def parse_firewall_logs(raw_text: str) -> List[NormalizedEvent]:
    events = []
    for line in raw_text.splitlines():
        event = parse_firewall_line(line)
        if event:
            events.append(event)
    return events