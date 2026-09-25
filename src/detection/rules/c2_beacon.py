# src/detection/rules/c2_beacon.py

from typing import List
from statistics import stdev, mean
from src.models.event_schema import NormalizedEvent, EventType
from src.models.detection_schema import DetectionResult, Severity
from src.mitre.techniques import get_technique


def detect_c2_beacon(events: List[NormalizedEvent], min_connections: int = 5, max_interval_variance_ratio: float = 0.15) -> DetectionResult:
    """
    Real C2 beacon detection: malware often 'phones home' at REGULAR
    intervals (every 60s, every 300s). Legitimate traffic is irregular.
    We detect this by checking if connection intervals to the SAME
    destination have LOW variance relative to their mean - i.e., they're
    suspiciously periodic.
    """
    conns = [e for e in events if e.event_type == EventType.NETWORK_CONNECTION]
    grouped: dict[tuple, list] = {}
    for e in conns:
        grouped.setdefault((e.src_ip, e.dst_ip), []).append(e)

    for (src, dst), group in grouped.items():
        if len(group) < min_connections:
            continue
        group.sort(key=lambda e: e.timestamp)
        intervals = [(group[i+1].timestamp - group[i].timestamp).total_seconds() for i in range(len(group)-1)]
        if not intervals or mean(intervals) == 0:
            continue
        variance_ratio = stdev(intervals) / mean(intervals) if len(intervals) > 1 else 0
        if variance_ratio <= max_interval_variance_ratio:
            technique = get_technique("T1071")
            return DetectionResult(
                rule_name="Possible C2 Beacon (Periodic Connections)",
                rule_id="SOC-NET-001",
                triggered=True,
                severity=Severity.CRITICAL,
                mitre_technique=technique.technique_id if technique else "T1071",
                mitre_tactic=technique.tactic if technique else "Command and Control",
                description=f"Highly periodic connections from '{src}' to '{dst}': {len(group)} connections, ~{mean(intervals):.0f}s intervals (variance ratio={variance_ratio:.2f}).",
                confidence=0.7,
                reopen_window_hours=336,
            )

    return DetectionResult(
        rule_name="Possible C2 Beacon (Periodic Connections)", rule_id="SOC-NET-001",
        triggered=False, severity=Severity.INFO, description="No periodic beaconing pattern found.", confidence=1.0,
    )