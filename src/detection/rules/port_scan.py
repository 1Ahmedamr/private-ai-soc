# src/detection/rules/port_scan.py

from datetime import timedelta
from typing import List
from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique


def _detect_port_scan_pattern(
    events: List[NormalizedEvent],
    unique_ports_threshold: int,
    window: timedelta,
    rule_name: str,
    rule_id: str,
    severity: Severity,
    confidence: float,
    reopen_window_hours: int,
) -> DetectionResult:
    candidate_events = [
        e for e in events
        if e.event_type == EventType.NETWORK_CONNECTION and e.conn_state == "S0"
    ]

    if len(candidate_events) < unique_ports_threshold:
        return DetectionResult(
            rule_name=rule_name, rule_id=rule_id, triggered=False,
            severity=Severity.INFO,
            description=f"Only {len(candidate_events)} unanswered connections; below threshold.",
            confidence=1.0,
        )

    candidate_events.sort(key=lambda e: e.timestamp)
    grouped: dict[tuple, list[NormalizedEvent]] = {}
    for event in candidate_events:
        key = (event.src_ip, event.dst_ip)
        grouped.setdefault(key, []).append(event)

    for (src, dst), group_events in grouped.items():
        left = 0
        for right in range(len(group_events)):
            while group_events[right].timestamp - group_events[left].timestamp > window:
                left += 1
            windowed_slice = group_events[left:right + 1]
            unique_ports_in_window = {e.dst_port for e in windowed_slice}

            if len(unique_ports_in_window) >= unique_ports_threshold:
                # Trigger confirmed — now count the FULL extent of the scan
                # not just the threshold-triggering window
                all_ports = {e.dst_port for e in group_events}
                first_ts = group_events[0].timestamp
                last_ts = group_events[-1].timestamp
                total_duration = (last_ts - first_ts).total_seconds()
                trigger_span = (group_events[right].timestamp - group_events[left].timestamp).total_seconds()

                technique = get_technique("T1046")
                return DetectionResult(
                    rule_name=rule_name,
                    rule_id=rule_id,
                    triggered=True,
                    severity=severity,
                    mitre_technique=technique.technique_id if technique else "T1046",
                    mitre_tactic=technique.tactic if technique else "Discovery",
                    description=(
                        f"{rule_name}: source '{src}' scanned {len(all_ports)} unique ports "
                        f"on destination '{dst}'. "
                        f"Total SYN packets: {len(group_events)} | "
                        f"Total unique ports: {len(all_ports)} | "
                        f"First seen: {first_ts.isoformat()} | "
                        f"Last seen: {last_ts.isoformat()} | "
                        f"Total duration: {total_duration:.1f}s | "
                        f"Alert triggered after {unique_ports_threshold} unique ports detected"
                        f"{' within <1 second' if trigger_span < 1 else f' within {trigger_span:.1f}s'}."
                    ),
                    confidence=confidence,
                    reopen_window_hours=reopen_window_hours,
                )

    return DetectionResult(
        rule_name=rule_name, rule_id=rule_id, triggered=False,
        severity=Severity.INFO,
        description="Unanswered connections found but not matching the scan pattern.",
        confidence=1.0,
    )

def detect_port_scan(
    events: List[NormalizedEvent],
    unique_ports_threshold: int = 5,
    window_seconds: int = 10,
) -> DetectionResult:
    """Fast port scan: many ports probed within seconds - classic automated scanner (e.g. Nmap default timing)."""
    return _detect_port_scan_pattern(
        events,
        unique_ports_threshold=unique_ports_threshold,
        window=timedelta(seconds=window_seconds),
        rule_name="Port Scan Detection (Fast)",
        rule_id="SOC-NET-002",
        severity=Severity.MEDIUM,
        confidence=0.85,
        reopen_window_hours=72,
    )


def detect_slow_port_scan(
    events: List[NormalizedEvent],
    unique_ports_threshold: int = 5,
    window_hours: int = 6,
) -> DetectionResult:
    """
    Slow / low-and-slow port scan: same signature, spread across hours
    instead of seconds - a deliberate evasion technique to dodge fast,
    short-window detections.

    Why LOWER severity/confidence than the fast variant?
    A pattern spread across hours is more ambiguous - it could be an
    evasive attacker, or coincidental unrelated failures. We still
    surface it for an analyst, just with appropriately tempered confidence.
    """
    return _detect_port_scan_pattern(
        events,
        unique_ports_threshold=unique_ports_threshold,
        window=timedelta(hours=window_hours),
        rule_name="Port Scan Detection (Slow / Low-and-Slow)",
        rule_id="SOC-NET-003",
        severity=Severity.MEDIUM,
        confidence=0.6,
        reopen_window_hours=168,  # 7 days
    )