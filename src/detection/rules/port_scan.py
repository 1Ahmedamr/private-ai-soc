# src/detection/rules/port_scan.py

from datetime import timedelta
from typing import List
from src.models.event_schema import NormalizedEvent, EventType
from src.models.detection_schema import DetectionResult
from src.models.event_schema import Severity
from src.mitre.techniques import get_technique


def detect_port_scan(
    events: List[NormalizedEvent],
    unique_ports_threshold: int = 5,
    window_seconds: int = 10,
) -> DetectionResult:
    """
    Rule: Port Scan Detection (Network Reconnaissance)

    Detects a source host attempting connections to many DIFFERENT
    ports on the same destination within a short time window, with
    no successful response (conn_state = "S0").

    Why "unique ports" and not just "many connections"?
    A busy web server legitimately gets thousands of connections per
    minute - but almost always to the SAME port (80/443). A source
    hitting MANY DIFFERENT ports on ONE destination in seconds is the
    actual scanning signature - that's what distinguishes recon
    behavior from normal traffic volume.
    """

    # Step 1: Filter to failed/no-response network connections only
    candidate_events = [
        e for e in events
        if e.event_type == EventType.NETWORK_CONNECTION and e.conn_state == "S0"
    ]

    if len(candidate_events) < unique_ports_threshold:
        return DetectionResult(
            rule_name="Port Scan Detection",
            rule_id="SOC-NET-002",
            triggered=False,
            severity=Severity.INFO,
            description=f"Only {len(candidate_events)} unanswered connections found; below threshold.",
            confidence=1.0,
        )

    # Step 2: Group by (source_ip, destination_ip) pair
    candidate_events.sort(key=lambda e: e.timestamp)
    grouped: dict[tuple, list[NormalizedEvent]] = {}
    for event in candidate_events:
        key = (event.src_ip, event.dst_ip)
        grouped.setdefault(key, []).append(event)

    # Step 3: For each source->destination pair, check unique ports within the window
    for (src, dst), group_events in grouped.items():
        unique_ports = {e.dst_port for e in group_events}

        if len(unique_ports) < unique_ports_threshold:
            continue

        first_time = group_events[0].timestamp
        last_time = group_events[-1].timestamp
        duration = last_time - first_time

        if duration <= timedelta(seconds=window_seconds):
            technique = get_technique("T1046")
            return DetectionResult(
                rule_name="Port Scan Detection",
                rule_id="SOC-NET-002",
                triggered=True,
                severity=Severity.MEDIUM,  # recon is a precursor, not confirmed compromise - MEDIUM, not HIGH
                mitre_technique=technique.technique_id if technique else "T1046",
                mitre_tactic=technique.tactic if technique else "Discovery",
                description=(
                    f"Port scan detected: source '{src}' probed {len(unique_ports)} "
                    f"distinct ports on destination '{dst}' within "
                    f"{duration.total_seconds():.1f} seconds, with no successful responses."
                ),
                confidence=0.85,  # slightly lower than brute force - scanners can be legitimate (vuln scanners, monitoring tools)
                reopen_window_hours=72,  # scanning often precedes a real attack days later - moderate window
            )

    return DetectionResult(
        rule_name="Port Scan Detection",
        rule_id="SOC-NET-002",
        triggered=False,
        severity=Severity.INFO,
        description="Unanswered connections found but not within required time window/port diversity.",
        confidence=1.0,
    )