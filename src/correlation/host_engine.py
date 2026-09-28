# src/correlation/host_engine.py

"""
Host-based correlation engine.

Groups multiple incidents by victim IP (or host) within a time window
and produces a HostSummary — a unified view of everything that happened
to one asset during an attack campaign.

Why keep individual incidents AND add a host summary?
Individual incidents preserve granular evidence and let analysts
drill into each detection independently. The host summary answers
the analyst's first question: "what happened to this host, and in
what order?" — the attack narrative that raw incident lists don't tell.

Design principles:
- Never modify existing incidents (read-only correlation)
- Group by VICTIM IP, not source IP (attacker IPs are external)
- Time window: incidents within 4 hours of each other on the same host
- Narrative is AI-generated from the structured incident sequence
- Severity is the HIGHEST severity across all grouped incidents
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict
from dataclasses import dataclass, field


CORRELATION_WINDOW_HOURS = 4


@dataclass
class HostSummary:
    """
    A unified view of all incidents affecting one host within a time window.
    This is the "attack narrative" object — what a SOC analyst reads first.
    """
    victim_ip: str
    victim_host: Optional[str]
    incident_ids: List[str]
    first_seen: datetime
    last_seen: datetime
    duration_minutes: float
    highest_severity: str
    highest_risk: int
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    detection_names: List[str]
    attack_stages: List[str]          # ordered by time
    narrative: Optional[str] = None   # AI-generated summary
    is_confirmed_compromise: bool = False


def _extract_victim_ip(incident) -> Optional[str]:
    """
    Extracts the victim (target) IP from an incident.
    For network incidents, the victim is the destination.
    For auth incidents, the victim is the host being attacked.
    For IOC matches, the correlation_key IS the source — we need dst_ip.
    """
    # Check events for destination IPs (victim)
    dst_ips = []
    for event in incident.events[:20]:
        if event.dst_ip and not event.dst_ip.startswith("192.168."):
            dst_ips.append(event.dst_ip)
        elif event.host:
            return event.host

    # Fall back to correlation key if it's an IP
    if incident.correlation_key.startswith("ip:"):
        return incident.correlation_key.split("ip:", 1)[1]
    if incident.correlation_key.startswith("user:"):
        return None  # user-based incidents don't have a victim IP

    return dst_ips[0] if dst_ips else None


def _extract_target_ip(incident) -> Optional[str]:
    """
    For port scans and C2, the SOURCE is the attacker, TARGET is the victim.
    For Suricata alerts, look at dest_ip in events.
    """
    for event in incident.events[:20]:
        if event.dst_ip:
            return event.dst_ip
    return None


def correlate_by_host(incidents: list, window_hours: int = CORRELATION_WINDOW_HOURS) -> List[HostSummary]:
    """
    Groups incidents by victim host within a rolling time window.
    Returns one HostSummary per affected host.
    """
    if not incidents:
        return []

    # Build a mapping: victim_ip -> list of incidents
    host_incidents: Dict[str, list] = {}

    for incident in incidents:
        # Try to identify the victim/target
        victim = None

        # For Suricata alerts: destination IP is the victim
        for event in incident.events[:10]:
            if event.dst_ip and not _is_external(event.dst_ip):
                victim = event.dst_ip
                break

        # For port scans: destination is the victim
        if not victim and "scan" in incident.title.lower():
            victim = _extract_target_ip(incident)

        # Fall back: use correlation key as the identity
        if not victim:
            ck = incident.correlation_key
            if ck.startswith("ip:"):
                victim = ck.split("ip:", 1)[1]
            elif ck.startswith("user:"):
                victim = ck  # use user identity as grouping key

        if victim:
            host_incidents.setdefault(victim, []).append(incident)

    summaries = []
    for victim_ip, host_incs in host_incidents.items():
        if len(host_incs) < 2:
            continue  # single incident doesn't need a summary

        # Sort by first_seen
        host_incs.sort(key=lambda i: i.first_seen)

        # Check time window — all must be within window_hours of first incident
        first_time = host_incs[0].first_seen
        window_end = first_time + timedelta(hours=window_hours)
        in_window = [i for i in host_incs if i.first_seen <= window_end]

        if len(in_window) < 2:
            continue

        # Collect MITRE techniques and tactics across all incidents
        all_techniques = []
        all_tactics = []
        for inc in in_window:
            for t in inc.mitre_techniques:
                if t not in all_techniques:
                    all_techniques.append(t)
            for d in inc.detections:
                if d.mitre_tactic and d.mitre_tactic not in all_tactics:
                    all_tactics.append(d.mitre_tactic)

        severity_order = ["info", "low", "medium", "high", "critical"]
        highest_sev = max(
            (i.severity for i in in_window),
            key=lambda s: severity_order.index(s) if s in severity_order else 0,
        )

        summaries.append(HostSummary(
            victim_ip=victim_ip,
            victim_host=next((e.host for i in in_window for e in i.events[:5] if e.host), None),
            incident_ids=[i.incident_id for i in in_window],
            first_seen=in_window[0].first_seen,
            last_seen=in_window[-1].last_seen,
            duration_minutes=round((in_window[-1].last_seen - in_window[0].first_seen).total_seconds() / 60, 1),
            highest_severity=highest_sev,
            highest_risk=max(i.risk_score for i in in_window),
            mitre_techniques=all_techniques,
            mitre_tactics=all_tactics,
            detection_names=[d.rule_name for i in in_window for d in i.detections],
            attack_stages=[d.mitre_tactic for i in in_window for d in i.detections if d.mitre_tactic],
        ))

    return summaries


def _is_external(ip: str) -> bool:
    """Rough check: is this IP likely external/attacker?"""
    private_prefixes = ("10.", "172.", "192.168.", "127.")
    return not any(ip.startswith(p) for p in private_prefixes)


def generate_narrative(summary: HostSummary, incidents: list) -> str:
    """
    Generates a plain-language attack narrative from a HostSummary.
    Called by the AI investigation layer, not here directly.
    This builds the structured prompt context for the LLM.
    """
    inc_map = {i.incident_id: i for i in incidents}
    linked_incs = [inc_map[iid] for iid in summary.incident_ids if iid in inc_map]
    linked_incs.sort(key=lambda i: i.first_seen)

    lines = [
        f"Host {summary.victim_ip} was involved in {len(linked_incs)} correlated incidents "
        f"over {summary.duration_minutes:.0f} minutes "
        f"({summary.first_seen.strftime('%Y-%m-%dT%H:%M:%SZ')} to "
        f"{summary.last_seen.strftime('%Y-%m-%dT%H:%M:%SZ')}).",
        "",
        "Incident sequence (chronological):",
    ]
    for i, inc in enumerate(linked_incs, 1):
        lines.append(
            f"  {i}. [{inc.severity.upper()}] {inc.title} "
            f"(risk={inc.risk_score}, "
            f"MITRE={', '.join(inc.mitre_techniques) or 'unknown'})"
        )

    if summary.mitre_tactics:
        lines.append(f"\nObserved tactics: {', '.join(set(summary.mitre_tactics))}")

    return "\n".join(lines)
