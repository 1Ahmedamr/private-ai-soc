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


_IPV4_RE = None


def _involved_internal_ips(incident) -> set:
    """Internal hosts an incident is actually ABOUT: the correlation-key IP, the
    targets of alert events, and any IP named in its detection descriptions.
    (Not every dst_ip of every correlated event - that would link a host to
    everything its neighbour ever talked to.)"""
    import ipaddress
    import re
    global _IPV4_RE
    if _IPV4_RE is None:
        _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    candidates = set()
    ck = incident.correlation_key
    if ck.startswith("ip:"):
        candidates.add(ck.split("ip:", 1)[1])
    for e in incident.events:
        if str(getattr(e.event_type, "value", e.event_type)) == "alert" and e.dst_ip:
            candidates.add(e.dst_ip)
    for d in incident.detections:
        candidates.update(_IPV4_RE.findall(d.description or ""))

    internal = set()
    for ip in candidates:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_private and not (a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified):
            internal.add(ip)
    return internal


def correlate_by_host(incidents: list, window_hours: int = CORRELATION_WINDOW_HOURS) -> List[HostSummary]:
    """
    Groups incidents by each internal host they involve (as source OR target)
    within a time window. One incident can appear under several hosts.
    """
    if not incidents:
        return []

    host_incidents: Dict[str, list] = {}
    for incident in incidents:
        hosts = _involved_internal_ips(incident)
        if not hosts and incident.correlation_key.startswith("user:"):
            hosts = {incident.correlation_key}
        for h in hosts:
            host_incidents.setdefault(h, []).append(incident)

    severity_order = ["info", "low", "medium", "high", "critical"]
    summaries = []
    for host, host_incs in host_incidents.items():
        host_incs.sort(key=lambda i: i.first_seen)
        window_end = host_incs[0].first_seen + timedelta(hours=window_hours)
        in_window = [i for i in host_incs if i.first_seen <= window_end]
        if len(in_window) < 2:
            continue

        techniques, tactics = [], []
        for inc in in_window:
            for t in inc.mitre_techniques:
                if t not in techniques:
                    techniques.append(t)
            for d in inc.detections:
                if d.mitre_tactic and d.mitre_tactic not in tactics:
                    tactics.append(d.mitre_tactic)

        first = in_window[0].first_seen
        last = max(i.last_seen for i in in_window)
        summaries.append(HostSummary(
            victim_ip=host,
            victim_host=next((e.host for i in in_window for e in i.events[:5] if e.host), None),
            incident_ids=[i.incident_id for i in in_window],
            first_seen=first,
            last_seen=last,
            duration_minutes=round((last - first).total_seconds() / 60, 1),
            highest_severity=max((i.severity for i in in_window),
                                 key=lambda s: severity_order.index(s) if s in severity_order else 0),
            highest_risk=max(i.risk_score for i in in_window),
            mitre_techniques=techniques,
            mitre_tactics=tactics,
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
