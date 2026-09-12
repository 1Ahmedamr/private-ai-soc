# src/dashboard/cli_view.py

from typing import List
from src.models.incident_schema import Incident, IncidentStatus


# ANSI color codes - why hand-roll this instead of a dependency like
# `rich` or `colorama`? At this project stage, a CLI dashboard is a
# stepping stone toward Phase 16's real web dashboard, not a permanent
# fixture. Adding a dependency for a temporary tool isn't worth it -
# revisit this decision when/if this becomes a long-lived interface.
_RESET = "\033[0m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_BOLD = "\033[1m"

_SEVERITY_COLORS = {
    "critical": _RED,
    "high": _RED,
    "medium": _YELLOW,
    "low": _GREEN,
    "info": _GREEN,
}


def _color_for_severity(severity: str) -> str:
    return _SEVERITY_COLORS.get(severity, _RESET)


def render_incident_table(incidents: List[Incident]) -> str:
    """
    Renders open/investigating incidents sorted by risk_score descending
    - highest-priority work at the top, matching how a real analyst
    triages a queue: worst first, not chronological.
    """
    visible = [
        i for i in incidents
        if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
    ]
    visible.sort(key=lambda i: i.risk_score, reverse=True)

    if not visible:
        return "No open incidents. Queue is clear."

    lines = []
    header = f"{_BOLD}{'ID':<14}{'RISK':<6}{'SEV':<9}{'PRIORITY':<12}{'MITRE':<16}{'TITLE':<32}{'AI VERDICT'}{_RESET}"
    lines.append(header)
    lines.append("-" * 110)

    for inc in visible:
        color = _color_for_severity(inc.severity)
        mitre = ",".join(inc.mitre_techniques) or "-"
        ai_status = (inc.ai_verdict[:40] + "...") if inc.ai_verdict else "(not investigated)"
        title = inc.title[:30]

        line = (
            f"{color}{inc.incident_id:<14}{inc.risk_score:<6}{inc.severity:<9}"
            f"{inc.priority:<12}{mitre:<16}{title:<32}{_RESET}{ai_status}"
        )
        lines.append(line)

    return "\n".join(lines)


def render_incident_detail(incident: Incident) -> str:
    """Full drill-down view for a single incident - the equivalent of
    'clicking into' an incident in a real SOC dashboard."""
    lines = [
        f"{'='*70}",
        f"Incident: {incident.incident_id}",
        f"Title:    {incident.title}",
        f"Status:   {incident.status}  |  Priority: {incident.priority}  |  Risk: {incident.risk_score}/100",
        f"Severity: {incident.severity}",
        f"Correlation Key: {incident.correlation_key}",
        f"MITRE:    {', '.join(incident.mitre_techniques) or 'none mapped'}",
        f"First Seen: {incident.first_seen}  |  Last Seen: {incident.last_seen}",
        f"Events Attached: {len(incident.events)}",
        f"Related Incidents: {', '.join(incident.related_incident_ids) or 'none'}",
        f"{'-'*70}",
        "Detections:",
    ]
    for d in incident.detections:
        lines.append(f"  - [{d.rule_name}] {d.description} (confidence={d.confidence})")

    lines.append(f"{'-'*70}")
    if incident.ai_verdict:
        lines.append(f"AI Summary: {incident.ai_verdict}")
        lines.append("Recommended Actions:")
        for action in incident.recommended_actions:
            lines.append(f"  - {action}")
    else:
        lines.append("AI Investigation: not yet run")

    lines.append(f"{'='*70}")
    return "\n".join(lines)