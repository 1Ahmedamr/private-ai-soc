# src/correlation/timeline.py

"""
Builds a chronological attack timeline for one correlated host.

Works on the session-dict form of incidents and host summaries (plain
dicts), so it is trivially testable and has no dependency on Flask.

Honesty note: entries are ordered by when each INCIDENT's detection
window began. That shows observed sequence, not proven causation.
All timestamps are normalized to UTC for display.
"""

from datetime import datetime, timezone
from typing import List, Optional
from src.correlation.assessment import build_assessment


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _human(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def _sev(value) -> str:
    return str(value).lower().split(".")[-1]


def _tactics_for(techniques: List[str]) -> List[str]:
    from src.mitre.techniques import get_technique
    tactics: List[str] = []
    for t in techniques or []:
        tech = get_technique(t)
        tactic = getattr(tech, "tactic", None) if tech else None
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    return tactics


def build_host_timeline(host_summary: dict, incidents: List[dict]) -> dict:
    wanted = set(host_summary.get("incident_ids", []))
    linked = [i for i in incidents if i.get("incident_id") in wanted]
    linked.sort(key=lambda i: _parse(i["first_seen"]))

    entries = []
    prev_start: Optional[datetime] = None
    for inc in linked:
        start = _parse(inc["first_seen"])
        end = _parse(inc["last_seen"])
        gap = None if prev_start is None else _human((start - prev_start).total_seconds())
        entries.append({
            "incident_id": inc["incident_id"],
            "time": _fmt(start),
            "end_time": _fmt(end),
            "duration": _human((end - start).total_seconds()),
            "gap_label": gap,
            "title": inc["title"],
            "severity": _sev(inc["severity"]),
            "risk": inc["risk_score"],
            "actor": inc.get("correlation_key", ""),
            "techniques": inc.get("mitre_techniques", []),
            "tactics": _tactics_for(inc.get("mitre_techniques", [])),
            "evidence": [
                (d.get("description", "")[:240])
                for d in inc.get("detections", [])
            ],
        })
        prev_start = start

    ordered_tactics: List[str] = []
    for e in entries:
        for t in e["tactics"]:
            if t not in ordered_tactics:
                ordered_tactics.append(t)

    span = ""
    if linked:
        latest_end = max(_parse(i["last_seen"]) for i in linked)
        span = _human((latest_end - _parse(linked[0]["first_seen"])).total_seconds())

    return {
        "victim_ip": host_summary.get("victim_ip", ""),
        "count": len(entries),
        "span": span,
        "highest_severity": _sev(host_summary.get("highest_severity", "low")),
        "tactics_in_order": ordered_tactics,
        "entries": entries,
        "assessment": build_assessment(entries, host_summary.get("victim_ip", "")),
    }
