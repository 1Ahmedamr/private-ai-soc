# src/ai/fivew.py
"""Deterministic 5W triage built from stored incident evidence (no LLM).
The local 8B model invented roles, beaconing and persistence when asked for
5Ws, so these answers are assembled in code: every field is either copied
from the evidence or explicitly marked 'not determined'."""
import ipaddress
import re
from datetime import datetime, timezone

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_INC = re.compile(r"INC-[A-F0-9]{8}", re.I)


def _utc(ts: str) -> str:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _endpoints(inc: dict):
    seen = []
    ck = inc.get("correlation_key", "")
    cands = [ck.split("ip:", 1)[1]] if ck.startswith("ip:") else []
    for e in inc.get("key_events", []) or []:
        cands += [e.get("src_ip"), e.get("dst_ip")]
    for d in inc.get("detections", []):
        cands += _IP.findall(d.get("description", ""))
    for ip in cands:
        if not ip or ip in seen:
            continue
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_multicast or a.is_loopback or a.is_link_local:
            continue
        seen.append(ip)
    out = []
    for ip in seen[:6]:
        scope = "internal" if ipaddress.ip_address(ip).is_private else "external"
        out.append(f"{ip} ({scope})")
    return out


def _technique_names(techs):
    names = []
    try:
        from src.mitre.techniques import get_technique
        for t in techs:
            n = getattr(get_technique(t), "name", None)
            names.append(f"{t} {n}" if n else t)
    except Exception:
        names = list(techs)
    return names


def build_5w(inc: dict) -> str:
    detections = inc.get("detections", [])
    techs = _technique_names(inc.get("mitre_techniques", []))
    lines = [
        f"{inc.get('incident_id', '')} - {inc.get('title', '')} "
        f"(severity {str(inc.get('severity', '')).lower().split('.')[-1]}, risk {inc.get('risk_score')}/100)",
        "Who: hosts observed in the evidence: " + (", ".join(_endpoints(inc)) or "none identified")
        + ". Which side initiated or is the source/target of any attack is not determined from this evidence.",
        "What (detections, verbatim): " + " | ".join(d.get("description", "")[:240] for d in detections),
        f"When: first seen {_utc(inc['first_seen'])}; last seen {_utc(inc['last_seen'])}.",
        "Where: network capture only; no process, host or file telemetry was captured.",
        "Why/How: not determinable from network alerts alone. "
        + (f"Mapped techniques (detection mappings, not confirmed behaviour): {', '.join(techs)}." if techs else "No technique mapped."),
        "Next: validate the alert against proxy/DNS logs and endpoint telemetry before any containment.",
    ]
    return "\n".join(lines)


def answer_5w(analysis: dict, question: str) -> str:
    incidents = list(analysis.get("incidents", []))
    wanted = {m.upper() for m in _INC.findall(question)}
    if wanted:
        incidents = [i for i in incidents if i.get("incident_id", "").upper() in wanted] or incidents
    incidents.sort(key=lambda i: i.get("risk_score", 0), reverse=True)
    if not incidents:
        return "No incidents in this analysis."
    return "\n\n".join(build_5w(i) for i in incidents)
