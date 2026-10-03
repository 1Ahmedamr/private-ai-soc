# src/ai/fivew.py
"""Deterministic 5W triage built from stored incident evidence (no LLM).
Every field is copied from the evidence or marked 'not determined'.
Plain text on purpose: the chat UI does not render markdown."""
import ipaddress
import re
from datetime import datetime, timezone

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_INC = re.compile(r"INC-[A-F0-9]{8}", re.I)
_FROM_TO = re.compile(r"from '((?:\d{1,3}\.){3}\d{1,3})' to '((?:\d{1,3}\.){3}\d{1,3})'")
_SRC_DST = re.compile(r"source '((?:\d{1,3}\.){3}\d{1,3})'.*?destination '((?:\d{1,3}\.){3}\d{1,3})'")


def _dt(ts: str) -> datetime:
    d = datetime.fromisoformat(ts)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def _fmt(ts: str) -> str:
    return _dt(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def _duration(a: str, b: str) -> str:
    s = int(max((_dt(b) - _dt(a)).total_seconds(), 0))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _scope(ip: str) -> str:
    return "internal" if ipaddress.ip_address(ip).is_private else "external"


def _valid(ip):
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not (a.is_multicast or a.is_loopback or a.is_link_local)


def _flow(inc: dict):
    """(source, destination) as recorded by the detection, else None."""
    for d in inc.get("detections", []):
        text = d.get("description", "")
        m = _FROM_TO.search(text) or _SRC_DST.search(text)
        if m and _valid(m.group(1)) and _valid(m.group(2)):
            return m.group(1), m.group(2)
    ck = inc.get("correlation_key", "")
    src = ck.split("ip:", 1)[1] if ck.startswith("ip:") else None
    for e in inc.get("key_events", []) or []:
        s, t = e.get("src_ip"), e.get("dst_ip")
        if src and s == src and t and t != src and _valid(t):
            return src, t
    for e in inc.get("key_events", []) or []:
        s, t = e.get("src_ip"), e.get("dst_ip")
        if _valid(s) and _valid(t) and s != t:
            return s, t
    return (src, None) if src and _valid(src) else (None, None)


def _others(inc: dict, skip, limit=4):
    pool = []
    for d in inc.get("detections", []):
        pool += _IP.findall(d.get("description", ""))
    for e in inc.get("key_events", []) or []:
        pool += [e.get("src_ip"), e.get("dst_ip")]
    out = []
    for ip in pool:
        if ip and ip not in skip and ip not in out and _valid(ip):
            out.append(ip)
    return out[:limit]


def _technique_names(techs):
    try:
        from src.mitre.techniques import get_technique
        names = []
        for t in techs:
            n = getattr(get_technique(t), "name", None)
            names.append(f"{t} {n}" if n else t)
        return names
    except Exception:
        return list(techs)


def _related(inc: dict, analysis: dict):
    titles = {i.get("incident_id"): i.get("title", "") for i in analysis.get("incidents", [])}
    out = []
    for hs in analysis.get("host_summaries", []):
        ids = hs.get("incident_ids", [])
        if inc.get("incident_id") in ids:
            for other in ids:
                if other != inc.get("incident_id") and other in titles:
                    out.append(f"{other} ({titles[other]}) on host {hs.get('victim_ip')}")
    return list(dict.fromkeys(out))


def build_5w(inc: dict, analysis: dict = None) -> str:
    from src.ai.actions import build_actions
    analysis = analysis or {}
    detections = inc.get("detections", [])
    descs = [d.get("description", "") for d in detections]
    sev = str(inc.get("severity", "")).lower().split(".")[-1]
    src, dst = _flow(inc)
    shown = {x for x in (src, dst) if x}
    others = _others(inc, shown)
    techs = _technique_names(inc.get("mitre_techniques", []))
    info_only = bool(descs) and all("ET INFO" in d for d in descs)

    L = [f"5Ws SUMMARY - {inc.get('incident_id', '')} - {inc.get('title', '')}",
         f"Severity: {sev.upper()} | Risk: {inc.get('risk_score')}/100", "", "WHO"]
    if src:
        L.append(f"- Source IP (as recorded by the detection): {src} ({_scope(src)})")
    if dst:
        L.append(f"- Destination IP (as recorded by the detection): {dst} ({_scope(dst)})")
    if others:
        L.append("- Other hosts in this evidence: " + ", ".join(f"{ip} ({_scope(ip)})" for ip in others))
    L.append("- Source/destination describe traffic direction only. Which host initiated the activity, "
             "or acted as source or target of an attack, is not determined from this evidence.")

    L += ["", "WHAT"]
    L += [f"- {x[:240]}" for x in descs] or ["- No detection text recorded."]
    if techs:
        L.append("- Mapped techniques (detection mappings, not confirmed behaviour): " + ", ".join(techs))

    L += ["", "WHEN", f"- First seen: {_fmt(inc['first_seen'])}", f"- Last seen: {_fmt(inc['last_seen'])}",
          f"- Duration: {_duration(inc['first_seen'], inc['last_seen'])}"]

    L += ["", "WHERE", "- Network capture only. No process, host or file telemetry was captured."]
    rel = _related(inc, analysis)
    if rel:
        L.append("- Same host also appears in: " + "; ".join(rel))

    L += ["", "WHY / HOW", "- Not determinable from network alerts alone."]
    if info_only:
        L.append("- Stage: suspected ingress tool transfer; requires investigation. "
                 "The signature is informational and does not show the file is malicious.")

    L += ["", "NEXT STEPS"]
    steps = build_actions(descs, [src] if src else [], ([dst] if dst else []) + others)
    steps.append("Validate the alert against proxy/DNS logs and endpoint telemetry before any containment.")
    L += [f"{i}. {s}" for i, s in enumerate(steps, 1)]

    label = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}.get(sev, sev)
    L += ["", f"RISK: {label} ({inc.get('risk_score')}/100). Network evidence only: these are indicators, "
              "not confirmed compromise."]
    return "\n".join(L)


def answer_5w(analysis: dict, question: str) -> str:
    incidents = list(analysis.get("incidents", []))
    wanted = {m.upper() for m in _INC.findall(question)}
    if wanted:
        incidents = [i for i in incidents if i.get("incident_id", "").upper() in wanted] or incidents
    incidents.sort(key=lambda i: i.get("risk_score", 0), reverse=True)
    if not incidents:
        return "No incidents in this analysis."
    return ("\n\n" + "-" * 40 + "\n\n").join(build_5w(i, analysis) for i in incidents)
