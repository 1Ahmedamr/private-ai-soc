# src/ai/evidence.py

from typing import List
from src.models.incident_schema import Incident
from src.knowledge.index import KnowledgeBase
from pydantic import BaseModel


class InvestigationEvidence(BaseModel):
    incident_id: str
    title: str
    severity: str
    risk_score: int
    correlation_key: str
    mitre_techniques: List[str]
    mitre_tactic: str = ""
    detection_descriptions: List[str]
    event_count: int
    first_seen: str
    last_seen: str
    is_reopened_incident: bool
    relevant_playbook_excerpts: List[str] = []
    source_ips: list = []
    target_ips: list = []
    attack_stage: str = ""
    affected_hosts: list = []
    accounts: list = []


# Most advanced stage first, used to order the stages shown to the analyst.
_STAGE_PRIORITY = [
    "impact", "exfiltration", "command and control", "collection",
    "lateral movement", "persistence", "privilege escalation",
    "defense evasion", "execution", "discovery", "credential access",
    "initial access", "resource development", "reconnaissance",
]


def compute_attack_stage(detections) -> str:
    """Stage label from the detections' own tactics. Returns '' when fewer than
    two distinct tactics exist, so single-tactic incidents keep the existing logic."""
    seen = {}
    for d in detections:
        tactic = getattr(d, "mitre_tactic", None)
        if tactic:
            for part in tactic.split(","):
                key = part.lower().replace("_", " ").strip()
                if key:
                    seen.setdefault(key, key.title())
    if len(seen) < 2:
        return ""
    order = {name: i for i, name in enumerate(_STAGE_PRIORITY)}
    keys = sorted(seen, key=lambda k: order.get(k, len(_STAGE_PRIORITY)))
    return " + ".join(seen[k] for k in keys)


_knowledge_base = None


def _get_knowledge_base() -> KnowledgeBase:
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
        _knowledge_base.build()
    return _knowledge_base


def build_evidence(incident: Incident) -> InvestigationEvidence:
    kb = _get_knowledge_base()
    query = f"{incident.title} {' '.join(d.description for d in incident.detections)}"
    relevant_chunks = [chunk for chunk, score in kb.query(query, top_k=2) if score > 0.3]

    source_ips = []
    target_ips = []
    if incident.correlation_key.startswith("ip:"):
        source_ips = [incident.correlation_key.split("ip:")[1]]
    import ipaddress
    import re
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    affected_hosts, accounts = [], []
    for event in incident.events[:200]:
        if event.host and event.host not in affected_hosts:
            affected_hosts.append(event.host)
        if event.user and event.user not in accounts:
            accounts.append(event.user)
        # user/host-keyed incidents (logons, process events) have no IP key; use the IPs recorded on the events
        if not incident.correlation_key.startswith("ip:") and event.src_ip and event.src_ip not in source_ips:
            try:
                parsed = ipaddress.ip_address(event.src_ip)
            except ValueError:
                continue
            if not (parsed.is_multicast or parsed.is_loopback or parsed.is_link_local) and len(source_ips) < 3:
                source_ips.append(event.src_ip)
    for d in incident.detections:
        for ip in ip_re.findall(d.description or ""):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.is_multicast or a.is_loopback or a.is_link_local:
                continue
            if ip not in source_ips and ip not in target_ips:
                target_ips.append(ip)
    if not target_ips:  # fallback for detections that name no IPs
        for event in incident.events[:20]:
            if event.dst_ip and event.dst_ip not in target_ips:
                target_ips.append(event.dst_ip)

    mitre_tactic = ""
    for d in incident.detections:
        if d.mitre_tactic:
            mitre_tactic = d.mitre_tactic
            break

    return InvestigationEvidence(
        incident_id=incident.incident_id,
        title=incident.title,
        severity=incident.severity,
        risk_score=incident.risk_score,
        correlation_key=incident.correlation_key,
        mitre_techniques=incident.mitre_techniques,
        mitre_tactic=mitre_tactic,
        detection_descriptions=[
            f"{d.description} [events: {len(incident.events)}]"
            for d in incident.detections
        ],
        event_count=len(incident.events),
        first_seen=incident.first_seen.isoformat(),
        last_seen=incident.last_seen.isoformat(),
        is_reopened_incident=len(incident.related_incident_ids) > 0,
        relevant_playbook_excerpts=relevant_chunks,
        source_ips=source_ips[:5],
        target_ips=target_ips[:5],
        attack_stage=compute_attack_stage(incident.detections),
        affected_hosts=affected_hosts[:5],
        accounts=accounts[:5],
    )
