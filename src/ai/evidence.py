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
        source_ips=source_ips,
        target_ips=target_ips[:5],
    )
