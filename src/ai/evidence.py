# src/ai/evidence.py

from pydantic import BaseModel
from typing import List
from src.models.incident_schema import Incident
from src.knowledge.index import KnowledgeBase


class InvestigationEvidence(BaseModel):
    """
    This is the ENTIRE contract of what the AI is allowed to see.
    Notice what's deliberately excluded: raw_data blobs, full event
    objects, anything not already validated/decided by deterministic
    code. The AI reasons about CONCLUSIONS our engine already reached,
    not raw material it could misinterpret or be manipulated by
    (prompt injection risk - Phase 15 of the roadmap, addressed here
    concretely instead of just mentioned).
    """
    incident_id: str
    title: str
    severity: str              # already decided by Detection Engine - AI does not re-decide this
    risk_score: int             # already decided by Risk Scoring - AI does not re-decide this
    correlation_key: str
    mitre_techniques: List[str]
    detection_descriptions: List[str]   # human-readable summaries, not raw log lines
    event_count: int
    first_seen: str
    last_seen: str
    is_reopened_incident: bool
    relevant_playbook_excerpts: List[str] = []


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

    return InvestigationEvidence(
        incident_id=incident.incident_id,
        title=incident.title,
        severity=incident.severity,
        risk_score=incident.risk_score,
        correlation_key=incident.correlation_key,
        mitre_techniques=incident.mitre_techniques,
        detection_descriptions=[d.description for d in incident.detections],
        event_count=len(incident.events),
        first_seen=incident.first_seen.isoformat(),
        last_seen=incident.last_seen.isoformat(),
        is_reopened_incident=len(incident.related_incident_ids) > 0,
        relevant_playbook_excerpts=relevant_chunks,
    )