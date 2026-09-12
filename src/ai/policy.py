# src/ai/policy.py

from src.models.incident_schema import Incident, IncidentStatus

# Why 50, specifically?
# Recall Day 7's severity->base-score mapping: MEDIUM=30, HIGH=60. A
# risk_score of 50 sits between those, meaning: a MEDIUM incident needs
# real corroborating evidence or a critical-asset multiplier to cross
# this line, while a bare HIGH severity with average confidence clears
# it comfortably. This deliberately biases toward "when in doubt, spend
# the LLM call" for HIGH-severity cases, while keeping routine MEDIUM
# noise (e.g. a single unconfirmed detection) out of the AI queue.
AUTO_INVESTIGATE_MIN_RISK_SCORE = 50


def should_auto_investigate(incident: Incident) -> bool:
    """
    Decides whether an incident should automatically receive an AI
    investigation, without a human explicitly requesting it.

    Two conditions, both required:
    1. Status must be OPEN or INVESTIGATING - never CLOSED or
       FALSE_POSITIVE. A closed incident already has a human verdict;
       auto-investigating it would waste LLM cost re-litigating a
       decided case, and worse, could produce an AI opinion that
       contradicts a closed human decision, confusing future readers
       of the incident record.
    2. risk_score must meet the threshold - this is the actual cost
       control. Without it, EVERY incident (including LOW-severity
       single failed logins that only narrowly qualified past Day 3's
       policy) would trigger an LLM call, defeating the entire purpose
       of having a risk score in the first place.
    """
    if incident.status not in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
        return False
    return incident.risk_score >= AUTO_INVESTIGATE_MIN_RISK_SCORE