# src/risk/scoring.py

from src.models.incident_schema import Incident
from src.models.event_schema import Severity


# --- Weight configuration ---
# Why hardcode weights here instead of scattering magic numbers everywhere?
# Same "Single Source of Truth" principle from policy.py - if we tune the
# scoring formula later (based on real benchmark data, per Phase 19 of the
# roadmap), we update it here, once.

SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}

MAX_EVIDENCE_BONUS = 20      # cap on how much "more evidence" can add to the score
EVIDENCE_BONUS_PER_DETECTION = 5

CRITICAL_ASSET_MULTIPLIER = 1.3    # asset importance boosts final score


def calculate_risk_score(incident: Incident, is_critical_asset: bool = False) -> int:
    base_score = SEVERITY_WEIGHTS[incident.severity]

    evidence_count = len(incident.detections)
    evidence_bonus = min(
        (evidence_count - 1) * EVIDENCE_BONUS_PER_DETECTION,
        MAX_EVIDENCE_BONUS,
    )
    evidence_bonus = max(evidence_bonus, 0)

    # Volume bonus: large event counts indicate high-confidence, sustained activity
    # A single-packet detection vs 1700+ SYN packets deserve different scores
    event_count = len(incident.events)
    if event_count >= 1000:
        volume_bonus = 25   # was 15 — 1714 ports in 11s is aggressive
    elif event_count >= 100:
        volume_bonus = 15   # was 10
    elif event_count >= 10:
        volume_bonus = 5
    else:
        volume_bonus = 0

    if incident.detections:
        avg_confidence = sum(d.confidence for d in incident.detections) / len(incident.detections)
    else:
        avg_confidence = 1.0

    raw_score = (base_score + evidence_bonus + volume_bonus) * avg_confidence

    if is_critical_asset:
        raw_score *= CRITICAL_ASSET_MULTIPLIER

    final_score = max(0, min(100, round(raw_score)))
    return final_score