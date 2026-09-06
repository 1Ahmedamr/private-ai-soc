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
EVIDENCE_BONUS_PER_DETECTION = 5   # each additional detection adds this much (capped)

CRITICAL_ASSET_MULTIPLIER = 1.3    # asset importance boosts final score


def calculate_risk_score(incident: Incident, is_critical_asset: bool = False) -> int:
    """
    Calculates a 0-100 risk score for an incident.

    Formula (in plain terms):
    1. Start from the base severity weight (e.g. HIGH = 60)
    2. Add a bonus for how much corroborating evidence exists
       (more detections = more confidence this is real, not noise)
    3. Weight by average confidence across all detections
       (low-confidence detections shouldn't inflate the score much)
    4. Multiply by asset importance if this affects a critical asset
       (e.g. Domain Controller vs a regular workstation)
    5. Clamp the final result to [0, 100]
    """

    base_score = SEVERITY_WEIGHTS[incident.severity]

    # Evidence bonus: more detections = more corroborating proof
    evidence_count = len(incident.detections)
    evidence_bonus = min(
        (evidence_count - 1) * EVIDENCE_BONUS_PER_DETECTION,
        MAX_EVIDENCE_BONUS,
    )
    evidence_bonus = max(evidence_bonus, 0)  # never negative

    # Average confidence across all detections in this incident
    if incident.detections:
        avg_confidence = sum(d.confidence for d in incident.detections) / len(incident.detections)
    else:
        avg_confidence = 1.0

    raw_score = (base_score + evidence_bonus) * avg_confidence

    if is_critical_asset:
        raw_score *= CRITICAL_ASSET_MULTIPLIER

    # Clamp to 0-100
    final_score = max(0, min(100, round(raw_score)))

    return final_score