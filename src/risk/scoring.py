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

    # Volume bonus: large event counts indicate high-confidence, sustained
    # activity - BUT only when that volume happened in a short window.
    # 355 packets over 2.85 hours (low-and-slow) is much less suspicious
    # than 1714 packets in 11 seconds (aggressive), even though both are
    # "high volume" by raw count. Scale the bonus down for spread-out activity.
    # Prefer detection-scoped evidence (specific to what actually fired)
    # over the incident's full correlated event list, which can include
    # unrelated activity from the same host/IP and would otherwise
    # overstate volume for a host that is simply generally active.
    detections_with_evidence = [
        d for d in incident.detections
        if d.evidence_event_count is not None and d.evidence_duration_seconds is not None
    ]
    if detections_with_evidence:
        d = max(detections_with_evidence, key=lambda d: d.evidence_event_count)
        event_count = d.evidence_event_count
        duration_seconds = max(d.evidence_duration_seconds, 1)
    else:
        event_count = len(incident.events)
        duration_seconds = max(
            (incident.last_seen - incident.first_seen).total_seconds(), 1
        )
    events_per_minute = event_count / (duration_seconds / 60)

    if event_count >= 1000:
        base_volume_bonus = 25
    elif event_count >= 100:
        base_volume_bonus = 15
    elif event_count >= 10:
        base_volume_bonus = 5
    else:
        base_volume_bonus = 0

    # Rate scaling: full bonus only for bursty activity (>=10 events/min).
    # Below that, scale down linearly - low-and-slow activity shouldn't
    # score the same as a fast burst just because the raw count is similar.
    if events_per_minute >= 10:
        rate_factor = 1.0
    elif events_per_minute >= 1:
        rate_factor = 0.5
    else:
        rate_factor = 0.25

    volume_bonus = round(base_volume_bonus * rate_factor)

    if incident.detections:
        avg_confidence = sum(d.confidence for d in incident.detections) / len(incident.detections)
    else:
        avg_confidence = 1.0

    raw_score = (base_score + evidence_bonus + volume_bonus) * avg_confidence

    if is_critical_asset:
        raw_score *= CRITICAL_ASSET_MULTIPLIER

    final_score = max(0, min(100, round(raw_score)))
    return final_score