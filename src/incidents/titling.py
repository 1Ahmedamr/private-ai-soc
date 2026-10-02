# src/incidents/titling.py
"""Pick an incident title from its strongest detection (severity, then confidence).
The first detection to fire is arbitrary; a variance-0.01 beacon should not be
titled after a generic signature hit that happened to be processed first."""

_ORDER = ["info", "low", "medium", "high", "critical"]


def _rank(sev) -> int:
    s = str(getattr(sev, "value", sev)).lower().split(".")[-1]
    return _ORDER.index(s) if s in _ORDER else 0


def strongest_title(detections, fallback: str) -> str:
    triggered = [d for d in detections if getattr(d, "triggered", True)]
    if not triggered:
        return fallback
    best = max(triggered, key=lambda d: (_rank(d.severity), d.confidence))
    return best.rule_name
