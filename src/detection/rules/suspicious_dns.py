# src/detection/rules/suspicious_dns.py

import math
from collections import Counter
from typing import List
from src.models.event_schema import NormalizedEvent, EventType, Severity
from src.models.detection_schema import DetectionResult
from src.mitre.techniques import get_technique


def _shannon_entropy(s: str) -> float:
    """
    Measures randomness of a string. Real words ('google') have LOW
    entropy (repeated letter patterns humans use). DGA malware domains
    ('xk7q9zvbn2') have HIGH entropy - this is a standard, well-known
    technique for flagging algorithmically-generated domains.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_suspicious_dns(events: List[NormalizedEvent], entropy_threshold: float = 3.5) -> DetectionResult:
    dns_events = [e for e in events if e.event_type == EventType.DNS_QUERY]

    for event in dns_events:
        domain = event.event_id or ""
        subdomain = domain.split(".")[0] if domain else ""
        if len(subdomain) >= 8 and _shannon_entropy(subdomain) >= entropy_threshold:
            technique = get_technique("T1568")
            return DetectionResult(
                rule_name="Suspicious DNS (High-Entropy Domain)",
                rule_id="SOC-NET-004",
                triggered=True,
                severity=Severity.MEDIUM,
                mitre_technique=technique.technique_id if technique else "T1568",
                mitre_tactic=technique.tactic if technique else "Command and Control",
                description=f"High-entropy domain queried: '{domain}' (entropy={_shannon_entropy(subdomain):.2f}) - possible DGA/C2 domain.",
                confidence=0.6,
                reopen_window_hours=72,
            )

    return DetectionResult(
        rule_name="Suspicious DNS (High-Entropy Domain)", rule_id="SOC-NET-004",
        triggered=False, severity=Severity.INFO, description="No high-entropy DNS queries found.", confidence=1.0,
    )