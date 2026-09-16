# Playbook: Suricata Signature Match Alerts

## Immediate Actions
1. Check the specific signature name - "invalid checksum" signatures are frequently capture artifacts from hardware checksum offloading, NOT malicious traffic (see docs/KNOWN_BENIGN_PATTERNS.md).
2. Cross-reference the signature ID against Suricata's own rule documentation to understand exactly what pattern triggered it.

## Investigation Steps
1. If the signature relates to a known CVE or exploit pattern, check if the destination host is actually vulnerable (patched vs unpatched).
2. Check packet payload (if captured) for confirmation - a signature match alone is not proof of successful exploitation, only of an attempt matching a known pattern.

## Containment
- For confirmed exploit-attempt signatures (not checksum artifacts): isolate the target host pending investigation.

## False Positive Indicators
- "Invalid checksum" signatures on internally-captured traffic - see docs/KNOWN_BENIGN_PATTERNS.md for the documented root cause.
- Signature matches on traffic to/from known vulnerability scanners.