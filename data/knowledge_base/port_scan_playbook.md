# Playbook: Port Scanning / Network Discovery Incidents

## Immediate Actions
1. Determine if the destination is a critical asset (check configs/assets.csv).
2. Port scanning alone is reconnaissance, not confirmed compromise - do NOT treat as equivalent to an active breach.

## Investigation Steps
1. Check for FOLLOW-UP activity from the same source IP in the days after the scan - scanning often precedes a targeted attack days later (see reopen_window_hours logic for slow-scan detections).
2. Identify which ports were probed - unusual ports (non-standard RDP, database ports) suggest targeted reconnaissance rather than generic scanning.
3. Check if the source IP is internal (possible compromised internal host) or external.

## Containment
- If source is internal: isolate the host immediately, as this may indicate an already-compromised machine performing lateral movement reconnaissance.
- If source is external: block at the perimeter firewall.

## False Positive Indicators
- Source IP matches a known internal vulnerability scanner (Nessus, OpenVAS) - verify against configs/assets.csv.
- Single connection attempt patterns from network monitoring tools.