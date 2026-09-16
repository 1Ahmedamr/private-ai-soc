# Playbook: Brute Force / Credential Access Incidents

## Immediate Actions
1. Identify the source IP and check if it appears in prior incidents (related_incident_ids).
2. If the targeted account is a privileged account (root, admin, domain admin), escalate to P1 regardless of the automated priority score.
3. Temporarily lock the targeted account if attempts exceed 10 within any window.

## Investigation Steps
1. Check authentication logs for ANY successful login from the same source IP in the surrounding 24 hours - a successful login after failures is the highest-priority signal of compromise.
2. Cross-reference the source IP against known threat intelligence feeds if available.
3. Review whether MFA was enforced on the targeted account.

## Containment
- Block the source IP at the firewall/edge if attempts continue after account lockout.
- Force password reset on the targeted account if any successful authentication is found.

## False Positive Indicators
- Source IP belongs to an internal vulnerability scanner or monitoring tool (check configs/assets.csv for known scanner IPs).
- Timing correlates with a scheduled automated job (e.g., a backup script with a stale credential).