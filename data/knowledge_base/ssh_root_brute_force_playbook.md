# Playbook: SSH Root Brute Force

## Immediate Actions
1. This targets the highest-privilege account on a Linux host - treat as P1 regardless of automated risk score if the target is a production server.
2. Check `last` and `lastb` command output on the target host for any successful root login during the attack window.

## Investigation Steps
1. Identify if root SSH login is even supposed to be enabled - many hardened configs disable it entirely (PermitRootLogin no in sshd_config). If it's enabled, this is itself a finding independent of the attack.
2. Check for SSH key-based auth bypass attempts, not just password attempts.
3. Review sshd logs for the exact usernames attempted alongside root - attackers often rotate through common admin usernames in the same campaign.

## Containment
- Disable password authentication for root immediately; require key-based auth only.
- Add source IP to a fail2ban or equivalent blocklist if not already automatic.

## False Positive Indicators
- Source IP is a known internal automation/config-management tool (Ansible, Puppet) misconfigured with wrong credentials.
