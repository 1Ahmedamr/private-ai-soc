# Known Limitations

Written deliberately and kept current. Every item below was checked against the code or measured, not assumed.

## Threat intelligence
- The local IOC store is small (about 9 IPs: a few hand-curated entries plus the abuse.ch Feodo Tracker list, refreshed manually with `python -m scripts.update_ioc_feeds`). There are no domain or file-hash feeds yet, so IOC matching adds little coverage on its own.
- VirusTotal enrichment is opt-in and needs your own API key.

## MITRE ATT&CK
- Full ATT&CK STIX import is implemented (697 techniques; all 281 technique IDs referenced by the loaded Sigma rules resolve).
- The dataset (about 48 MB) is not committed. Download it to `data/mitre/enterprise-attack.json`. Without it the code falls back to 7 built-in techniques and prints a warning.
- The local dataset uses newer tactic names (`Stealth`, `Defense Impairment`) while older Sigma rules still tag `Defense Evasion`. No automatic mapping is applied, so both spellings can appear.
- Sigma detections report only the first tactic listed on a rule.

## Detection coverage
- Sigma: about 1,470 rules loaded with a custom evaluator (not pySigma). Supported value modifiers: exact, contains, startswith, endswith, re, cidr, and the `all` list modifier. Others (for example `windash`) are not expanded, so rules relying on them can under-match.
- Zeek: only conn.log and dns.log are parsed. Roughly 5 of the 19 Zeek-category Sigma rules can fire; the rest need SMB, Kerberos, DCE-RPC or HTTP logs, which are not parsed yet.
- Suricata: the Emerging Threats Open ruleset is used as shipped. There is no local suppression or threshold tuning. The only adjustment is downgrading `ET INFO` and `SURICATA` internal signatures to LOW severity.
- C2 beacon detection accepts a variance ratio up to 0.6 to catch real malware with irregular handshakes. This is a precision/recall tradeoff and can flag legitimate periodic traffic (health checks, polling).

## AI investigation
- The knowledge base has 4 playbooks (brute force, port scan, SSH root brute force, Suricata signatures). Other incident types get no playbook guidance.
- Output comes from a small local model (qwen3:8b) constrained by prompt rules. It can still overstate; treat it as triage assistance, not a verdict.

## Deployment and privacy
- Detection makes no network calls. The only outbound requests are the opt-in VirusTotal lookup and the manual IOC feed updater.
- The egress-guard test covers the Ollama client path only, not VirusTotal or the zeek/suricata subprocess calls.
- The Docker Compose stack has not been re-verified recently; a container restart loop was seen in an earlier snapshot and is undiagnosed.
