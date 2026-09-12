# Private AI SOC

A local-first Security Operations platform: ingestion → normalization →
deterministic detection → correlation → incident management → risk
scoring → optional local AI investigation. No telemetry ever leaves
the machine (see THREAT_MODEL.md and the egress-guard test suite for
proof, not just a claim).

## Why this exists
Built as a hands-on SOC analyst training project and a proof-of-concept
for privacy-first security tooling - see docs/PROJECT_PHILOSOPHY.md.
This is not a Splunk competitor. It is a demonstrable, tested pipeline
covering the core SOC workflow end-to-end.

## Current capabilities
- Multi-source ingestion: Windows (4625), Linux (SSH auth), Zeek (conn.log)
- Deterministic detection: brute force, SSH root brute force, fast/slow port scanning
- Sliding-window correlation, deduplication, per-rule reopen windows
- MITRE ATT&CK mapping (T1110, T1110.001, T1078, T1046)
- Risk scoring: severity + confidence + evidence + critical-asset weighting
- Asset inventory (CSV-driven criticality)
- Local AI investigation (Ollama/Qwen) - auto-triggered above a risk threshold, always optional, never authoritative
- Persistent storage: SQLite (dev) and PostgreSQL (via Docker)
- CLI dashboard with live polling mode
- 78+ automated tests, including a named attack-scenario regression suite

## Quick start
See docs/INSTALLATION.md

## Architecture
See docs/ARCHITECTURE.md

## Security & Privacy
See docs/THREAT_MODEL.md and docs/SECURITY.md

## Status
Active development - see docs/ROADMAP.md for what's built vs planned.
