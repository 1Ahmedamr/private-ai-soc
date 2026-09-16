# Roadmap

## V1 — Complete
- Multi-source ingestion (Windows, Linux, Zeek, Suricata)
- Normalized event schema across all sources
- Detection engine: brute force, SSH root, port scan, DNS, PowerShell, C2, Suricata
- Sliding-window correlation, deduplication, reopen windows
- MITRE ATT&CK mapping (T1110, T1046, T1059.001, T1568, T1071, T1078)
- Risk scoring (severity + confidence + evidence + asset criticality)
- Asset inventory (CSV-driven criticality)
- Local AI investigation (Ollama/Qwen) with structured evidence contract
- Local RAG knowledge base (sentence-transformers, offline)
- Persistent storage: SQLite (dev) + PostgreSQL (production via Docker)
- Flask web dashboard with Basic Auth and timeline view
- Live polling mode + file-watching ingestion loop
- 109 automated tests, 7/7 attack scenario coverage
- CI (GitHub Actions), MIT license, full documentation set
- Egress guard proving privacy claim in code, not just docs
- PCAP processing pipeline (Zeek + Suricata via subprocess)

## V2 — Planned
- Sigma rule loading (community rule library → DetectionEngine)
- Full MITRE ATT&CK dataset import (STIX/JSON feed)
- More playbooks (SOC team-authored, via knowledge base)
- Suricata rule tuning (suppress known-benign signatures)
- Traditional-vs-AI-SOC benchmark (requires external citation research)
- Demo video

## Known Gaps (Acknowledged, Not Hidden)
- SQLite concurrency ceiling under heavy write load (mitigated by
  PostgreSQL option, not fully eliminated)
- Knowledge base has only 4 playbooks (useful for demo, needs real
  organizational content for production)
- C2 beacon detection uses interval variance — works for regular
  beacons, misses jittered beacons (a known attacker evasion technique)
- No real-time streaming ingestion (polling loop is a simulation)