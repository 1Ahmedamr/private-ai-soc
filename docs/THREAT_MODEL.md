# Threat Model: Private AI SOC

## What this project actually guarantees
- Telemetry (logs, events, incidents) is processed and stored entirely
  on local infrastructure (SQLite/Postgres running locally, Ollama
  running locally).
- The AI investigation layer (src/ai/ollama_client.py) makes zero
  outbound network calls to any host except 127.0.0.1 - enforced by
  tests/unit/test_egress_guard.py, not just claimed in this document.

## What this project does NOT guarantee (honest gaps)
1. **Ollama/model supply chain**: The qwen3:8b model file was
   downloaded once from Ollama's registry. We do not verify its
   checksum/provenance beyond Ollama's own tooling. A compromised model
   file is a theoretical vector this project does not defend against.
2. **Docker image provenance**: postgres:16 is pulled from Docker Hub.
   We trust the official Postgres image maintainers; no image
   signing/verification is implemented.
3. **Host-level security**: If the machine running this stack is
   itself compromised (malware, physical access), no software-level
   control here helps - this project protects data-in-transit-to-cloud,
   not the local machine's own security posture.
4. **Dependency supply chain**: pip/npm packages (psycopg2-binary,
   pydantic, requests, etc.) are trusted at install time. No SBOM or
   dependency-pinning-with-hash-verification is implemented yet.
5. **The AI's own outputs are not verified for correctness** - only
   for SHAPE (via InvestigationVerdict validation). A plausible-sounding
   but factually wrong AI summary would pass all current checks. Human
   review of AI verdicts remains necessary (see src/ai/policy.py's
   design intent: AI is advisory, never authoritative).

## Why this matters
A security tool that oversells its guarantees is worse than one that's
honest about its limits - false confidence leads to skipped human
review. This document exists so anyone evaluating this project (a
hiring manager, a future contributor, myself in 6 months) knows exactly
where the real boundary of "private" sits.