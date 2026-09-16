# Private AI SOC
![Tests](https://github.com/1Ahmedamr/private-ai-soc/actions/workflows/tests.yml/badge.svg)

A fully local, privacy-first Security Operations platform. Logs never
leave your machine. AI investigation runs on a local model. Every
privacy claim is proven by a test, not just written in a document.

## Why this exists
Most AI-powered SOC tools route your security telemetry through a
cloud LLM. For a security team, that's a real tension: you're trusting
a third party with your most sensitive data. This project proves the
alternative is buildable — same detect-correlate-investigate workflow,
zero external data exposure.

## What it does
- **Ingests** logs from 4 sources: Windows Event Log (4625/4688),
  Linux SSH auth, Zeek network logs, Suricata IDS alerts
- **Detects** threats using deterministic rules: brute force, SSH root
  attacks, port scanning (fast + evasive), suspicious DNS (entropy),
  PowerShell abuse, C2 beacon periodicity, Suricata signatures
- **Correlates** events into incidents with deduplication, per-rule
  reopen windows, and related-incident linking
- **Scores** risk using severity + confidence + evidence count + asset
  criticality — before any AI is involved
- **Investigates** with a local LLM (Ollama/Qwen) using a stripped
  evidence contract that prevents prompt injection and raw log exposure
- **Retrieves** relevant playbook guidance via local RAG
  (sentence-transformers, offline)
- **Displays** incidents on a Flask dashboard with Basic Auth and a
  chronological timeline view

## The privacy claim, proven not just stated
`tests/unit/test_egress_guard.py` runs the real, unmocked AI
investigation code path under an active network trap that fails the
build if any call reaches outside localhost. See `docs/THREAT_MODEL.md`
for the complete, honest list of what is and is not protected.

## Quick start
```bash
cd docker && docker compose up -d --build
docker exec -it soc_ollama ollama pull qwen3:8b
export DASHBOARD_USERNAME=analyst DASHBOARD_PASSWORD=yourpassword
python -m scripts.seed_dashboard_data
python -m src.webapp.app
# open http://localhost:5001
```
Full setup: see `docs/INSTALLATION.md`

## Test suite
```bash
python -m pytest tests/unit/ -v          # 109 tests
python -m tests.scenarios.run_scenarios  # 7/7 attack scenarios
```

## Architecture
See `docs/ARCHITECTURE.md`

## Status
V1 complete. See `docs/ROADMAP.md` for what's built vs. planned.
