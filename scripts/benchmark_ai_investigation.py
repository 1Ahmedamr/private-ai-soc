# scripts/benchmark_ai_investigation.py

import time
from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority
from src.models.event_schema import Severity
from src.ai.evidence import build_evidence
from src.ai.ollama_client import investigate

incident = Incident(
    title="Brute Force Detection", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
    correlation_key="user:admin", first_seen=datetime.now(), last_seen=datetime.now(), risk_score=62,
)

print("Timing real AI investigation call (requires Ollama running)...")
start = time.perf_counter()
evidence = build_evidence(incident)
verdict = investigate(evidence)
duration = time.perf_counter() - start

if verdict:
    print(f"Investigation completed in {duration:.2f} seconds.")
    print(f"Summary: {verdict.summary[:100]}...")
else:
    print(f"Investigation returned None after {duration:.2f} seconds (Ollama unreachable or error).")