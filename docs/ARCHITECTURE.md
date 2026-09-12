# Architecture

## Pipeline
Raw Log/Event
   -> Ingestion (src/ingestion/*_parser.py) - source-specific parsers
   -> Normalization (src/models/event_schema.py) - common schema, all sources converge here
   -> Detection Engine (src/detection/engine.py) - deterministic rules only, no AI
   -> Incident Engine (src/incidents/engine.py) - dedup, reopen windows, correlation
   -> Risk Scoring (src/risk/scoring.py) - severity + confidence + evidence + asset criticality
   -> [optional, threshold-gated] AI Investigation (src/ai/) - advisory summary + MITRE context, never overrides severity/risk

## Key design decisions (and why)
- **One common event schema, many parsers**: adding a new log source
  (e.g. Suricata) means writing ONE parser function - detection,
  correlation, and risk scoring require zero changes. Proven concretely
  across Windows/Linux/Zeek sources with no shared-engine modifications.
- **AI never decides severity**: severity/risk are deterministic,
  computed before the AI is ever invoked. The AI receives a stripped
  evidence contract (src/ai/evidence.py) - never raw log data - which
  also closes the prompt-injection vector (attacker-controlled log text
  never reaches the LLM).
- **Repository Pattern for storage**: EventStore/IncidentStore have
  identical interfaces whether backed by SQLite or PostgreSQL - proven
  by swapping backends without touching PipelineOrchestrator.
- **Reopen windows are per-rule, not global**: a brute force incident
  and a hypothetical slow C2 beacon warrant very different "how long
  after closing can this reopen" policies - reflects real attacker
  behavior differences, not an arbitrary constant.

## Data flow diagram
[Windows/Linux/Zeek logs] -> [Parsers] -> [NormalizedEvent] -> [EventStore (persisted)]
                                                              -> [DetectionEngine] -> [DetectionResult]
                                                              -> [IncidentEngine] -> [Incident] -> [IncidentStore (persisted)]
                                                                                   -> [AI Investigation, if risk >= threshold]
                                                                                   -> [CLI Dashboard]