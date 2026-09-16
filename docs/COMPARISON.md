# Traditional SOC vs. Private AI SOC — Honest Comparison

## Methodology
This document distinguishes MEASURED figures (from this project's own
test suite, fully reproducible via `python -m tests.scenarios.run_scenarios`)
from CITED figures (published industry data, sourced in
COMPARISON_SOURCES.md). No number here is estimated or invented.

## Measured: This System's Detection Pipeline

| Scenario | Detection Time (ms) | Accuracy |
|---|---|---|
[paste the real table from tests.scenarios.run_scenarios here]

These numbers reflect DETECTION LATENCY ONLY - from normalized event
to correlated incident. They do NOT include AI investigation time
(which depends on local hardware and model size - see below).

## Measured: AI Investigation Latency
A single end-to-end AI investigation call (evidence construction +
local Qwen3:8b inference via Ollama + response parsing) took 17.18
seconds on the development machine (Apple Silicon, local Ollama).
Reproducible via `python -m scripts.benchmark_ai_investigation`.

This is NOT comparable to human analyst triage time in any direct
sense - it reflects local model inference speed on consumer hardware,
which varies significantly by machine and model size. A smaller
quantized model would be faster; a larger model would be slower and
potentially more accurate. This number exists to be transparent about
system behavior, not to make a speed claim against anything else.

## Cited: Industry Context (NOT measured by this project)
See COMPARISON_SOURCES.md for full citations.

- [Cited figure 1, e.g. average manual alert triage time]
- [Cited figure 2, e.g. average breach identification time]

## What This Comparison Does NOT Claim
- This project has never been deployed in a real production SOC
- The cited industry figures describe DIFFERENT organizations, tools,
  and attack types than our own synthetic test scenarios - they are
  context, not a controlled experiment
- "Faster than industry average" is NOT a claim this document makes,
  because our scenarios are synthetic and simplified compared to real-
  world alert volume and complexity