# Benchmark

## Methodology
Numbers below come directly from tests/scenarios/run_scenarios.py,
reproducible by running `python -m tests.scenarios.run_scenarios`.
No numbers here are estimated or fabricated.

## Detection coverage & accuracy
SCENARIO                      STATUS            TIME (ms)   
------------------------------------------------------------
Brute Force                   PASS              5979.01     
PowerShell Execution          NOT IMPLEMENTED   -           
Suspicious DNS                NOT IMPLEMENTED   -           
Port Scanning                 PASS              0.86        
Possible C2                   NOT IMPLEMENTED   -           
Credential Attack (SSH Root)  PASS              10304.8     
Benign Activity               PASS              0.44        
------------------------------------------------------------
Coverage: 4/7 roadmap scenarios implemented
Accuracy: 4/4 implemented scenarios behave correctly


## What this does NOT measure
This measures THIS system's internal detection latency and accuracy
against known synthetic scenarios. It is not a comparison against a
staffed traditional SOC's manual triage time, since no such SOC is
operated as part of this project. Any "traditional SOC" comparison
figures would need to cite external, published sources (e.g. industry
incident-response time reports) rather than be presented as measured -
see docs/ROADMAP.md Phase 20 for this open, honestly-unfinished item.