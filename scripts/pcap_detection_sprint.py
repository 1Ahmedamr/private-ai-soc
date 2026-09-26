#!/usr/bin/env python3
"""
Real-world PCAP detection sprint.
Runs each PCAP through the full pipeline and measures detection coverage.
Honest output — reports what was found and what was missed, not just wins.
"""

import os
import time
import json
from pathlib import Path
from src.pipeline.pcap_processor import process_pcap
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

PCAP_DIR = Path("data/pcaps/malware_samples")
RESULTS = []


def analyze_pcap(pcap_path: str) -> dict:
    print(f"\n{'='*60}")
    print(f"Analyzing: {Path(pcap_path).name}")
    print(f"{'='*60}")

    start = time.time()
    try:
        events = process_pcap(pcap_path)
        orchestrator = PipelineOrchestrator(
            EventStore(), IncidentStore(), AssetInventory()
        )
        incidents = orchestrator.ingest_pcap(pcap_path)
        elapsed = time.time() - start

        print(f"Events: {len(events)} | Time: {elapsed:.1f}s | Incidents: {len(incidents)}")

        severities = {}
        all_rules = []
        for inc in incidents:
            sev = inc.severity
            severities[sev] = severities.get(sev, 0) + 1
            for d in inc.detections:
                all_rules.append(d.rule_name)
            print(f"  [{inc.severity.upper()}] {inc.title} | risk={inc.risk_score}")

        sigma_count = len([r for r in all_rules if "[Sigma]" in r])
        ioc_count = len([r for r in all_rules if "IOC" in r])

        return {
            "file": Path(pcap_path).name,
            "events": len(events),
            "incidents": len(incidents),
            "time_seconds": round(elapsed, 1),
            "severities": severities,
            "sigma_rules_fired": sigma_count,
            "ioc_matches": ioc_count,
            "all_rules": list(set(all_rules)),
            "error": None,
        }

    except Exception as e:
        elapsed = time.time() - start
        print(f"ERROR after {elapsed:.1f}s: {e}")
        return {
            "file": Path(pcap_path).name,
            "events": 0,
            "incidents": 0,
            "time_seconds": round(elapsed, 1),
            "error": str(e),
        }


# Find all PCAPs
pcap_files = []
for ext in ("*.pcap", "*.pcapng", "*.cap"):
    pcap_files.extend(PCAP_DIR.rglob(ext))

# Also check top-level pcaps dir for ones you already have
top_pcaps = list(Path("data/pcaps").glob("*.pcap"))
pcap_files.extend(top_pcaps)

if not pcap_files:
    print("No PCAP files found. Add PCAPs to data/pcaps/malware_samples/")
    exit(0)

print(f"Found {len(pcap_files)} PCAP files to analyze")

for pcap in sorted(pcap_files)[:10]:  # cap at 10 to avoid hour-long runs
    result = analyze_pcap(str(pcap))
    RESULTS.append(result)

# Summary report
print(f"\n\n{'='*60}")
print("DETECTION SPRINT SUMMARY")
print(f"{'='*60}")
print(f"{'File':<40} {'Events':>8} {'Incidents':>10} {'Time':>6} {'Sigma':>6} {'IOC':>5}")
print("-" * 80)
for r in RESULTS:
    if r.get("error"):
        print(f"{r['file']:<40} ERROR: {r['error'][:30]}")
    else:
        print(f"{r['file']:<40} {r['events']:>8} {r['incidents']:>10} "
              f"{r['time_seconds']:>5.1f}s {r['sigma_rules_fired']:>6} {r['ioc_matches']:>5}")

total_incidents = sum(r.get("incidents", 0) for r in RESULTS)
total_errors = sum(1 for r in RESULTS if r.get("error"))
print(f"\nTotal: {len(RESULTS)} files | {total_incidents} incidents | {total_errors} errors")

# Save results for analysis
with open("data/processed/sprint_results.json", "w") as f:
    json.dump(RESULTS, f, indent=2)
print(f"\nFull results saved to data/processed/sprint_results.json")
