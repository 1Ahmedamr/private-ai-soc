# tests/scenarios/run_scenarios.py

import time
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator
from tests.scenarios.scenario_definitions import ALL_SCENARIOS


def run_all_scenarios():
    results = []

    for scenario_fn in ALL_SCENARIOS:
        scenario = scenario_fn()

        if scenario.get("not_implemented"):
            results.append({**scenario, "status": "NOT IMPLEMENTED", "passed": None, "duration_ms": None})
            continue

        orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), AssetInventory())

        start = time.perf_counter()
        incidents = orchestrator.ingest(scenario["events"])
        duration_ms = (time.perf_counter() - start) * 1000

        incident_created = len(incidents) > 0
        passed = incident_created == scenario["expect_incident"]

        if passed and scenario.get("expect_rule") and incidents:
            rule_names = [d.rule_name for d in incidents[0].detections]
            passed = scenario["expect_rule"] in rule_names

        results.append({
            **scenario,
            "status": "PASS" if passed else "FAIL",
            "passed": passed,
            "duration_ms": round(duration_ms, 2),
            "incidents_created": len(incidents),
        })

    return results


def print_report(results):
    print(f"{'SCENARIO':<30}{'STATUS':<18}{'TIME (ms)':<12}")
    print("-" * 60)
    for r in results:
        time_str = f"{r['duration_ms']}" if r["duration_ms"] is not None else "-"
        print(f"{r['name']:<30}{r['status']:<18}{time_str:<12}")

    implemented = [r for r in results if r["passed"] is not None]
    passed_count = sum(1 for r in implemented if r["passed"])

    print("-" * 60)
    print(f"Coverage: {len(implemented)}/{len(results)} roadmap scenarios implemented")
    print(f"Accuracy: {passed_count}/{len(implemented)} implemented scenarios behave correctly")


if __name__ == "__main__":
    print_report(run_all_scenarios())