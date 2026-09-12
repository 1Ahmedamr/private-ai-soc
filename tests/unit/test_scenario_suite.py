# tests/unit/test_scenario_suite.py

from tests.scenarios.run_scenarios import run_all_scenarios


def test_all_implemented_scenarios_pass():
    results = run_all_scenarios()
    implemented = [r for r in results if r["passed"] is not None]

    failures = [r["name"] for r in implemented if not r["passed"]]
    assert not failures, f"Scenario regressions detected: {failures}"


def test_benign_activity_never_creates_a_false_positive_incident():
    """The single most important test in this file - explicit,
    isolated proof that normal activity does not create noise."""
    results = run_all_scenarios()
    benign = next(r for r in results if r["name"] == "Benign Activity")
    assert benign["passed"] is True
    assert benign["incidents_created"] == 0