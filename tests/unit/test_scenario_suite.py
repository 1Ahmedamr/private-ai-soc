# tests/unit/test_scenario_suite.py
"""Scenario regression suite: detection and incident logic, run offline.

AI investigation is switched off here on purpose. It adds a slow call to a local LLM
(about 17 seconds per incident) and none of the scenarios assert on its output. It has its
own tests: test_orchestrator_auto_investigate.py and test_ai_investigation.py.
"""

import socket

import pytest

from src.pipeline.orchestrator import PipelineOrchestrator
from tests.scenarios.run_scenarios import run_all_scenarios


@pytest.fixture(scope="module")
def scenario_run():
    """Runs every scenario once for the whole module, with the network and the LLM off."""
    attempts = []

    def refuse_connect(self, address):
        attempts.append(address)
        raise ConnectionRefusedError("network is off during scenario tests")

    patcher = pytest.MonkeyPatch()
    patcher.setattr(socket.socket, "connect", refuse_connect)
    patcher.setattr(PipelineOrchestrator, "investigate_incident", lambda self, incident, store: None)
    try:
        results = run_all_scenarios()
    finally:
        patcher.undo()
    return results, attempts


def test_all_implemented_scenarios_pass(scenario_run):
    results, _ = scenario_run
    implemented = [r for r in results if r["passed"] is not None]

    failures = [r["name"] for r in implemented if not r["passed"]]
    assert not failures, f"Scenario regressions detected: {failures}"


def test_benign_activity_never_creates_a_false_positive_incident(scenario_run):
    """The single most important test in this file - explicit,
    isolated proof that normal activity does not create noise."""
    results, _ = scenario_run
    benign = next(r for r in results if r["name"] == "Benign Activity")
    assert benign["passed"] is True
    assert benign["incidents_created"] == 0


def test_scenarios_never_touch_the_network(scenario_run):
    """Detection and incident logic must not depend on a model server or the internet."""
    _, attempts = scenario_run
    assert attempts == [], f"scenarios tried to connect to: {attempts[:3]}"
