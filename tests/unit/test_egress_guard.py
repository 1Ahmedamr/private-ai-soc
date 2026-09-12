# tests/unit/test_egress_guard.py

import pytest
from unittest.mock import patch
from datetime import datetime
from src.security.egress_guard import block_external_network, UnexpectedNetworkAccessError
from src.models.incident_schema import Incident, IncidentPriority
from src.models.event_schema import Severity
from src.ai.evidence import build_evidence
from src.ai.ollama_client import investigate


def test_guard_blocks_non_localhost_connections():
    """Sanity check on the guard mechanism itself, before trusting it
    to protect the real pipeline."""
    import socket
    with block_external_network():
        with pytest.raises(UnexpectedNetworkAccessError):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("8.8.8.8", 53))  # Google DNS - a real external host


def test_guard_allows_localhost_connections():
    """The guard must not break legitimate local calls (Ollama, Postgres)."""
    import socket
    with block_external_network():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", 1))  # will fail to actually connect (nothing listening) - that's fine, we're only testing the GUARD allows the attempt through
        except (ConnectionRefusedError, OSError):
            pass  # expected - port 1 isn't listening; the point is it wasn't BLOCKED by the guard


def test_ollama_client_never_calls_external_hosts():
    """
    THE actual proof for the project's core claim: running a full AI
    investigation call, with the egress guard active, must not attempt
    to reach anywhere except localhost. If ollama_client.py is ever
    changed to call a cloud API, this test fails immediately.
    """
    incident = Incident(
        title="Test", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key="user:admin", first_seen=datetime.now(), last_seen=datetime.now(),
    )
    evidence = build_evidence(incident)

    with block_external_network():
        # We don't care if Ollama is actually running for this test -
        # we care that if it DOES try to connect, it's only ever to
        # localhost. A ConnectionRefusedError to 127.0.0.1 is fine and
        # expected in CI; an UnexpectedNetworkAccessError is the failure
        # we're actually testing against.
        try:
            investigate(evidence)
        except UnexpectedNetworkAccessError:
            pytest.fail("ollama_client.py attempted to reach a non-localhost host!")