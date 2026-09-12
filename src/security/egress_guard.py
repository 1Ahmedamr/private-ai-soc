 # src/security/egress_guard.py

import socket
from contextlib import contextmanager

# Localhost is where Ollama and Postgres/SQLite live. Anything else
# means data is about to leave the machine - which contradicts the
# entire "private" promise of this project.
_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


class UnexpectedNetworkAccessError(Exception):
    """Raised when code attempts to connect to a non-localhost address
    while the egress guard is active."""


@contextmanager
def block_external_network():
    """
    Monkey-patches socket.socket.connect for the duration of the
    context, raising instead of allowing any connection to a host
    outside _ALLOWED_HOSTS. This is a TEST-TIME safety net, not a
    production firewall - its purpose is to catch an accidental
    external API call (e.g. someone pastes in an OpenAI client by
    habit) during development, before it ships.
    """
    original_connect = socket.socket.connect

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in _ALLOWED_HOSTS:
            raise UnexpectedNetworkAccessError(
                f"Blocked outbound connection attempt to '{host}'. "
                f"This project's core promise is that telemetry never "
                f"leaves the local machine. If this is intentional, "
                f"update _ALLOWED_HOSTS in egress_guard.py explicitly - "
                f"never silently allow new outbound hosts."
            )
        return original_connect(self, address)

    socket.socket.connect = guarded_connect
    try:
        yield
    finally:
        socket.socket.connect = original_connect