# tests/conftest.py
import os

# The dashboard refuses to start without a real password. Tests supply their own, so
# they never depend on a developer's .env and behave the same in a fresh clone.
os.environ["DASHBOARD_PASSWORD"] = "unit-test-password-not-for-real-use"
