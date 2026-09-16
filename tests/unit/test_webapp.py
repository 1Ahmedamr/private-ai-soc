# tests/unit/test_webapp.py

import base64
import pytest
from src.webapp.app import app, DASHBOARD_USERNAME, DASHBOARD_PASSWORD


def auth_header():
    """Builds a valid Basic Auth header using the test client's known credentials."""
    creds = f"{DASHBOARD_USERNAME}:{DASHBOARD_PASSWORD}"
    encoded = base64.b64encode(creds.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_requires_authentication(client):
    """The actual security proof: no credentials means no access."""
    response = client.get("/")
    assert response.status_code == 401


def test_index_returns_200_with_valid_credentials(client):
    response = client.get("/", headers=auth_header())
    assert response.status_code == 200


def test_index_rejects_wrong_password(client):
    creds = f"{DASHBOARD_USERNAME}:wrongpassword"
    encoded = base64.b64encode(creds.encode()).decode()
    response = client.get("/", headers={"Authorization": f"Basic {encoded}"})
    assert response.status_code == 401


def test_unknown_incident_returns_404_when_authenticated(client):
    response = client.get("/incident/INC-DOESNOTEXIST", headers=auth_header())
    assert response.status_code == 404


def test_unknown_incident_requires_auth_before_404(client):
    """
    Important distinction: an unauthenticated request should get 401,
    NOT 404 - otherwise an attacker could probe which incident IDs
    exist just by watching for 401 vs 404, without ever authenticating.
    """
    response = client.get("/incident/INC-DOESNOTEXIST")
    assert response.status_code == 401