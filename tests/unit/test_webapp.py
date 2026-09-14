# tests/unit/test_webapp.py

import pytest
from src.webapp.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200


def test_unknown_incident_returns_404(client):
    response = client.get("/incident/INC-DOESNOTEXIST")
    assert response.status_code == 404