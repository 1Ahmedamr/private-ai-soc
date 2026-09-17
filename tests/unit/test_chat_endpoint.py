# tests/unit/test_chat_endpoint.py

import pytest
from src.webapp.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"
    with app.test_client() as client:
        yield client


def auth_header():
    import base64
    from src.webapp.app import DASHBOARD_USERNAME, DASHBOARD_PASSWORD
    creds = f"{DASHBOARD_USERNAME}:{DASHBOARD_PASSWORD}"
    encoded = base64.b64encode(creds.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def test_chat_without_session_returns_400(client):
    """No uploaded file = no session context = should refuse the chat request."""
    response = client.post(
        "/chat",
        json={"question": "What happened?"},
        headers=auth_header(),
    )
    assert response.status_code == 400
    assert "No analysis context" in response.get_json()["error"]


def test_chat_without_auth_returns_401(client):
    response = client.post("/chat", json={"question": "test"})
    assert response.status_code == 401


def test_chat_with_empty_question_returns_400(client):
    with client.session_transaction() as sess:
        sess["last_analysis"] = {
            "filename": "test.json", "format_detected": "windows_json",
            "events_parsed": 6, "incidents": [], "ai_summaries": {},
            "errors": [], "parse_warning": None,
        }
    response = client.post(
        "/chat",
        json={"question": "   "},
        headers=auth_header(),
    )
    assert response.status_code == 400


def test_analyze_page_loads_with_auth(client):
    response = client.get("/analyze", headers=auth_header())
    assert response.status_code == 200
    assert b"Analyze" in response.data