# tests/unit/test_dashboard_auth.py
"""The dashboard fails closed: no default password, no crash on odd credentials,
and every route behind authentication."""

import base64
import re

import pytest

import src.webapp.app as webapp


def basic(user, password):
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode()
    return {"Authorization": f"Basic {token}"}


def test_missing_password_refuses_to_start():
    with pytest.raises(RuntimeError):
        webapp.load_dashboard_password(None)


@pytest.mark.parametrize("bad", ["", "   ", "changeme", "ChangeMe"])
def test_empty_or_default_password_is_rejected(bad):
    with pytest.raises(RuntimeError):
        webapp.load_dashboard_password(bad)


def test_real_password_is_accepted():
    assert webapp.load_dashboard_password("a-long-random-value") == "a-long-random-value"


def test_correct_credentials_still_work():
    assert webapp.check_credentials(webapp.DASHBOARD_USERNAME, webapp.DASHBOARD_PASSWORD) is True


def test_non_ascii_credentials_are_rejected_without_crashing():
    assert webapp.check_credentials("analÿst", "pässword") is False


def test_non_ascii_login_gets_401_not_500():
    resp = webapp.app.test_client().get("/", headers=basic("analÿst", "pässword"))
    assert resp.status_code == 401


def test_every_route_requires_authentication():
    client = webapp.app.test_client()
    checked = 0
    for rule in webapp.app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        path = re.sub(r"<[^>]+>", "x", rule.rule)
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            assert client.open(path, method=method).status_code == 401, f"{method} {rule.rule} is open"
            checked += 1
    assert checked >= 9
