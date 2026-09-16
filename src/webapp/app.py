# src/webapp/app.py

import os
import secrets
from functools import wraps
from flask import request, Response
from flask import Flask, render_template, abort
from src.incidents.store import IncidentStore
from src.models.incident_schema import IncidentStatus

DB_PATH = "data/processed/soc_incidents.db"

app = Flask(__name__)
# Credentials come from environment variables, never hardcoded - this
# is the same principle as .env being gitignored from Day 1. Falls
# back to a default ONLY for local dev convenience; INSTALLATION.md
# will document setting real values for anyone actually deploying this.
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "analyst")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "changeme")


def check_credentials(username: str, password: str) -> bool:
    """
    Uses secrets.compare_digest instead of a plain == comparison.
    Why does this matter? A naive `password == DASHBOARD_PASSWORD`
    comparison exits as soon as the first mismatched character is
    found - which means comparing a WRONG password takes slightly less
    time than comparing a password that matches the first few
    characters. This timing difference is measurable and is a REAL,
    named attack class (timing attack) used to guess passwords
    character-by-character. compare_digest runs in constant time
    regardless of where the mismatch occurs, closing that channel.
    """
    return secrets.compare_digest(username, DASHBOARD_USERNAME) and secrets.compare_digest(password, DASHBOARD_PASSWORD)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_credentials(auth.username, auth.password):
            return Response(
                "Authentication required.", 401,
                {"WWW-Authenticate": 'Basic realm="Private AI SOC Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated


def get_store() -> IncidentStore:
    """
    Why a fresh IncidentStore() per request instead of one global
    connection? SQLite connections aren't safely shared across Flask's
    threaded request handling by default. A cheap per-request connection
    avoids a whole class of "database is locked" bugs - the same
    concurrency lesson from the SQLite-vs-Postgres discussion, applied
    here at the web layer instead of the ingestion layer.
    """
    return IncidentStore(DB_PATH)


@app.route("/")
@require_auth
def index():
    store = get_store()
    incidents = [
        i for i in store.get_all()
        if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
    ]
    incidents.sort(key=lambda i: i.risk_score, reverse=True)
    return render_template("index.html", incidents=incidents, total=len(store.get_all()))


@app.route("/incident/<incident_id>")
@require_auth
def incident_detail(incident_id):
    store = get_store()
    incident = store.get_by_id(incident_id)
    if not incident:
        abort(404)
    return render_template("detail.html", incident=incident)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True, port=5001)