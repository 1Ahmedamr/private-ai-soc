# src/webapp/app.py

import os
import secrets
from functools import wraps
from pathlib import Path
from flask import request, Response
from flask import Flask, render_template, abort
from src.incidents.store import IncidentStore
from src.models.incident_schema import IncidentStatus
from src.dashboard.timeline import build_timeline_entries
from werkzeug.utils import secure_filename
from src.pipeline.file_analyzer import analyze_file

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


UPLOAD_FOLDER = "data/uploads"
ALLOWED_EXTENSIONS = {".json", ".log", ".txt", ".pcap", ".pcapng", ".cap"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/analyze", methods=["GET"])
@require_auth
def analyze_page():
    return render_template("analyze.html")


@app.route("/analyze", methods=["POST"])
@require_auth
def analyze_upload():
    if "logfile" not in request.files:
        return render_template("analyze.html", error="No file uploaded.")

    file = request.files["logfile"]
    if not file.filename:
        return render_template("analyze.html", error="No file selected.")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return render_template(
            "analyze.html",
            error=f"File type '{ext}' not supported. Supported: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    filename = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    result = analyze_file(save_path, file.filename)
    os.remove(save_path)  # don't persist uploads - privacy principle

    return render_template("analyze_results.html", result=result)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True, port=5001)