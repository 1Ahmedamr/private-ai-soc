# src/webapp/app.py

from flask import Flask, render_template, abort
from src.incidents.store import IncidentStore
from src.models.incident_schema import IncidentStatus

DB_PATH = "data/processed/soc_incidents.db"

app = Flask(__name__)


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
def index():
    store = get_store()
    incidents = [
        i for i in store.get_all()
        if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
    ]
    incidents.sort(key=lambda i: i.risk_score, reverse=True)
    return render_template("index.html", incidents=incidents, total=len(store.get_all()))


@app.route("/incident/<incident_id>")
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