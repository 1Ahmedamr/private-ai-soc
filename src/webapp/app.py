# src/webapp/app.py

import uuid
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
from flask import Flask, render_template, abort, request, Response, session, jsonify


DB_PATH = "data/processed/soc_incidents.db"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())
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
    os.remove(save_path)
    session["last_analysis"] = result.to_session_dict()
    session["chat_history"] = []
    return render_template("analyze_results.html", result=result)

@app.route("/chat", methods=["POST"])
@require_auth
def chat():
    """
    Multi-turn chat endpoint. Each request receives:
    - The user's new question
    - The full conversation history so far (from session)
    - The structured analysis context (from session)

    Returns a JSON response with the AI's answer.
    The AI never sees raw log content - only the structured
    incident evidence, same as the investigation layer.
    """
    if "last_analysis" not in session:
        return jsonify({"error": "No analysis context found. Please upload a file first."}), 400

    data = request.get_json()
    if not data or "question" not in data:
        return jsonify({"error": "No question provided."}), 400

    question = data["question"].strip()
    if not question:
        return jsonify({"error": "Empty question."}), 400

    analysis = session["last_analysis"]
    chat_history = session.get("chat_history", [])

    # Build context from structured incident data ONLY
    context_parts = [
        f"File analyzed: {analysis['filename']}",
        f"Format: {analysis['format_detected']}",
        f"Events parsed: {analysis['events_parsed']}",
        f"Incidents found: {len(analysis['incidents'])}",
    ]

    for inc in analysis["incidents"]:
        context_parts.append(
            f"\nIncident: {inc['title']} | Severity: {inc['severity']} | "
            f"Risk: {inc['risk_score']}/100 | Identity: {inc['correlation_key']} | "
            f"MITRE: {', '.join(inc['mitre_techniques'])} | "
            f"First seen: {inc['first_seen']} | Last seen: {inc['last_seen']}"
        )
        for d in inc["detections"]:
            context_parts.append(f"  Detection: {d['rule_name']} - {d['description']}")

        if inc.get("key_events"):
            context_parts.append(f"  Raw events ({len(inc['key_events'])} shown):")
            for e in inc["key_events"]:
                parts = []
                if e.get("timestamp"): parts.append(f"time={e['timestamp']}")
                if e.get("src_ip"): parts.append(f"src_ip={e['src_ip']}")
                if e.get("dst_ip"): parts.append(f"dst_ip={e['dst_ip']}")
                if e.get("user"): parts.append(f"user={e['user']}")
                if e.get("host"): parts.append(f"host={e['host']}")
                if e.get("status"): parts.append(f"status={e['status']}")
                context_parts.append(f"    event: {' | '.join(parts)}")

    context = "\n".join(context_parts)

    # Build conversation history for multi-turn
    history_text = ""
    if chat_history:
        history_text = "\n\nPrevious conversation:\n"
        for turn in chat_history[-6:]:  # last 6 turns max to avoid context overflow
            history_text += f"Analyst: {turn['question']}\nAI: {turn['answer']}\n"

    system_prompt = f"""You are a SOC analyst assistant helping investigate a specific security incident.
You have access to the structured analysis results below. Answer the analyst's questions
based ONLY on this data. Be specific, concise, and actionable.
Do not invent data that isn't in the analysis. If you don't know something from the
available data, say so clearly rather than guessing.

ANALYSIS CONTEXT:
{context}
{history_text}"""

    full_prompt = f"{system_prompt}\n\nAnalyst question: {question}\n\nAnswer:"

    try:
        import requests as req
        OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        response = req.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": "qwen3:8b", "prompt": full_prompt, "stream": False},
            timeout=60,
        )
        response.raise_for_status()
        answer = response.json()["response"].strip()
    except Exception as e:
        return jsonify({"error": f"AI unavailable: {str(e)[:100]}"}), 503

    # Store in session for multi-turn continuity
    chat_history.append({"question": question, "answer": answer})
    session["chat_history"] = chat_history
    session.modified = True

    return jsonify({"answer": answer, "turn": len(chat_history)})


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True, port=5001)