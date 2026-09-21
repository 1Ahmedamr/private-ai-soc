# src/webapp/app.py

import os
import uuid
from pathlib import Path
from functools import wraps
import secrets

from flask import Flask, render_template, abort, request, Response, session, jsonify
from werkzeug.utils import secure_filename

from src.incidents.store import IncidentStore
from src.models.incident_schema import IncidentStatus
from src.dashboard.timeline import build_timeline_entries
from src.pipeline.file_analyzer import analyze_file

DB_PATH = "data/processed/soc_incidents.db"
UPLOAD_FOLDER = "data/uploads"
ALLOWED_EXTENSIONS = {".json", ".log", ".txt", ".pcap", ".pcapng", ".cap"}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "analyst")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "changeme")


def check_credentials(username: str, password: str) -> bool:
    return (
        secrets.compare_digest(username, DASHBOARD_USERNAME)
        and secrets.compare_digest(password, DASHBOARD_PASSWORD)
    )


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
    timeline = build_timeline_entries(incident)
    return render_template("detail.html", incident=incident, timeline=timeline)


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
        return render_template("analyze.html", error=f"File type '{ext}' not supported.")
    filename = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)
    result = analyze_file(save_path, file.filename)
    try:
        os.remove(save_path)
    except FileNotFoundError:
        pass
    session["last_analysis"] = result.to_session_dict()
    session["chat_history"] = []
    return render_template("analyze_results.html", result=result)


@app.route("/chat", methods=["POST"])
@require_auth
def chat():
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
            f"MITRE: {', '.join(inc['mitre_techniques'])}"
        )
        context_parts.append(
            f"  Exact timestamps (use verbatim): "
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
                if e.get("status"): parts.append(f"status={e['status']}")
                context_parts.append(f"    event: {' | '.join(parts)}")
        if inc["incident_id"] in analysis["ai_summaries"]:
            summary = analysis["ai_summaries"][inc["incident_id"]]
            context_parts.append(f"  AI Summary: {summary['summary']}")
            context_parts.append(f"  Attack Stage: {summary['likely_attack_stage']}")
            context_parts.append(f"  Remediation: {'; '.join(summary['recommended_actions'])}")

    context = "\n".join(context_parts)
    history_text = ""
    if chat_history:
        history_text = "\n\nPrevious conversation:\n"
        for turn in chat_history[-6:]:
            history_text += f"Analyst: {turn['question']}\nAI: {turn['answer']}\n"

    system_prompt = f"""You are a SOC analyst assistant. Your answers must follow this exact structure:

**OBSERVED FACTS** (only what the evidence explicitly states):
- State what signatures matched, how many times, between which IPs
- State exact timestamps from the evidence verbatim
- State packet counts and port counts from the evidence

**POSSIBLE INTERPRETATION** (clearly labeled as hypothesis, not fact):
- What this activity MIGHT indicate
- What additional evidence would confirm or deny the hypothesis

**RECOMMENDED ACTIONS** (specific, actionable):
- What to investigate next

HARD RULES — violation is a serious error:
- NEVER say "attacker" — say "source host" or "source IP"
- NEVER say "compromised" or "persistence achieved" or "exfiltration" from IDS signatures alone
- NEVER say "DLL specifically" when the rule says "EXE or DLL" — copy the rule name exactly
- NEVER combine separate incidents into a confirmed attack chain — say "may be related, requires investigation"
- ET MALWARE = "traffic matched a malware-related signature" NOT "malware confirmed"
- ET INFO = "informational signature" NOT malicious without additional evidence
- Suricata firing N times = "signature matched N times" NOT "N attacks occurred"
- Attack Stage for ET MALWARE with no other evidence = "Suspected C2 / Requires Investigation" NOT "Compromise"
- Copy timestamps EXACTLY character-for-character from evidence
- NEVER invent specific details not present in the evidence above — no beacon
  intervals, no payload contents, no timing patterns, no packet contents —
  unless that exact detail appears in the ANALYSIS CONTEXT. If asked about
  something not in the evidence, say "not available in the current evidence"
- NEVER recommend isolating a host, blocking an IP, or other containment
  actions as if they are the confirmed next step. A single signature match
  is not sufficient justification for containment. Recommended Actions must
  distinguish "Containment: not recommended yet — validate the alert first"
  from "Next steps: review traffic, check endpoint telemetry" — do not
  recommend containment unless the evidence shows corroborating signals
  beyond a single detection

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
            timeout=120,
        )
        response.raise_for_status()
        answer = response.json()["response"].strip()
    except Exception as e:
        return jsonify({"error": f"AI unavailable: {str(e)[:100]}"}), 503

    chat_history.append({"question": question, "answer": answer})
    session["chat_history"] = chat_history
    session.modified = True
    return jsonify({"answer": answer, "turn": len(chat_history)})


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True, port=5001)
