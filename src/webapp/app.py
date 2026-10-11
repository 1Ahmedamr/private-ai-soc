# src/webapp/app.py

import os
import uuid
from pathlib import Path
from functools import wraps
import secrets
from flask import Flask, render_template, abort, request, Response, session, jsonify
from werkzeug.utils import secure_filename
from src.detection.rule_analytics import get_rule_stats
from src.incidents.store import IncidentStore
from src.models.incident_schema import IncidentStatus
from src.dashboard.timeline import build_timeline_entries
from src.pipeline.file_analyzer import analyze_file
from src.webapp.analysis_store import save_analysis, load_analysis, save_chat_history

from dotenv import load_dotenv
load_dotenv()



DB_PATH = "data/processed/soc_incidents.db"
UPLOAD_FOLDER = "data/uploads"
ALLOWED_EXTENSIONS = {".json", ".log", ".txt", ".pcap", ".pcapng", ".cap", ".xlsx", ".xlsm", ".xls"}

app = Flask(__name__)
# Secret key must be STABLE across restarts — os.urandom() changes on
# every restart/reload, invalidating all sessions. Use .env or a fixed fallback.
_secret = os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    _secret_file = ".flask_secret"
    try:
        _secret = open(_secret_file).read().strip()
    except FileNotFoundError:
        import secrets as _sec
        _secret = _sec.token_hex(32)
        open(_secret_file, "w").write(_secret)
app.secret_key = _secret
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "analyst")
_REJECTED_PASSWORDS = {"", "changeme"}


def load_dashboard_password(value):
    """The dashboard has no default password: it refuses to start without a real one.
    A printed warning is easy to miss; a startup failure is not."""
    if value is None or value.strip().lower() in _REJECTED_PASSWORDS:
        raise RuntimeError(
            "DASHBOARD_PASSWORD is not set (or is the old default 'changeme'). "
            "Set a real password in .env or the environment before starting the dashboard. "
            "See .env.example."
        )
    return value


DASHBOARD_PASSWORD = load_dashboard_password(os.environ.get("DASHBOARD_PASSWORD"))


def check_credentials(username: str, password: str) -> bool:
    # Compare bytes: compare_digest raises TypeError on non-ASCII str, which would
    # turn a bad login into a 500. Run both comparisons so a wrong username does
    # not answer faster than a wrong password.
    user_ok = secrets.compare_digest((username or "").encode("utf-8"), DASHBOARD_USERNAME.encode("utf-8"))
    pass_ok = secrets.compare_digest((password or "").encode("utf-8"), DASHBOARD_PASSWORD.encode("utf-8"))
    return user_ok and pass_ok


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


def current_analysis():
    """Analysis lives server-side (cookie holds only an id); falls back to
    a legacy in-cookie analysis if present."""
    stored = load_analysis(session.get("analysis_id"))
    if stored:
        return stored["analysis"]
    return session.get("last_analysis")


def current_chat_history():
    stored = load_analysis(session.get("analysis_id"))
    if stored:
        return stored["chat_history"]
    return session.get("chat_history", [])


def store_chat_history(history):
    if load_analysis(session.get("analysis_id")):
        save_chat_history(session["analysis_id"], history)
    else:
        session["chat_history"] = history
        session.modified = True


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
    session.pop("last_analysis", None)
    session.pop("chat_history", None)
    session["analysis_id"] = save_analysis(result.to_session_dict())
    return render_template("analyze_results.html", result=result)


@app.route("/chat", methods=["POST"])
@require_auth
def chat():
    analysis = current_analysis()
    if analysis is None:
        return jsonify({
            "error": "Session expired — please re-upload your file to restore the analysis context.",
            "session_expired": True
        }), 400
    data = request.get_json()
    if not data or "question" not in data:
        return jsonify({"error": "No question provided."}), 400
    question = data["question"].strip()
    if not question:
        return jsonify({"error": "Empty question."}), 400

    import re as _re
    if _re.search(r"\b5\s*w'?s?\b|triage summary", question, _re.I):
        from src.ai.fivew import answer_5w
        answer = answer_5w(analysis, question)
        history = current_chat_history()
        history.append({"question": question, "answer": answer})
        store_chat_history(history)
        return jsonify({"answer": answer, "turn": len(history)})
    chat_history = current_chat_history()

    context_parts = [
        f"File analyzed: {analysis['filename']}",
        f"Format: {analysis['format_detected']}",
        f"Events parsed: {analysis['events_parsed']}",
        f"Incidents found: {len(analysis['incidents'])}",
    ]
    guard_evidence = []  # detection text only, used to check the model's claims

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
            guard_evidence.append(f"{d['rule_name']} {d['description']}")
        if inc.get("key_events"):
            context_parts.append(f"  Raw events ({len(inc['key_events'])} shown):")
            for e in inc["key_events"]:
                parts = []
                if e.get("timestamp"): parts.append(f"time={e['timestamp']}")
                if e.get("src_ip"): parts.append(f"src_ip={e['src_ip']}")
                if e.get("dst_ip"): parts.append(f"dst_ip={e['dst_ip']}")
                if e.get("event_id"): parts.append(f"event_id={e['event_id']}")
                if e.get("host"): parts.append(f"host={e['host']}")
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
- State which detections fired (rule names), how many times, and the hosts, users and IPs involved
- State exact timestamps from the evidence verbatim
- State packet counts and port counts only if the evidence contains them

**POSSIBLE INTERPRETATION** (clearly labeled as hypothesis, not fact):
- What this activity MIGHT indicate
- What additional evidence would confirm or deny the hypothesis

**RECOMMENDED ACTIONS** (specific, actionable):
- What to investigate next

HARD RULES — violation is a serious error:
- For Windows evidence, the machine in host= is the AFFECTED host where the activity ran. Never call it the "source host". The source of failed logons is the src_ip on those events.
- NEVER mention reconnaissance, credential stuffing, password spraying, lateral movement or exfiltration unless the evidence text states it
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
        from src.ai.guard import sanitize_ai_text
        answer = sanitize_ai_text(answer, " ".join(guard_evidence))
    except Exception as e:
        return jsonify({"error": f"AI unavailable: {str(e)[:100]}"}), 503

    chat_history.append({"question": question, "answer": answer})
    store_chat_history(chat_history)
    return jsonify({"answer": answer, "turn": len(chat_history)})


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.route("/analytics")
@require_auth
def analytics():
    stats = get_rule_stats()
    return render_template("analytics.html", stats=stats)

@app.route("/enrich", methods=["POST"])
@require_auth
def enrich():
    """
    Opt-in VirusTotal enrichment endpoint.
    The analyst explicitly submits an IOC for external lookup.
    Privacy warning is shown in the UI before this is called.
    """
    data = request.get_json()
    if not data or "ioc" not in data:
        return jsonify({"error": "No IOC provided"}), 400

    ioc = data["ioc"].strip()
    ioc_type = data.get("type", "ip")
    if ioc_type == "ip":
        import ipaddress
        try:
            addr = ipaddress.ip_address(ioc)
        except ValueError:
            return jsonify({"error": "Not a valid IP address."}), 400
        if addr.is_private or addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return jsonify({"error": "Private/internal addresses are never sent to VirusTotal."}), 400

    if not os.environ.get("VT_API_KEY"):
        return jsonify({
            "error": "VT_API_KEY not set. Set it as an environment variable to enable VirusTotal enrichment.",
            "setup": "export VT_API_KEY=your_key_here"
        }), 503

    from src.enrichment.virustotal import enrich_ip, enrich_hash
    try:
        if ioc_type == "ip":
            result = enrich_ip(ioc)
        elif ioc_type in ("md5", "sha256", "hash"):
            result = enrich_hash(ioc)
        else:
            return jsonify({"error": f"Unsupported IOC type: {ioc_type}"}), 400

        if result is None:
            return jsonify({"not_found": True, "ioc": ioc})

        return jsonify({
            "ioc": ioc,
            "malicious": result.malicious_votes,
            "suspicious": result.suspicious_votes,
            "harmless": result.harmless_votes,
            "total_engines": result.total_engines,
            "community_score": result.community_score,
            "threat_names": result.threat_names,
            "permalink": result.permalink,
            "verdict": (
                "MALICIOUS" if result.malicious_votes >= 5
                else "SUSPICIOUS" if result.malicious_votes >= 1 or result.suspicious_votes >= 3
                else "CLEAN"
            ),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/host-summary", methods=["POST"])
@require_auth
def host_summary():
    analysis = current_analysis()
    if analysis is None:
        return jsonify({"error": "Session expired — please re-upload your file.", "session_expired": True}), 400
    data = request.get_json()
    victim_ip = data.get("victim_ip") if data else None
    if not victim_ip:
        return jsonify({"error": "victim_ip required"}), 400
    host_sums = analysis.get("host_summaries", [])
    target = next((hs for hs in host_sums if hs["victim_ip"] == victim_ip), None)
    if not target:
        return jsonify({"error": f"No host summary for {victim_ip}"}), 404
    linked = [i for i in analysis["incidents"] if i["incident_id"] in target["incident_ids"]]
    linked.sort(key=lambda i: i["first_seen"])
    sequence = "\n".join(
        f"  {n+1}. [{i['severity'].upper()}] {i['title']} (risk={i['risk_score']}, first={i['first_seen'][:19]})"
        for n, i in enumerate(linked)
    )
    prompt = f"""You are a SOC analyst writing an attack narrative.

HOST: {victim_ip}
WINDOW: {target['first_seen'][:19]} to {target['last_seen'][:19]}
DURATION: {target['duration_minutes']:.0f} minutes
HIGHEST SEVERITY: {target['highest_severity'].upper()}
MITRE: {', '.join(target['mitre_techniques']) or 'Unknown'}
TACTICS: {', '.join(set(target['mitre_tactics'])) or 'Unknown'}

INCIDENTS (chronological):
{sequence}

Write a 3-5 sentence attack narrative. Rules:
- Say "source host" not "attacker"
- Distinguish observed facts from inferences
- Recommendations must reference specific IPs and artifacts from the evidence
- Never say "check Suricata rule documentation"

Respond ONLY with JSON: {{"narrative":"...","attack_stage":"...","confidence":"high/medium/low","priority_action":"..."}}"""

    try:
        import requests as req, json as j
        r = req.post(
            f"{os.environ.get('OLLAMA_HOST','http://localhost:11434')}/api/generate",
            json={"model":"qwen3:8b","prompt":prompt,"stream":False,"format":"json"},
            timeout=120,
        )
        r.raise_for_status()
        parsed = j.loads(r.json()["response"])
        return jsonify({
            "victim_ip": victim_ip,
            "incident_count": len(linked),
            "duration_minutes": target["duration_minutes"],
            **parsed,
        })
    except Exception as e:
        return jsonify({"error": f"AI unavailable: {str(e)[:100]}"}), 503


@app.route("/timeline/<path:victim_ip>")
@require_auth
def host_timeline(victim_ip):
    analysis = current_analysis()
    if analysis is None:
        return render_template("analyze.html", error="Session expired - please re-upload your file."), 400
    hs = next((h for h in analysis.get("host_summaries", []) if h["victim_ip"] == victim_ip), None)
    if not hs:
        abort(404)
    from src.correlation.timeline import build_host_timeline
    tl = build_host_timeline(hs, analysis["incidents"])
    return render_template("timeline.html", tl=tl)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5001, host="127.0.0.1")
