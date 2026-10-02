# tests/unit/test_analysis_store.py

import base64
from src.webapp import analysis_store
from src.webapp.app import app, DASHBOARD_USERNAME, DASHBOARD_PASSWORD


def test_large_payload_roundtrips(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis_store, "STORE_DIR", tmp_path)
    big = {"incidents": ["x" * 1000] * 50}  # ~50KB, far over the 4KB cookie limit
    aid = analysis_store.save_analysis(big)
    assert analysis_store.load_analysis(aid)["analysis"] == big


def test_rejects_path_traversal_and_garbage(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis_store, "STORE_DIR", tmp_path)
    assert analysis_store.load_analysis("../../etc/passwd") is None
    assert analysis_store.load_analysis(None) is None
    assert analysis_store.load_analysis("a" * 32) is None  # valid shape, no file


def test_chat_history_persists(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis_store, "STORE_DIR", tmp_path)
    aid = analysis_store.save_analysis({"k": 1})
    analysis_store.save_chat_history(aid, [{"question": "q", "answer": "a"}])
    assert analysis_store.load_analysis(aid)["chat_history"][0]["answer"] == "a"


def test_timeline_works_from_server_side_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis_store, "STORE_DIR", tmp_path)
    inc = lambda iid, title, a, b: {
        "incident_id": iid, "title": title, "severity": "high", "risk_score": 70,
        "correlation_key": "ip:1.2.3.4", "first_seen": a, "last_seen": b,
        "mitre_techniques": ["T1071"],
        "detections": [{"rule_name": "r", "description": "evidence"}],
    }
    aid = analysis_store.save_analysis({
        "host_summaries": [{"victim_ip": "172.17.5.135", "incident_ids": ["A", "B"],
                            "highest_severity": "high"}],
        "incidents": [inc("A", "Port Scan", "2022-12-14T18:39:00+00:00", "2022-12-14T18:50:00+00:00"),
                      inc("B", "BackConnect CnC", "2022-12-14T19:06:00+00:00", "2022-12-14T19:30:00+00:00")],
    })
    app.config["TESTING"] = True
    creds = base64.b64encode(f"{DASHBOARD_USERNAME}:{DASHBOARD_PASSWORD}".encode()).decode()
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["analysis_id"] = aid
        r = client.get("/timeline/172.17.5.135", headers={"Authorization": f"Basic {creds}"})
        assert r.status_code == 200
        assert b"BackConnect CnC" in r.data
