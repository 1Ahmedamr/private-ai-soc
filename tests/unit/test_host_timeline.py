# tests/unit/test_host_timeline.py

import base64
from src.correlation.timeline import build_host_timeline
from src.webapp.app import app, DASHBOARD_USERNAME, DASHBOARD_PASSWORD


def inc(iid, title, first, last, sev="high", risk=70, techs=None):
    return {
        "incident_id": iid, "title": title, "severity": sev, "risk_score": risk,
        "correlation_key": "ip:51.195.169.87", "first_seen": first, "last_seen": last,
        "mitre_techniques": techs or ["T1071"],
        "detections": [{"rule_name": "r", "description": f"evidence for {title}"}],
    }


HS = {"victim_ip": "172.17.5.135", "incident_ids": ["A", "B"], "highest_severity": "high"}


def test_entries_sorted_chronologically_regardless_of_input_order():
    incidents = [
        inc("B", "Later", "2022-12-14T19:06:00+00:00", "2022-12-14T19:30:00+00:00"),
        inc("A", "Earlier", "2022-12-14T18:39:00+00:00", "2022-12-14T18:50:00+00:00"),
    ]
    tl = build_host_timeline(HS, incidents)
    assert [e["title"] for e in tl["entries"]] == ["Earlier", "Later"]
    assert tl["entries"][0]["gap_label"] is None
    assert tl["entries"][1]["gap_label"] == "27m 0s"


def test_offset_timestamps_normalized_to_utc():
    incidents = [inc("A", "X", "2022-12-14T21:00:00+02:00", "2022-12-14T21:10:00+02:00")]
    tl = build_host_timeline({"victim_ip": "h", "incident_ids": ["A"]}, incidents)
    assert tl["entries"][0]["time"] == "2022-12-14 19:00:00 UTC"


def test_unlinked_incidents_are_excluded():
    incidents = [
        inc("A", "In", "2022-12-14T18:00:00+00:00", "2022-12-14T18:05:00+00:00"),
        inc("Z", "Out", "2022-12-14T18:01:00+00:00", "2022-12-14T18:06:00+00:00"),
    ]
    tl = build_host_timeline(HS, incidents)
    assert tl["count"] == 1 and tl["entries"][0]["title"] == "In"


def test_timeline_page_renders_from_session():
    app.config["TESTING"] = True
    creds = base64.b64encode(f"{DASHBOARD_USERNAME}:{DASHBOARD_PASSWORD}".encode()).decode()
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["last_analysis"] = {
                "host_summaries": [HS],
                "incidents": [
                    inc("A", "Port Scan", "2022-12-14T18:39:00+00:00", "2022-12-14T18:50:00+00:00"),
                    inc("B", "BackConnect CnC", "2022-12-14T19:06:00+00:00", "2022-12-14T19:30:00+00:00"),
                ],
            }
        r = client.get("/timeline/172.17.5.135", headers={"Authorization": f"Basic {creds}"})
        assert r.status_code == 200
        assert b"BackConnect CnC" in r.data and b"172.17.5.135" in r.data


def test_timeline_requires_auth():
    with app.test_client() as client:
        assert client.get("/timeline/1.2.3.4").status_code == 401


def test_span_uses_latest_end_not_last_started_incident():
    incidents = [
        inc("A", "Long", "2022-12-14T19:00:00+00:00", "2022-12-14T22:00:00+00:00"),
        inc("B", "Short", "2022-12-14T20:00:00+00:00", "2022-12-14T20:00:00+00:00"),
    ]
    assert build_host_timeline(HS, incidents)["span"] == "3h 0m"
