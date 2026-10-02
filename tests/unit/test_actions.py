import re
from src.ai.actions import build_actions

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def test_backconnect_actions_use_correct_endpoints_only():
    desc = ["Suricata matched signature 'ET MALWARE BackConnect CnC Activity (Set Sleep Timer)' (14 occurrence(s))."]
    acts = build_actions(desc, ["51.195.169.87"], ["172.17.5.135"])
    joined = " ".join(acts)
    assert "172.17.5.135" in joined and "51.195.169.87" in joined
    assert "DNS requests from 51.195.169.87" not in joined
    assert set(IP.findall(joined)) <= {"51.195.169.87", "172.17.5.135"}


def test_pe_download_direction_and_no_unsupported_claims():
    desc = ["Suricata matched signature 'ET INFO PE EXE or DLL Windows file download HTTP' (3 occurrence(s))."]
    joined = " ".join(build_actions(desc, ["199.127.62.132"], ["172.17.5.135"]))
    assert "from 199.127.62.132 to 172.17.5.135" in joined
    assert "authentication logs" not in joined and "lateral" not in joined


def test_entropy_domain_is_not_called_dga():
    desc = ["High-entropy domain queried: 'primsenetwolk.com' (entropy=3.55) - possible DGA/C2 domain."]
    joined = " ".join(build_actions(desc, ["172.17.5.135"], []))
    assert "primsenetwolk.com" in joined and "does not establish DGA" in joined
