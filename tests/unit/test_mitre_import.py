# tests/unit/test_mitre_import.py

from src.mitre.techniques import get_technique
from src.mitre.import_dataset import load_full_mitre_dataset, DATASET_PATH


def test_hardcoded_techniques_always_resolve_regardless_of_dataset():
    """These 4 MUST always work since our own rules depend on them directly."""
    assert get_technique("T1110") is not None
    assert get_technique("T1046") is not None


def test_missing_dataset_file_returns_empty_dict_not_crash():
    if not DATASET_PATH.exists():
        result = load_full_mitre_dataset()
        assert result == {}


def test_unknown_technique_returns_none():
    assert get_technique("T9999.999") is None

def test_missing_dataset_warns_once(monkeypatch, capsys, tmp_path):
    import src.mitre.import_dataset as m
    monkeypatch.setattr(m, "DATASET_PATH", tmp_path / "nope.json")
    monkeypatch.setitem(m._WARNED, "missing", False)
    assert m.load_full_mitre_dataset() == {}
    assert m.load_full_mitre_dataset() == {}
    assert capsys.readouterr().out.count("ATT&CK dataset not found") == 1
