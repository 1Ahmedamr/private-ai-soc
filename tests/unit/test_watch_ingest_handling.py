# tests/unit/test_watch_ingest_handling.py
"""What the watcher does with each file, and what it reports about its own health."""

import json

import pytest

from src.pipeline import watch_ingest as watcher


class FakeOrchestrator:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = 0

    def ingest(self, events):
        self.calls += 1
        if self.fail:
            raise ValueError("boom")
        return []


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(watcher, "WATCH_DIR", tmp_path / "incoming")
    monkeypatch.setattr(watcher, "PROCESSED_DIR", tmp_path / "archive")
    monkeypatch.setattr(watcher, "FAILED_DIR", tmp_path / "failed")
    monkeypatch.setattr(watcher, "SKIPPED_DIR", tmp_path / "skipped")
    monkeypatch.setattr(watcher, "STATUS_FILE", tmp_path / "status.json")
    monkeypatch.setitem(watcher._PREFIX_PARSER_MAP, "windows_", lambda raw: raw)
    monkeypatch.setattr(watcher.time, "sleep", lambda seconds: None)
    watcher.WATCH_DIR.mkdir()
    return tmp_path


def drop(name, content=None):
    path = watcher.WATCH_DIR / name
    path.write_text(json.dumps(content if content is not None else [{"n": 1}]))
    return path


def test_successful_file_is_archived_and_recorded(dirs):
    assert watcher.process_file(drop("windows_a.json"), FakeOrchestrator()) == "ingested"
    assert (watcher.PROCESSED_DIR / "windows_a.json").exists()
    assert json.loads(watcher.STATUS_FILE.read_text())["last_ingest_at"]


def test_failed_file_is_quarantined_not_archived(dirs):
    assert watcher.process_file(drop("windows_bad.json"), FakeOrchestrator(fail=True)) == "failed"
    assert (watcher.FAILED_DIR / "windows_bad.json").exists()
    assert not (watcher.PROCESSED_DIR / "windows_bad.json").exists()


def test_unrecognized_prefix_is_skipped_not_archived_as_ingested(dirs):
    orchestrator = FakeOrchestrator()
    assert watcher.process_file(drop("random_file.json"), orchestrator) == "skipped"
    assert (watcher.SKIPPED_DIR / "random_file.json").exists()
    assert not (watcher.PROCESSED_DIR / "random_file.json").exists()
    assert orchestrator.calls == 0


def test_same_name_never_overwrites_an_earlier_file(dirs):
    watcher.process_file(drop("windows_a.json", [{"n": "first"}]), FakeOrchestrator())
    watcher.process_file(drop("windows_a.json", [{"n": "second"}]), FakeOrchestrator())
    texts = [p.read_text() for p in watcher.PROCESSED_DIR.iterdir()]
    assert len(texts) == 2
    assert any('"first"' in t for t in texts) and any('"second"' in t for t in texts)


def test_two_failures_with_the_same_name_are_both_kept(dirs):
    for n in ("one", "two"):
        watcher.process_file(drop("windows_bad.json", [{"n": n}]), FakeOrchestrator(fail=True))
    assert len(list(watcher.FAILED_DIR.iterdir())) == 2


def test_health_with_no_activity(dirs):
    assert watcher.pipeline_health() == {
        "incoming_backlog": 0, "quarantined": 0, "skipped": 0,
        "last_ingest_at": None, "last_poll_at": None,
    }


def test_health_counts_files_and_exposes_no_filenames(dirs):
    drop("windows_waiting.json")
    watcher.process_file(drop("windows_bad_secretname.json"), FakeOrchestrator(fail=True))
    watcher.process_file(drop("random_file.json"), FakeOrchestrator())
    health = watcher.pipeline_health()
    assert (health["incoming_backlog"], health["quarantined"], health["skipped"]) == (1, 1, 1)
    assert "secretname" not in str(health) and "random_file" not in str(health)


def test_unwritable_status_file_does_not_turn_a_good_file_into_a_failure(dirs, monkeypatch):
    (dirs / "blocker").write_text("not a directory")
    monkeypatch.setattr(watcher, "STATUS_FILE", dirs / "blocker" / "status.json")
    assert watcher.process_file(drop("windows_a.json"), FakeOrchestrator()) == "ingested"
    assert (watcher.PROCESSED_DIR / "windows_a.json").exists()


def test_file_that_vanishes_before_processing_does_not_crash(dirs):
    assert watcher.process_file(watcher.WATCH_DIR / "windows_gone.json", FakeOrchestrator()) == "pending"
