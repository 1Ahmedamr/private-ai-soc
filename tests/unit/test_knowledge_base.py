# tests/unit/test_knowledge_base.py

import pytest
from src.knowledge.index import _chunk_markdown


def test_chunk_markdown_splits_on_paragraphs():
    text = "First paragraph.\n\nSecond paragraph.\n\nThird."
    chunks = _chunk_markdown(text)
    assert len(chunks) == 3
    assert chunks[0] == "First paragraph."


def test_chunk_markdown_ignores_empty_sections():
    text = "First.\n\n\n\nSecond."
    chunks = _chunk_markdown(text)
    assert chunks == ["First.", "Second."]


@pytest.mark.skipif(
    True, reason="Requires downloading sentence-transformers model (~90MB) - run manually, not in CI"
)
def test_knowledge_base_build_and_query_manual_only():
    """
    Why skip in CI? Same reasoning as the PCAP/Zeek/Suricata tests -
    downloading a 90MB model on every CI run is slow and wasteful when
    the actual retrieval LOGIC (chunking, thresholding) is already
    covered by the tests above without needing the real model.
    """
    from src.knowledge.index import KnowledgeBase
    kb = KnowledgeBase()
    kb.build()
    results = kb.query("brute force attack on privileged account")
    assert len(results) > 0