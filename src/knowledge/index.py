# src/knowledge/index.py

from pathlib import Path
from typing import List, Tuple
import numpy as np

KNOWLEDGE_BASE_DIR = Path("data/knowledge_base")


def _chunk_markdown(text: str, chunk_size: int = 500) -> List[str]:
    """
    Splits a playbook into paragraph-sized chunks for retrieval.
    Why chunk instead of embedding the whole document? A whole playbook
    document mixes "immediate actions" with "false positive indicators" -
    a query about false positives shouldn't retrieve the whole document
    when only that section is relevant. Chunking by paragraph keeps each
    retrievable unit focused on one topic.
    """
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    return paragraphs


class KnowledgeBase:
    """
    Loads all markdown playbooks, embeds them locally, and answers
    similarity queries - entirely offline after the one-time model
    download. No chunk or query ever leaves this process.
    """

    def __init__(self):
        self.chunks: List[str] = []
        self.embeddings: np.ndarray = None
        self._model = None

    def _get_model(self):
        # Lazy import + lazy load: sentence-transformers pulls in torch,
        # which is heavy to import. Only pay that cost if the knowledge
        # base is actually used - matches the same lazy-loading pattern
        # as the MITRE dataset cache from Day C.
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model

    def build(self) -> None:
        if not KNOWLEDGE_BASE_DIR.exists():
            return

        all_chunks = []
        for md_file in sorted(KNOWLEDGE_BASE_DIR.glob("*.md")):
            text = md_file.read_text()
            all_chunks.extend(_chunk_markdown(text))

        if not all_chunks:
            return

        model = self._get_model()
        self.chunks = all_chunks
        self.embeddings = model.encode(all_chunks, convert_to_numpy=True)

    def query(self, question: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """
        Returns the top_k most relevant chunks for a question, using
        cosine similarity - the standard, simple approach for small-scale
        local retrieval. Returns (chunk_text, similarity_score) pairs.
        """
        if self.embeddings is None or len(self.chunks) == 0:
            return []

        model = self._get_model()
        query_embedding = model.encode([question], convert_to_numpy=True)[0]

        similarities = np.dot(self.embeddings, query_embedding) / (
            np.linalg.norm(self.embeddings, axis=1) * np.linalg.norm(query_embedding)
        )

        top_indices = np.argsort(similarities)[::-1][:top_k]
        return [(self.chunks[i], float(similarities[i])) for i in top_indices]