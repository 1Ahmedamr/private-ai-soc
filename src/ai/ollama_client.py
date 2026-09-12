# src/ai/ollama_client.py

import json
import requests
from src.ai.evidence import InvestigationEvidence
from src.ai.verdict import InvestigationVerdict
from typing import Optional

SYSTEM_PROMPT = """You are a SOC investigation assistant. You will be given
ALREADY-DECIDED evidence about a security incident: severity, risk score, and
MITRE mapping have already been determined by deterministic detection rules.

Your job is ONLY to:
1. Summarize what happened in plain language
2. Identify the likely attack stage (MITRE tactic name)
3. Recommend concrete investigation/response actions
4. State your own confidence/uncertainty about the summary

You must NOT change, second-guess, or override the given severity or risk
score - those are not yours to decide. Respond ONLY with valid JSON matching
this exact shape, nothing else:
{"summary": "...", "likely_attack_stage": "...", "recommended_actions": ["...","..."], "analyst_confidence_note": "..."}
"""


def investigate(evidence: InvestigationEvidence, model: str = "qwen2.5:7b") -> Optional[InvestigationVerdict]:
    """
    Returns None on any failure (unreachable Ollama, malformed response) -
    the pipeline must be able to proceed WITHOUT an AI verdict. AI
    investigation is an enhancement, never a dependency the rest of the
    system breaks without - direct application of the human-in-the-loop
    principle from your own roadmap's business section.
    """
    prompt = f"{SYSTEM_PROMPT}\n\nEvidence:\n{evidence.model_dump_json(indent=2)}"

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=60,
        )
        response.raise_for_status()
        raw_text = response.json()["response"]
        parsed = json.loads(raw_text)
        return InvestigationVerdict.model_validate(parsed)
    except Exception:
        return None