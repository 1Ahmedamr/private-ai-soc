# src/ai/ollama_client.py

import os
import json
import requests
from typing import Optional
from src.ai.evidence import InvestigationEvidence
from src.ai.verdict import InvestigationVerdict


OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

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

CRITICAL: When mentioning IP addresses, copy them EXACTLY from the
evidence data. Never modify, approximate, or retype IP addresses from
memory - always read them directly from the source_ips and target_ips
fields provided. An incorrect IP in a SOC report can cause analysts
to investigate the wrong host.

CRITICAL RULES:
- Copy timestamps EXACTLY from the evidence fields. Never round or approximate times.
- Do not use the word "attacker" unless there is confirmed malicious activity beyond reconnaissance.
- Do not conclude "compromised host" from scanning activity alone. Use "source host."
- Distinguish observed facts from analyst assumptions in your response.

...rest of prompt...

When identifying the MITRE attack stage, use the tactic from the
mitre_techniques field directly. For T1046 (Network Service Discovery),
the correct tactic is 'Discovery', NOT 'Initial Access'. For T1110
(Brute Force), the correct tactic is 'Credential Access'. Always
derive the attack stage from the provided MITRE technique data.
"""


def investigate(evidence: InvestigationEvidence, model: str = "qwen3:8b") -> Optional[InvestigationVerdict]:
    """
    Returns None on any failure (unreachable Ollama, malformed response) -
    the pipeline must be able to proceed WITHOUT an AI verdict.
    """
    playbook_section = ""
    if evidence.relevant_playbook_excerpts:
        playbook_section = (
            "\n\nRelevant internal playbook guidance (use this to inform "
            "your recommended actions, but still reason about this "
            "specific incident):\n" + "\n---\n".join(evidence.relevant_playbook_excerpts)
        )

    tactic_instruction = ""
    if evidence.mitre_tactic:
        tactic_instruction = (
            f"\n\nCRITICAL INSTRUCTION: The MITRE tactic for this incident is "
            f"'{evidence.mitre_tactic}'. You MUST use this exact tactic name as "
            f"the 'likely_attack_stage' field in your response. Do not substitute "
            f"a different tactic. This is non-negotiable."
        )

    prompt = f"{SYSTEM_PROMPT}\n\nEvidence:\n{evidence.model_dump_json(indent=2)}{playbook_section}{tactic_instruction}"
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=120,
        )
        response.raise_for_status()
        raw_text = response.json()["response"]
        parsed = json.loads(raw_text)
        return InvestigationVerdict.model_validate(parsed)
    except Exception:
        return None
