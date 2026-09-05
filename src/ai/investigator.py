import subprocess

def investigate(text):

    prompt = f"""
You are a senior SOC analyst.

Analyze the following network activity.

Network Activity:
{text}

Provide:

1. Findings
2. Suspicious indicators
3. Risk score (1-10)
4. Recommendations
"""

    result = subprocess.run(
        ["ollama", "run", "qwen3:8b"],
        input=prompt,
        text=True,
        capture_output=True
    )

    return result.stdout