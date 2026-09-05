from src.ai.investigator import investigate

sample = """
Host: 172.16.8.49

Domains:
grinswakebthu.info
taibeinan.cc

HTTP POST requests detected.

Possible outbound communication.
"""

report = investigate(sample)

print(report)