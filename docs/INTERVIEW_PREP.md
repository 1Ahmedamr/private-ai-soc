# Interview Preparation: Private AI SOC

## The one-sentence pitch
A fully local, privacy-first security operations pipeline that ingests
logs from 4 sources, runs deterministic detection and correlation, scores
risk automatically, and enriches incidents with AI investigation — with
a proven, tested guarantee that no telemetry leaves the local machine.

## Architecture decisions I can defend

### Why deterministic detection BEFORE the AI?
Because AI models can hallucinate, are non-deterministic (same input
can produce slightly different output), and are slow. Severity, risk
scores, and MITRE mappings are computed by rule-based code (tested,
reproducible, fast) BEFORE the AI ever sees the incident. The AI's
job is explanation and recommendation — never judgment. This is
directly proven by the evidence contract in src/ai/evidence.py, which
strips raw log data before it reaches the LLM.

### Why a single normalized schema for all 4 log sources?
Adding the 4th source (Suricata) required ZERO changes to detection,
correlation, risk scoring, or the AI layer. This isn't a claim — it's
a demonstrable architectural proof: src/ingestion/ has 4 separate
parsers, and everything downstream is completely source-agnostic.

### Why SQLite for dev and PostgreSQL for production?
SQLite's single-file locking breaks under concurrent writes from
multiple ingestion processes — a real, specific bottleneck I can
describe exactly. PostgreSQL's connection-pooled model solves this.
The Repository Pattern (same interface for both stores) means the
swap required zero changes to any engine, orchestrator, or test
outside the storage layer itself.

### Why is the reopen window per-rule instead of global?
A brute force rule fires again hours after the attacker retries. A C2
beacon might sleep for weeks before reconnecting. A single global
window would either miss legitimate reopens (too short) or conflate
unrelated incidents (too long). Each rule defines its own window
because each rule models attacker behavior for a specific technique.

### Why Basic Auth with secrets.compare_digest instead of a simpler comparison?
Plain == comparison exits at the first mismatched character, making
password length measurable via response time (a timing attack). This
is a real, named attack class. secrets.compare_digest runs in
constant time regardless of where the mismatch occurs.

### Why does the egress guard test use real unmocked code?
Mocking requests.post proves the parsing logic works but never proves
what URL the code was TRYING to reach. test_egress_guard.py
intercepts real socket.connect calls, meaning it would catch an
accidental cloud API call even if I added it in a new file tomorrow.
It's the difference between "we trust the code" and "we verify it."

### Why Shannon entropy for DNS detection?
DGA (Domain Generation Algorithm) malware creates random-looking
domain names to rotate C2 infrastructure. Real human-readable domains
have low entropy (repeated patterns humans use). This is a
well-established, published detection technique — I didn't invent it,
I implemented a known-good approach from the security research
literature.

## Things this project deliberately does NOT do (and why)

- **Replace Splunk**: It's a proof-of-concept for a specific niche
  (data-sovereign, local AI-assisted SOC). Claiming otherwise would
  be dishonest and would immediately fail scrutiny.
- **Trust the AI to decide severity**: See the architecture decision
  above. If asked "what if the AI is wrong?" — it can be wrong about
  its explanation, but it can never lower or raise the risk score
  because it doesn't have access to that decision.
- **Auto-remediate**: The system recommends actions, it doesn't take
  them. Human-in-the-loop is a deliberate design choice, not a
  limitation.

## Metrics I can cite from real test runs

- 109 automated tests passing (including 7 named attack scenarios)
- 7/7 scenario coverage: brute force, PowerShell execution, suspicious
  DNS, port scanning, C2 beacon, SSH root brute force, benign activity
- 0 false positives on the benign-activity scenario (explicit test)
- 17.18 seconds average AI investigation latency (local qwen3:8b)
- 4 log sources: Windows Event Log, Linux SSH auth, Zeek conn.log,
  Suricata EVE JSON
- All numbers reproducible via the test suite, not claimed from memory

## Questions I expect and how I'd answer them

**Q: How is this different from just calling ChatGPT on your logs?**
A: Three ways. First, no data leaves the machine (proven by
test_egress_guard.py, not just claimed). Second, the AI never decides
anything — severity and risk are computed deterministically before the
AI sees the incident. Third, the AI receives a stripped evidence
contract, not raw log data, which closes the prompt-injection vector
at the architecture level.

**Q: What's the biggest weakness?**
A: Honest answer: SQLite has concurrency limits (described in the
threat model), the knowledge base has only 4 playbooks (needs
organizational content to be genuinely useful), and detection rules
are hand-written rather than loaded from a community Sigma rule set
(a real gap I've noted explicitly in the roadmap).

**Q: How would you scale this to a real SOC?**
A: Three specific changes: PostgreSQL already replaces SQLite in the
Docker setup. The ingestion watch loop would be replaced by Kafka or
a proper log shipper (Filebeat, rsyslog). The LLM would move to a
dedicated GPU server rather than running locally on the analyst's
machine — but the architecture wouldn't change because the ollama
client's OLLAMA_HOST environment variable already supports this.

**Q: Did you use AI to write this?**
A: I used Claude as a technical mentor and pair programmer — the same
way a junior engineer would use Stack Overflow or a senior colleague.
Every architectural decision was reasoned through, defended, and
sometimes pushed back on. The code is mine; the debugging sessions
and architectural reviews happened in conversation. I can walk through
any part of this codebase and explain exactly why it's built the way
it is.