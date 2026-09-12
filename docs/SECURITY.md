# Security Practices in This Codebase

- SQL: all queries use parameterized statements (psycopg2/sqlite3
  placeholders) - never raw string interpolation of user-controlled
  values into SQL. See src/storage/event_store.py's correlation-key
  column whitelist as a concrete example of preventing injection via
  a dynamic column name.
- AI input isolation: see docs/THREAT_MODEL.md and src/ai/evidence.py -
  the LLM never sees raw log content, closing the prompt-injection
  vector at the architecture level, not via prompt wording alone.
- No secrets committed: .env, *.key, *.pem excluded via .gitignore.
  Current dev Postgres password is a known placeholder
  (docker/docker-compose.yml) - NOT suitable for anything beyond local
  development; flagged explicitly rather than hidden.
- Egress guard: tests/unit/test_egress_guard.py enforces no outbound
  network calls beyond localhost in the AI layer.

## Known gaps (tracked honestly)
See docs/THREAT_MODEL.md for the full, unvarnished list.