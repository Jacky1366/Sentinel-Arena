# CLAUDE.md — Sentinel Arena

## Project summary

Sentinel Arena is a closed-loop evaluation harness for AI defenders. A **Red** AI
attacks OWASP Juice Shop through an nginx reverse proxy. A **Blue** AI reads only the
proxy log, outputs verdicts, and invents detection rules. A pure-code **Judge** scores
every round. Components do NOT call
each other; they communicate only through file artifacts (JSON / JSONL) defined in
`docs/contract.md`. An orchestrator (`run_match.py`, later) controls the order.

Roles: the user is the **designer**; Claude is the **implementer**.

## THE RULE

**`docs/contract.md` is the source of truth. Never change an artifact format without
updating the contract and schemas first, and tell the designer.**

## Design principles

1. The proxy has NO defenses (no WAF, rate limit, auth). It only logs and forwards.
   All defense lives in Blue so the Judge can measure it.
2. We control the log format, so the Target is swappable.
3. Blue only reads the log. It is never on the live traffic path.
4. The Judge is pure deterministic code. Never use an LLM to judge.
5. The taxonomy limits Red's label vocabulary, not its attack techniques.
6. Only attack our own isolated Target. Juice Shop is never exposed outside the proxy.
7. Never commit secrets. API keys live only in `.env`.
8. ALL arena traffic, both attack and benign, carries `X-Arena-Request-Id` and is
   sent by the same HTTP client. Otherwise header presence leaks ground truth to Blue.
   Log lines with a missing or empty `request_id` are stray traffic: loaders skip
   and count them, never crash. Any other non-matching `request_id` is invalid.

## Directory map

```
CLAUDE.md               this file
README.md               overview, architecture diagram, how to run tests and the stack
docker-compose.yml      Juice Shop (internal only) + nginx proxy (127.0.0.1:8080)
docs/contract.md        data contract v0 (SOURCE OF TRUTH)
schemas/                JSON Schema (draft 2020-12) per artifact
  red_attack.schema.json    Red ground truth (Blue never reads)
  proxy_log.schema.json     nginx log line (Blue's only input)
  verdict.schema.json       Blue verdict
  rule.schema.json          single Blue rule
  rules_file.schema.json    rules.json wrapper (cross-match memory)
  round_record.schema.json  Judge output
config/
  taxonomy.json         ["CWE-89","CWE-79","CWE-22","benign"]
  challenge_map.json    CWE -> Juice Shop challenge names
proxy/nginx.conf        nginx: log + forward only, JSON log format (Stage 1)
tools/validate_log.py   classify proxy log lines: valid / stray / invalid
tools/smoke_test.sh     end-to-end check of the running stack
red/                    Red attacker (not yet implemented)
blue/                   Blue defender (not yet implemented)
judge/                  deterministic scorer (not yet implemented)
dashboard/              results viewer (not yet implemented)
data/runs/live/         nginx writes proxy.jsonl here (staging, git-ignored)
data/runs/<match_id>/   match output (git-ignored)
data/golden/            golden run for demo (committed later)
tests/test_schemas.py   schema + taxonomy-drift tests
tests/test_validate_log.py  validate_log.py classification tests
```

## How to run the stack

```bash
docker compose up -d --wait     # starts Juice Shop + nginx; returns once healthy
tools/smoke_test.sh             # expects: 4 valid, 2 stray, 0 invalid
.venv/bin/python tools/validate_log.py   # validate the whole live log
docker compose down             # stop (the log in data/runs/live/ is kept)
```

- The proxy is at `http://127.0.0.1:8080`, loopback only. Juice Shop has no host
  port; it is reachable only through nginx.
- nginx appends to `data/runs/live/proxy.jsonl`.
- Known limitation: nginx rejects paths that climb above the web root while
  parsing the request line, so they log as stray (empty `request_id` and path) and
  are invisible to Blue and the Judge. Red must never send them (contract §9).
- The smoke test's request (f) may solve a challenge; run
  `docker compose restart juice-shop` before a scored run.

## Working notes

- Python 3.11+. Always run Python via the project venv: `.venv/bin/python`
  (e.g. `.venv/bin/python -m pip install -r requirements.txt`,
  `.venv/bin/python -m pytest`). Never use the system `python3`.
- Schemas hardcode taxonomy enums. If `config/taxonomy.json` changes, update the
  schemas and contract too. Tests catch drift.
- `rules_file.schema.json` `$ref`s `rule.schema.json` by `$id`. Validators need a
  `referencing.Registry` that contains both (see `tests/test_schemas.py`).
- Stage 1 (Target + proxy) is implemented. Do not implement Red/Blue/Judge/dashboard
  logic until the designer asks.
