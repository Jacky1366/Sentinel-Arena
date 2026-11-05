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
docker-compose.yml      Juice Shop (internal only) + nginx (arena :8080, admin :8081)
docs/contract.md        data contract v0 (SOURCE OF TRUTH)
docs/progress.md        human-readable build progress (not authoritative)
schemas/                JSON Schema (draft 2020-12) per artifact
  red_attack.schema.json          Red ground truth (Blue never reads)
  proxy_log.schema.json           nginx log line (Blue's only input)
  challenge_snapshot.schema.json  before/after solved state (measurement)
  verdict.schema.json             Blue verdict
  rule.schema.json                single Blue rule
  rules_file.schema.json          rules.json wrapper (cross-match memory)
  round_record.schema.json        Judge output
  landed_fact.schema.json         Judge fact-1 intermediate (Stage 2)
config/
  taxonomy.json         ["CWE-89","CWE-79","CWE-22","benign"]
  challenge_map.json    CWE -> Juice Shop challenge names
proxy/nginx.conf        nginx: log+forward arena :8080, admin :8081 (access_log off)
red/payloads.json       scripted-Red attack set (data, verified empirically)
red/scripted_red.py     write labeled record, then fire one attack via :8080
runner/stage2_run.py    reset target, snapshot challenge state around each attack
judge/fact1_landed.py   pure landed computation over artifacts (no network)
tools/validate_log.py   classify proxy log lines: valid / stray / invalid
tools/smoke_test.sh     Stage 1 end-to-end check of the running stack
tools/stage2_check.py   Stage 2 end-to-end check (runner + Judge vs expected)
blue/                   Blue defender (not yet implemented)
dashboard/              results viewer (not yet implemented)
data/runs/live/         nginx + runner write here (staging, git-ignored)
data/runs/<match_id>/   match output (git-ignored)
data/golden/            golden run for demo (committed later)
tests/test_schemas.py       schema + taxonomy-drift tests
tests/test_validate_log.py  validate_log.py classification tests
tests/test_fact1_landed.py  Judge fact-1 unit tests (no Docker)
```

## How to run the stack

```bash
docker compose up -d --wait     # starts Juice Shop + nginx; returns once healthy
tools/smoke_test.sh             # Stage 1: expects 4 valid, 2 stray, 0 invalid
.venv/bin/python tools/stage2_check.py   # Stage 2: runner + Judge, all PASS
.venv/bin/python tools/validate_log.py   # validate the whole live log
docker compose down             # stop (the log in data/runs/live/ is kept)
```

- The arena proxy is at `http://127.0.0.1:8080` (Blue's input, logged). The Judge's
  admin path is `http://127.0.0.1:8081/api/Challenges` (measurement, `access_log
  off`). Both loopback only; Juice Shop has no host port.
- nginx appends to `data/runs/live/proxy.jsonl`. `stage2_run.py` rotates that log
  (`nginx -s reopen`) at the start of a run so it holds only the current match.
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
- Stages 1–2 are implemented (Target + proxy; scripted Red + Judge fact 1). Do not
  implement Blue, further Judge facts, or the dashboard until the designer asks.
