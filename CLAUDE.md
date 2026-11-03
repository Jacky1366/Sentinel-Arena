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
   Log lines without a valid `request_id` are stray traffic: loaders skip and count
   them, never crash.

## Directory map

```
CLAUDE.md               this file
README.md               overview, architecture diagram, how to run tests
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
proxy/                  nginx reverse proxy + JSON log format (not yet implemented)
red/                    Red attacker (not yet implemented)
blue/                   Blue defender (not yet implemented)
judge/                  deterministic scorer (not yet implemented)
dashboard/              results viewer (not yet implemented)
data/runs/<match_id>/   match output (git-ignored)
data/golden/            golden run for demo (committed later)
tests/test_schemas.py   schema + taxonomy-drift tests
```

## Working notes

- Python 3.11+. Always run Python via the project venv: `.venv/bin/python`
  (e.g. `.venv/bin/python -m pip install -r requirements.txt`,
  `.venv/bin/python -m pytest`). Never use the system `python3`.
- Schemas hardcode taxonomy enums. If `config/taxonomy.json` changes, update the
  schemas and contract too. Tests catch drift.
- `rules_file.schema.json` `$ref`s `rule.schema.json` by `$id`. Validators need a
  `referencing.Registry` that contains both (see `tests/test_schemas.py`).
- Current scope is scaffolding only. Do not implement Red/Blue/Judge/proxy/dashboard
  logic until the designer asks.
