# Sentinel Arena

A closed-loop evaluation harness for AI defenders.

A **Red** AI attacks OWASP Juice Shop through a logging-only nginx reverse proxy.
A **Blue** AI reads only the proxy log, classifies each request, and invents detection
rules that carry over between matches. A deterministic **Judge** scores every round.
Components never call each other; they exchange JSON/JSONL files defined in
[`docs/contract.md`](docs/contract.md).

## Architecture

```
                 X-Arena-Request-Id
 ┌─────────┐   HTTP (attack+benign)   ┌──────────────┐        ┌─────────────┐
 │   Red   │ ───────────────────────▶ │ nginx proxy  │ ─────▶ │ Juice Shop  │
 │  (AI)   │                          │ log+forward  │        │  (Target,   │
 └────┬────┘                          │ NO defenses  │        │  isolated)  │
      │                               └──────┬───────┘        └──────┬──────┘
      │ red_attacks.jsonl                    │ proxy.jsonl           │ /api/Challenges
      │ (ground truth)                       ▼                       │ (before/after)
      │                               ┌──────────────┐               │
      │                               │     Blue     │◀── rules.json │
      │                               │     (AI)     │──▶ (next match)
      │                               └──────┬───────┘               │
      │                                      │ verdicts.jsonl        │
      ▼                                      ▼                       ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                Judge (pure deterministic code, no LLM)                    │
 │           joins on request_id  ──▶  rounds.jsonl  ──▶  Dashboard          │
 └──────────────────────────────────────────────────────────────────────────┘

 Blue never reads red_attacks.jsonl. The orchestrator (run_match.py) sequences everything.
```

## Status

Data contract v0, plus Stage 1: Juice Shop behind a logging-only nginx proxy.
Red, Blue, Judge and the dashboard are not implemented yet.

## Setup and tests

Requires Python 3.11+. After creating the venv, always run Python through
`.venv/bin/python` so the project's dependencies are used.

```bash
python3 -m venv .venv                          # one-time: create the venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env                           # fill in API keys; never commit .env
.venv/bin/python -m pytest
```

## How to run the stack

Requires Docker with Compose v2.

```bash
docker compose up -d --wait     # starts Juice Shop + nginx; returns once healthy
tools/smoke_test.sh             # expects: 4 valid, 2 stray, 0 invalid
.venv/bin/python tools/validate_log.py   # validate the whole live log
docker compose down             # stop (the log in data/runs/live/ is kept)
```

- The proxy listens on `http://127.0.0.1:8080` (loopback only). Juice Shop has no
  host port and sits on an internal-only Docker network, so it is reachable only
  through nginx.
- Every request through the proxy is appended as one JSON line to
  `data/runs/live/proxy.jsonl` (git-ignored). See `docs/contract.md` §3.
- Known limitation: nginx rejects paths that climb above the web root
  (e.g. `/ftp/..%2f..%2fetc/passwd`) with 400 before reading headers, so the line
  has an empty `request_id` and path. It is stray and invisible to Blue and the
  Judge, so Red must never send such requests. See `docs/contract.md` §9.
- `tools/smoke_test.sh` request (f) may solve a Juice Shop challenge. Run
  `docker compose restart juice-shop` before a scored run to reset challenge state.

## Layout

See [`CLAUDE.md`](CLAUDE.md) for the directory map and design principles.
