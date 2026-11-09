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

Stages 0–4 done: data contract, Juice Shop behind a logging-only proxy, scripted
Red + Judge (landed, detected, round record), scripted Blue v0, and a one-command
match (`run_match.py`). Stage 5.1 done: the AI body (`agents/llm_client.py`) with
budget caps and cost tracking, tested with a fake provider (no real calls yet).
Stage 5.2 done: benign traffic interleaved with Red by a seeded schedule, and
false-positive scoring (Judge fact 4a), so the detection rate is always reported
next to an FP rate. AI-driven Red/Blue and the dashboard are not implemented yet. See
[`docs/progress.md`](docs/progress.md) and
[`docs/stage5_decisions.md`](docs/stage5_decisions.md).

## Setup and tests

Requires Python 3.11+. After creating the venv, always run Python through
`.venv/bin/python` so the project's dependencies are used.

```bash
python3 -m venv .venv                          # one-time: create the venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env                           # fill in ARENA_* API keys; never commit .env
brew install gitleaks                          # secret scanner (macOS; see docs/ops.md)
git config core.hooksPath .githooks            # one-time: enable the pre-commit hook
.venv/bin/python -m pytest
```

API keys use `ARENA_*` names only, never the SDKs' default names: an exported
`ANTHROPIC_API_KEY` would make Claude Code itself bill that key. The pre-commit
hook blocks commits that stage a secret. See [`docs/ops.md`](docs/ops.md) for the
key-leak playbook and `run_match.py` exit codes.

## How to run the stack

Requires Docker with Compose v2.

```bash
docker compose up -d --wait     # starts Juice Shop + nginx; returns once healthy
tools/smoke_test.sh             # Stage 1: expects 4 valid, 2 stray, 0 invalid
.venv/bin/python run_match.py            # one complete match -> data/runs/<match_id>/
.venv/bin/python tools/stage4_check.py   # Stage 4: run_match + frozen-dir checks, all PASS
.venv/bin/python tools/stage2_check.py   # Stage 2: scripted Red + Judge, all PASS
.venv/bin/python tools/stage3_check.py   # Stage 3: full pipeline vs expectations
.venv/bin/python tools/validate_log.py   # validate the whole live log
docker compose down             # stop (the log in data/runs/live/ is kept)
```

- The proxy listens on `http://127.0.0.1:8080` (loopback only). Juice Shop has no
  host port and sits on an internal-only Docker network, so it is reachable only
  through nginx.
- Every request through the proxy is appended as one JSON line to
  `data/runs/live/proxy.jsonl` (git-ignored). Each match freezes it into
  `data/runs/<match_id>/` together with `match.json`, its manifest. See
  `docs/contract.md` §3 and §6.2. A committed example is in
  `data/golden/scripted-baseline-match/`.
- Known limitation: nginx rejects paths that climb above the web root
  (e.g. `/ftp/..%2f..%2fetc/passwd`) with 400 before reading headers, so the line
  has an empty `request_id` and path. It is stray and invisible to Blue and the
  Judge, so Red must never send such requests. See `docs/contract.md` §9.
- `tools/smoke_test.sh` request (f) may solve a Juice Shop challenge. `run_match.py`
  resets the Target at the start of every match and refuses to run if it is not clean.

## Layout

See [`CLAUDE.md`](CLAUDE.md) for the directory map and design principles.
