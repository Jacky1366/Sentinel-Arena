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

Scaffolding plus data contract v0. Component logic is not implemented yet.

## Setup and tests

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in API keys; never commit .env
pytest
```

## Layout

See [`CLAUDE.md`](CLAUDE.md) for the directory map and design principles.
