# Stage 7 plan — live demo, compare view, analyst report

*Planned 2026-11-24. Decisions: `docs/stage7_decisions.md` (D45–D59). Demo: Dec 3.*

## Goal

Turn the frozen Stage 6 evidence into a demo that runs live and cannot fail badly:

1. **Battle** — a live match, shown in three acts (D47).
2. **Compare** — what we found: original vs open Blue on the same free-play traffic (D52).
3. **Report** — an AI-drafted, code-grounded evaluation report; a human decides (D53–D57).

Scope freeze (D40) stands: no new evidence. Live and test runs are `purpose=dev`.

## Architecture

```
terminal: ARENA_GO=… run_match (D46 config)
   └─ writes artifacts as today (orchestrator unchanged, D47)
          │ tail
   live server (stdlib, 127.0.0.1, read-only, SSE)  ── D48
          │
   dashboard/dist/index.html  ── LIVE (server) or REPLAY (file://)  ── D49
     ├─ Battle   three acts, event-driven animation  ── D50
     ├─ Compare  N Blue arms on the same traffic      ── D52
     └─ Report   rendered analyst report + decision   ── D53–D57

frozen evidence → summary.json (code) → analyst JSON (placeholders)
   → grounding check (code) → Jinja2 → report.html → print → report.pdf
```

## Out of scope

World map, X-Forwarded-For (D51) · a start button in the browser (D48) · per-line live
Blue or any orchestrator change (D47) · new evidence of any kind (D40).

## Work items (one issue each)

Labels: `needs-GO` (any paid call or test-set read), `paid`, `test-set`.
Each issue follows the usual flow: Step 0 plan → review → build (fake provider) → GO
gates if any → PR with `Closes #N`, merged with **Create a merge commit**.

### 1. Housekeeping
- Merge PR #9 (Stage 6.3); close issue #5.
- Add `docs/stage7_decisions.md` and this plan.
- Record the 2026-11-24 ledger-scan slip in `docs/progress.md`; apply D59 (shared helper
  if one fits, otherwise a documented rule).
- **Done when:** main is clean, both docs committed, slip recorded.

### 2. Live server
- stdlib `ThreadingHTTPServer`, `127.0.0.1` only, read-only (D48).
- Serves the dashboard and `/events` (SSE). Tails the match artifacts: follows
  `live/match.lock`, the proxy-log move at freeze, and an optional tee'd stdout transcript.
- Confirm whether stdout prints a slot line **before** each Red call; if so, emit a
  "Red thinking" start event from it.
- Tests: tailer against a fake match on the fake provider; event order; reconnect.
- **Done when:** a fake match streams every event type in order to a test client.
- Depends on: 1.

### 3. Dashboard live mode + Battle animation
- One `index.html`: LIVE via SSE, REPLAY via bundle (D49). Tabs: Battle / Compare / Report.
- Battle layout: Red | Target + scoreboard | Blue; timeline; event feed; header with
  act, timer, cost ticker. Projector-first: dark, large type, high contrast.
- Act 1: Red thinking → technique + typewriter payload → hit (status flash) → landed
  burst; benign slots as small dots; failure events (timeout, budget hit, invalid reply,
  guard block, send failure) shown as normal events.
- Act 2: radar sweep, "log lines analysed" from Blue ledger lines.
- Act 3: timeline flips one by one (TP / FN / quiet / FP), scoreboard reveal, summary
  card with "Why missed? → Compare".
- Honesty rules: D50.
- **Done when:** a fake live match and an existing bundle both play through all three acts.
- Depends on: 2.

### 4. Timing run — `needs-GO` `paid`
- One live match with the exact D46 config, `purpose=dev`, new seed, output outside
  `data/golden/`, watched in the new dashboard. Run in the DeepSeek peak window.
- Measure: wall clock; per-round Red and Blue latency; timeouts, retries, failed turns;
  cost per D39.
- Then fix the demo `red_timeout_s` and retry settings from the data (record as a decision).
- Prerequisite: DeepSeek balance topped up.
- **Done when:** measurements reported and demo timeout decided.
- Depends on: 3.

### 5. Free-play bundle + Compare view — `needs-GO` `test-set`
- Export the 3 free-play eval matches with original (live) and open (replay) verdicts,
  joined by `request_id`. Read-only; zero tokens.
- Compare view per D52: aggregate header, illustrative per-match table, divergent rows
  highlighted, landed column, row detail (technique, both verdicts), separate FP panel,
  instability note, audit-timing limitation badge.
- Data model supports N arms.
- **Done when:** the bundle plays in Compare from `file://` and every figure matches
  the committed stats.
- Depends on: 3.

### 6. Analyst: summary builder + grounding check
- **First, pre-register** the confidence rules (D55) in the decisions file before any
  summary is built. Proposal: audited and n ≥ 20 → High; audited and n < 20 → Moderate;
  unaudited (raw) → Low.
- `summary.json`: every figure the report may cite, computed by code from frozen
  evidence, each with its source artifact; plus descriptive fields (no raw payloads).
- Grounding check: every `{{placeholder}}` resolves; no bare numbers outside an
  allowlist; schema-valid JSON.
- Built and tested on fixtures and the fake provider. Building the real summary reads
  test-set data → GO.
- **Done when:** the grounding check rejects planted bad drafts (unknown placeholder,
  bare number, wrong shape) and accepts a valid one.
- Depends on: 1.

### 7. Analyst report + Report view — `needs-GO` `paid` `test-set`
- Probe: confirm the chosen OpenAI model accepts the analyst prompt; fallback
  `claude-sonnet-5-5` (D53). Analyst cap $1.
- Prompt: analysis, conclusions, decision criteria, no recommendation (D54); input is data.
- Render with Jinja2 (autoescape on, pinned) into the frozen template (D56); structure
  D57 with per-section authorship and the AI disclosure box; print CSS for PDF.
- Report view in the dashboard; decision record left blank for the human / audience vote.
- **Done when:** a grounded report renders in the dashboard and prints to PDF, and an
  XSS test string in an input field renders as text.
- Depends on: 6 (and 3 for the view).

### 8. E2E tests, failure drills, golden run — `needs-GO` `paid`
- Happy path end to end; failure drills per D58; Luna backup with prompt v3 (record
  whether it is accepted; else prompt v1).
- At least one run in the peak window, one on the demo laptop with a projector.
- Export the last clean run as the golden run bundle; keep a screen recording.
- **Done when:** every fallback has been switched to at least once and the golden run plays.
- Depends on: 4, 5, 7.

### 9. (Optional) Generic Compare: cost-paradox arms — `needs-GO` `test-set`
- Bundles for rules off / empty library / library v5 on the Gate 3 sources; three columns.
- Only if 1–8 are done. Otherwise the cost paradox stays a table in the slides.

## Schedule

| Date | Work |
|---|---|
| Nov 25 | 1, start 2 |
| Nov 26 | 2; start 6 |
| Nov 27 | 3; 4 in the evening peak window |
| Nov 28 | 5; 6 |
| Nov 29 | 7 |
| Nov 30 – Dec 1 | 8 |
| Dec 2 | Buffer, golden run final, freeze; 9 only if everything else is done |
| Dec 3 | Preflight in the afternoon, demo |

## Fallbacks

| Failure | Prevention | Response |
|---|---|---|
| Network down | Phone hotspot | Hotspot; else golden run |
| DeepSeek slow / timeout | Timeout from item 4 | Shown as a normal event |
| DeepSeek down / no balance | Top up beforehand | Switch Red to Luna (D46) |
| Anthropic (Blue) down | — | Golden run |
| Docker fails | Stack up before the session; `docker compose ps` | Golden run |
| Server / dashboard crash | — | `file://` + golden run |
| Match too long | Start at the opening, runs in background | Cut to golden run; return to the live result at the end |
| Laptop sleeps | `caffeinate -dims`, plugged in | — |
| Laptop / projector failure | — | Screen recording |

Rule: never debug on stage. Stuck for more than 30 seconds → switch.

## Demo-day preflight

- [ ] Balances: DeepSeek, OpenAI, Anthropic
- [ ] `docker compose up -d --wait`, then `docker compose ps`
- [ ] 2-call probe (`--probe`)
- [ ] Golden run bundle opens from `file://`
- [ ] Screen recording on the desktop
- [ ] Hotspot tested
- [ ] `caffeinate -dims`, plugged in, lid open

## Open questions

- Demo length and speaker split → decides the cut-over point and slide count (Nov 26).
- Demo timeout / retries → item 4.
- Does Luna accept free-play prompt v3? → item 8.
- Is there a "Red thinking" start event in stdout? → item 2.
- Which OpenAI model writes the report? → item 7 probe.
