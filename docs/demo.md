# Demo checklist (Stage 7, Dec 3)

Plan: `docs/plans/stage7_plan.md` (Fallbacks, Demo-day preflight). Decisions: D45–D58 in
`docs/stage7_decisions.md`. Launcher: `scripts/demo.sh`; config as code: `tools/demo_match.py`.

**Rule: never debug on stage. Stuck for more than 30 seconds → switch** (table below).

## The three commands

Run from the repo root (`~/dev/Sentinel-Arena`). `ARENA_GO` is the designer's token for
that one command; the script never sets or stores it and refuses a live mode without it.

```bash
ARENA_GO=<token> scripts/demo.sh            # LIVE: DeepSeek Red (D46), the primary
ARENA_GO=<token> scripts/demo.sh --luna     # LIVE: backup Red gpt-6-luna (D46)
scripts/demo.sh --replay                    # RECORDED golden run from file:// (no GO, no network, no cost)
```

A live mode runs the preflight below and stops with `DEMO STOP: <reason>` on the first
failed check. It then starts `caffeinate -dims` for the session (kept after the match),
starts the live server on `http://127.0.0.1:8765/` (kept running) and opens it, and runs
the match with `python -u`, tee'd to `data/runs/demo/transcript.log` (the previous one is
moved to `data/runs/demo/transcripts/`). `--replay` must be announced as recorded (D45).

| Setting | Value | Source |
|---|---|---|
| Red | `deepseek-v4-pro`, effort max, free-play prompt v3, 16384 output tokens | D46 = Gate B-freeplay |
| Backup Red (`--luna`) | `gpt-6-luna`, effort high, 8192 output tokens, prompt v3 (see Luna below) | D46, D38 |
| Blue | `claude-haiku-5-5`, rules on, caching on, library v5 read-only | D44 |
| Caps | red $0.40, match $0.40 | free-play arm |
| `red_timeout_s` | **120, provisional** until the #18 peak-window run | #14 |
| Retries | default (`config/llm.json`) | #14 designer decision |
| Purpose | `dev`: a sample, never evidence | D45 |

`.venv/bin/python tools/demo_match.py --print-config [--red luna]` prints it (zero cost).

## Preflight

Automatic in `scripts/demo.sh` (live modes):

- [ ] `ARENA_GO` given and well formed
- [ ] Docker: `juice-shop` running and healthy, `nginx` running
- [ ] `data/runs/live/` holds only `proxy.jsonl` and `archive/`; no `match.lock`
- [ ] `dashboard/dist/index.html` built
- [ ] `caffeinate -dims`; live server up on 127.0.0.1:8765; browser opened

By hand, before the session:

- [ ] Balances: DeepSeek, OpenAI, Anthropic
- [ ] `docker compose up -d --wait`, then `docker compose ps`
- [ ] Red probe, one call, nothing sent:
      `ARENA_GO=<token> .venv/bin/python -u tools/demo_match.py --one-turn` (and `--red luna`)
- [ ] `scripts/demo.sh --replay` opens the golden run
- [ ] Compare and Report tabs open (Report: both PDF links work)
- [ ] Screen recording on the desktop
- [ ] Hotspot tested
- [ ] Plugged in, lid open (caffeinate covers sleep)

## Fallbacks

| Failure | What you see | Switch to |
|---|---|---|
| Network down | `Call failed` turns, `api_error` | Hotspot; if still down: `scripts/demo.sh --replay` |
| DeepSeek slow / timeout | a turn waits up to 120 s, then `Call failed` | Nothing: shown as a normal event (D50). Stuck > 30 s with no new event → `--replay` |
| DeepSeek down / no balance | `Call failed` from the first turn | Ctrl-C, then `ARENA_GO=<token> scripts/demo.sh --luna` |
| Anthropic (Blue) down | Act 2 shows failed Blue calls | `scripts/demo.sh --replay` |
| Docker fails | `DEMO STOP: Docker service …` | `scripts/demo.sh --replay` |
| Live server / dashboard crash | blank page or no events | Open `dashboard/dist/index.html` from Finder, or `scripts/demo.sh --replay` |
| Match too long | still in Act 1 at the cut-over point | `scripts/demo.sh --replay` in a second terminal (the live match keeps running; return to it at the end) |
| Stale lock / dirty `live/` | `DEMO STOP: stale lock …` | `--replay` now; clear by hand after the demo, never on stage |
| Laptop sleeps | — | prevented by `caffeinate -dims` |
| Laptop / projector failure | — | Screen recording |

## Golden run

The last clean end-to-end run becomes the golden run (D58), on Dec 2:

```bash
.venv/bin/python tools/export_golden.py data/runs/<match_id> --check   # report only
.venv/bin/python tools/export_golden.py data/runs/<match_id>           # write golden-run
```

Clean = status completed, purpose dev, not test data by its manifest (D59), the demo
configuration (Blue D46; Red DeepSeek or Luna) and four facts PASS (or N/A: Blue stored no
rule). It writes the bundle `golden-run` (`dashboard/public/data/` + `bundles.js`) and
copies it into `dashboard/dist/data/`, so `--replay` plays it with no rebuild. Commit the
bundle. Whether the match folder is also committed under `data/golden/` is the designer's
call (important lane). `scripts/demo.sh` prints the `--check` line after each live match.

## Red failure diagnosis

On a Red `brain_failure` (invalid JSON or shape, missing field, refusal, truncated) the
transcript gets one line before the slot line:

```
red diagnosis: round 4 invalid_shape: stop=completed chars=812 shape={label:str, method:str, notes:dict, path:str} excerpt="…"
```

Diagnosis only (#18; scope freeze D40): the prompt and the parser are unchanged, the line
is redacted (Authorization values, JWTs, key shapes, long hex) and cut to 240 characters,
and it never enters an artifact, Red's next turn or the dashboard. A budget hit or an API
failure is an `instrument_failure`: there is no reply; `red_unsent.jsonl` `detail` names
the cap or the error type.

## Luna backup

Free-play prompt v3 with Luna: **accepted** (#18 Part 3, 2026-11-25 22:34 UTC, GO
`manual-luna-freeplay-check`, `tools/demo_match.py --red luna --one-turn`, ledger
`data/runs/demo-check-20261125T223418Z-07cb/`). One call, effort high: `stop=completed`,
4.3 s, 227 output tokens, $0.000168. It proposed a boolean-based SQL injection probe that the
guard allows; nothing was sent. So `--luna` keeps prompt v3. This covers one turn only: a
refusal later in a match would show as a `brain_failure refusal` turn (D50, a normal event).
If it ever refuses at the first turn, the fallback is prompt v1 (taxonomy, validated in
Gate B): set `"red_prompt_version": "1"` for `luna` in `tools/demo_match.py`.

## Before Dec 3 (Nov 28 – Dec 2, with people)

- Failure drills (D58), each switched to at least once: network loss → hotspot / replay;
  DeepSeek failure → `--luna`; server crash → `file://` replay; overlong match → cut to
  `--replay`.
- One run on the demo laptop with the projector.
- Final golden run export (above); screen recording of it.
