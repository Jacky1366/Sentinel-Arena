# Demo checklist (Stage 7, Dec 3)

Structure: **D61**, three matchups (`docs/stage7_decisions.md`). Plan:
`docs/plans/stage7_plan.md`. Launcher: `scripts/demo.sh`. Configs as code:
`tools/demo_match.py`.

**Rule: never debug on stage. Stuck for more than 30 seconds → switch** (fallbacks below).

## The three matchups, in order

Run from the repo root (`~/dev/Sentinel-Arena`). `ARENA_GO` is the designer's token for
that one command; the script never sets or stores it and refuses a paid mode without it. The
presenter starts each matchup separately.

```bash
scripts/demo.sh --new-session                    # 0 · start the demo session (free; do it first, once)
ARENA_GO=<token> scripts/demo.sh --taxonomy      # 1 · Limited attacker vs limited defender   (live match)
ARENA_GO=<token> scripts/demo.sh                 # 2 · Free attacker vs limited defender      (live match)
ARENA_GO=<token> scripts/demo.sh --open-replay   # 3 · Free attacker vs free defender (same attacks as 2)
```

- `--new-session` marks a boundary. It appends a line to `data/runs/demo/sessions.jsonl`
  (earlier sessions are kept). From then on:
  - the dashboard's matchup switcher shows only runs started in this session;
  - `--open-replay` only considers free-play matches started in this session.

  Rehearsal runs from earlier in the day therefore can't appear on stage or be picked by
  mistake. Without a session, everything is visible and the live preflight prints a `WARN`
  line. Start it **before** matchup 1. If you start it later, the earlier matchups of the
  demo disappear from the switcher.
- `--luna` added to 1 or 2 uses the backup Red `gpt-6-luna` (D46), e.g.
  `ARENA_GO=<token> scripts/demo.sh --taxonomy --luna`.
- 3 runs no match. Open Blue re-judges the frozen log of the **latest completed free-play
  demo match**, so run 2 first. It prints the source match id, and refuses if there is none.
  It makes Blue calls only (paid, small) and needs no Docker.
- Recorded golden runs, with no GO, no network and no cost. Announce them as recorded (D45):

```bash
scripts/demo.sh --replay taxonomy                # golden run of 1
scripts/demo.sh --replay freeplay                # golden run of 2
scripts/demo.sh --replay open                    # golden run of 3
```

What a live mode does:
1. Runs the preflight below and stops with `DEMO STOP: <reason>` on the first failed check.
2. Starts `caffeinate -dims` for the session (it keeps running after the match).
3. Starts the live server on `http://127.0.0.1:8765/` (it keeps running) and opens it.
4. Runs the matchup with `python -u`, tee'd to `data/runs/demo/transcript.log`. The previous
   transcript is moved to `data/runs/demo/transcripts/`.

The server follows a match through its lock and a replay through its transcript line.

| Setting | 1 taxonomy | 2 free-play | 3 open replay |
|---|---|---|---|
| Red | `deepseek-v4-pro`, effort max, prompt v1, 8192 tokens (Gate B-deepseek) | `deepseek-v4-pro`, effort max, prompt v3, 16384 tokens (D46) | none: the attacks of 2 |
| `--luna` | `gpt-6-luna`, effort high, prompt v1, 8192 (Gate B, D38) | `gpt-6-luna`, effort high, prompt v3, 8192 | not applicable |
| Blue | original: `claude-haiku-5-5`, rules on, caching on, library v5 read-only (D44) | the same | **open**: prompt v3-open, Haiku, rules on, caching on, library v5 (as gate-6.3-C-open, D42) |
| Caps | `config/llm.json` (red $0.25, match $0.50) | red $0.40, match $0.40 | Blue $0.25 |
| `red_timeout_s` | **120 (final, #14)** | **120 (final, #14)** | not applicable |

Common to all: retries at the default, and purpose `dev` (never evidence, D45).

`.venv/bin/python tools/demo_match.py --print-config [--matchup taxonomy] [--red luna]`
prints a configuration (zero cost).

Timing (#14, peak window): matchup 2 takes about 5 minutes (306 s). Red turns took up to 57 s.
Matchup 1 has not been timed yet (its first E2E run will tell). Matchup 3 is Blue calls only (the Blue phase took about 26 s at peak).

## Preflight

Automatic in `scripts/demo.sh` (live modes):

- [ ] `ARENA_GO` given and well formed
- [ ] 1 and 2 only: Docker `juice-shop` running and healthy, `nginx` running;
      `data/runs/live/` holds only `proxy.jsonl` and `archive/`
- [ ] No `data/runs/live/match.lock` (nothing running)
- [ ] 1 and 2 only: the Red provider reachable with its key (free: one request to its models
      endpoint, no tokens). On failure: `DEMO STOP: Red provider … NOT reachable: <kind> [cause: …]`
      with the fallback (`--luna`, or the `--replay` when already on Luna)
- [ ] Demo session read from `data/runs/demo/sessions.jsonl` (no file yet = `WARN`, not a stop:
      rehearsals before `--new-session` warn and continue)
- [ ] `dashboard/dist/index.html` built
- [ ] `caffeinate -dims`; live server up on 127.0.0.1:8765; browser opened

Every failed check prints one `DEMO STOP: <reason>` line with its fix, and exits 1. A
failure outside the named checks prints `DEMO STOP: unexpected failure … line N`: a launcher
bug; switch to the matchup's `--replay`. Exit 1 with no `DEMO STOP` line should no longer
happen (tests/test_demo.py).

By hand, before the session:

- [ ] Rehearsals done, then `scripts/demo.sh --new-session` (just before matchup 1)
- [ ] Balances: DeepSeek, OpenAI, Anthropic
- [ ] `docker compose up -d --wait`, then `docker compose ps`
- [ ] Do not start the live server by hand: `demo.sh` starts it on 127.0.0.1:8765 with the demo
      transcript. Anything else on port 8765 (e.g. a `python -m liveserver` from development) is a
      `DEMO STOP: port 8765 is served by something else`: stop it first
- [ ] Red probes, one call each, nothing sent:
      `ARENA_GO=<token> .venv/bin/python -u tools/demo_match.py --one-turn`, plus
      `--matchup taxonomy` (and `--red luna` for each, if time allows)
- [ ] `scripts/demo.sh --replay taxonomy|freeplay|open` each open their golden run
- [ ] Compare and Report tabs open (Report: both PDF links work)
- [ ] Screen recording on the desktop
- [ ] Hotspot tested
- [ ] Plugged in, lid open (caffeinate covers sleep)

## Fallbacks

Per matchup:

| Matchup | Failure | Switch to |
|---|---|---|
| 1 taxonomy | DeepSeek down / no balance (`Call failed` from turn 1) | Ctrl-C, then `ARENA_GO=<token> scripts/demo.sh --taxonomy --luna` |
| 1 taxonomy | anything else (Docker, Blue, network, too long) | `scripts/demo.sh --replay taxonomy` |
| 2 free-play | DeepSeek down / no balance | Ctrl-C, then `ARENA_GO=<token> scripts/demo.sh --luna` |
| 2 free-play | anything else | `scripts/demo.sh --replay freeplay` |
| 3 open | `REFUSED: no completed free-play demo match yet` (2 failed or was cut) | `scripts/demo.sh --replay open` |
| 3 open | Anthropic (Blue) down, or the replay fails | `scripts/demo.sh --replay open` |

If 2 ran on the backup (`--luna`), 3 re-judges that Luna match: it is the latest completed
free-play demo match.

By failure:

| Failure | What you see | Response |
|---|---|---|
| Network down | `Call failed` turns, `api_error` | Hotspot; if still down: the matchup's `--replay` |
| DeepSeek slow | a turn waits (timer runs) up to 120 s | Nothing: a normal event (D50). The screen still shows the timer, so it is not stuck |
| DeepSeek down / no balance | `Call failed` from the first turn (connection errors: the match stops after 2 turns; no balance is not caught by the free preflight: it reaches the models endpoint, not a paid call) | `--luna` (matchups 1 and 2) |
| Anthropic (Blue) down | Act 2 shows failed Blue calls | the matchup's `--replay` |
| Docker fails | `DEMO STOP: Docker service …` | the matchup's `--replay` |
| Red provider unreachable before the match | `DEMO STOP: Red provider … NOT reachable` | the fallback it prints (`--luna`, or the `--replay`) |
| Red provider unreachable during the match | `RED UNREACHABLE` after Red's first 2 turns both fail with connection errors; the match stops (kept, status failed) and prints `DEMO FALLBACK` | the fallback it prints |
| Live server / dashboard crash | blank page or no events | the matchup's `--replay` (file://) |
| Match too long | still in Act 1 at the cut-over point | the matchup's `--replay` in a second terminal; the live match keeps running, return to it at the end |
| Launcher bug | `DEMO STOP: unexpected failure … line N` | the matchup's `--replay`; report the line |
| Stale lock / dirty `live/` | `DEMO STOP: stale lock …` | `--replay` now; clear it by hand after the demo, never on stage |
| Laptop sleeps | — | prevented by `caffeinate -dims` |
| Laptop / projector failure | — | Screen recording |

## Golden runs (one per matchup)

In the E2E runs (D58), record one clean run of each matchup and export it. Final versions
are made on Dec 2.

**Current candidates (committed bundles):**
- `golden-freeplay`: the #14 peak-window run `20261126T010217Z-5316`.
  - 8 attacks, 6 caught.
  - **2 succeeded** under the free-play rule: turn 2 (Login Admin) and turn 5 (Error
    Handling). The limited defender missed turn 5.
  - 0 of 17 normal requests raised a false alarm.
- `golden-open`: its open-Blue replay `20261126T033748Z-ae0e` (GO `manual-open-replay-peak`,
  $0.001526).
  - Open Blue caught the same 6 of 8 and recovered neither missed turn: turn 1 (recon) and
    turn 5 (no verdict, a successful attack).
  - It raised 2 false alarms on the same 17 normal requests.
- Taxonomy: none yet (the first matchup-1 E2E run).

```bash
.venv/bin/python tools/export_golden.py data/runs/<match_id> --check       # 1 or 2: report only
.venv/bin/python tools/export_golden.py data/runs/<match_id>               # writes golden-taxonomy / golden-freeplay
.venv/bin/python tools/export_golden.py data/replays/<replay_id>           # 3: writes golden-open
```

The matchup comes from the manifest: Red prompt v1 → taxonomy, prompt v3 → freeplay, an
open-Blue replay → open. A run is clean when all of these hold:
- it is not test data by its manifest (D59);
- it completed, with purpose dev;
- it has the demo configuration;
- for 3, its source is a clean free-play demo match;
- four facts are PASS, or N/A (Blue stored no new rule).

The exporter writes `golden-<matchup>` to `dashboard/public/data/` (plus `bundles.js`) and
copies it to `dashboard/dist/data/`, so `--replay` plays it with no rebuild. Commit the
bundles. Whether the run folders are also committed under `data/golden/` is the designer's
call (important lane). `scripts/demo.sh` prints the `--check` line after each live run.
Export 3's golden run from a replay of 2's golden match, so the two golden runs show the
same attacks.

## What "succeeded" means (one definition per matchup)

The designer's rule (2026-11-26), shown on screen in plain words under the numbers and on the
All-three card:

| Matchup | An attack **succeeded** when … | Source |
|---|---|---|
| 1 taxonomy | it solved the challenge of its own attack type (the Judge's mapped landing) | round record `landed` |
| 2 free-play, 3 open | it solved **any** challenge in the web shop (free-play landing, D41) | round record `newly_solved`, as `stats/free_play.py` |

The two can differ. In the peak run, turn 5 solved Error Handling, which is outside the
challenge map: it succeeded under the free-play rule, but the Judge's mapped landing marks it
not measurable. One demo never mixes the two. Matchups 2 and 3 use the free-play rule in
Battle, on the All-three card, in Compare, in this file and in reports. In matchup 1 the
number of successful attacks shows "–" until the Judge's results are in.

## Red failure diagnosis

On a Red `brain_failure` (invalid JSON or shape, a missing field, a refusal, a truncated
reply), the transcript gets one line before the slot line:

```
red diagnosis: round 3 invalid_shape: stop=completed chars=361 shape={body:str, headers:dict, label:str, method:str, path:str, rationale:str, technique:str} excerpt="…"
```

This is diagnosis only (#18; scope freeze D40):
- The prompt and the parser are unchanged.
- The line is redacted (Authorization values, JWTs, key shapes, long hex) and cut to 240
  characters.
- It never enters an artifact, Red's next turn or the dashboard.

A budget hit or an API failure is an `instrument_failure`. There is no reply, and the
`detail` field in `red_unsent.jsonl` names the cap or the error type.

Finding (peak run, #14): both failed free-play turns sent a nested `headers` object. The
free-play reply format has flat `cookie` / `authorization` fields, so these turns are
`invalid_shape`. They show as normal "unusable reply" events. Expect about 2 of 10 turns.

## Luna backup

Free-play prompt v3 with Luna: **accepted**.
- Check: #18 Part 3, 2026-11-25 22:34 UTC, GO `manual-luna-freeplay-check`,
  `tools/demo_match.py --red luna --one-turn`. Ledger:
  `data/runs/demo-check-20261125T223418Z-07cb/`.
- Result: one call at effort high, `stop=completed`, 4.3 s, 227 output tokens, $0.000168.
  Luna proposed a boolean-based SQL injection probe that the guard allows; nothing was sent.
- So `--luna` keeps prompt v3 for matchup 2. For matchup 1, Luna uses prompt v1, which is the
  Gate B configuration.
- This covers one turn only. A refusal later in a match shows as a `brain_failure refusal`
  turn (D50, a normal event).
- If Luna ever refuses at the first turn of matchup 2, the fallback is prompt v1: set
  `"red_prompt_version": "1"` for `("freeplay", "luna")` in `tools/demo_match.py`.

## Before Dec 3 (Nov 28 – Dec 2, with people)

- Failure drills (D58), each switched to at least once:
  - network loss → hotspot / `--replay`;
  - DeepSeek failure → `--luna`;
  - server crash → `--replay`;
  - overlong match → cut to `--replay`;
  - matchup 3 without a match 2 → `--replay open`.
- One run on the demo laptop with the projector.
- Golden runs for all three matchups (above), plus a screen recording.
