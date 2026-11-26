# Live server (Stage 7, D48)

A read-only tail of a running match, streamed to the dashboard over Server-Sent Events.
Python standard library only, bound to `127.0.0.1`, GET/HEAD only. It makes no decision,
computes no score and cannot start a match: a match is launched from a terminal with
`ARENA_GO`, so `agents/llm_client.py` stays the only path to a paid call.

## Run

```bash
# terminal 1: the server (any free port; 8080 / 8081 / 3000 are refused)
.venv/bin/python -m liveserver --port 8765 --transcript data/runs/demo.transcript.log

# terminal 2: the match, stdout UNBUFFERED (-u) and tee'd to the transcript
setopt pipefail   # zsh; `set -o pipefail` in bash
ARENA_GO=manual-<what> .venv/bin/python -u run_match.py <flags> 2>&1 | tee data/runs/demo.transcript.log
```

- **`-u` is required for the transcript.** Piped to `tee`, Python block-buffers stdout, and
  the transcript would arrive in multi-KB bursts.
- The transcript is optional. Without it, every artifact event still streams, but
  `match_plan`, `target_reset`, `slot_done` and `match_failed` are missing, and each
  `red_turn_start` comes with the round's first line (no thinking time).
- Use a fresh transcript file per match. Keep it outside `data/runs/live/`, which must
  hold only `proxy.jsonl` and `archive/` between matches.
- Open `http://127.0.0.1:8765/` in the browser (the dashboard from `dashboard/dist/`).
  Events: `GET /events`. Reconnect with `Last-Event-ID` (browsers do this themselves) or
  `?last_id=N`.

## Events

Each SSE message is `id: N` + `data: {"id": N, "type": ..., "observed_at": <UTC, when the server saw it>, "match_id": ..., ...}`. Artifact
events carry the line as `row`. A client connecting mid-match receives the whole current
match first; `match_started` starts a new history (reset the view).

| type | from | extra fields |
|---|---|---|
| `match_started` | `live/match.lock` (or the transcript's `match <id> ->` line; or its `replay <id> of <match> -> <dir>` line for a Blue replay under `data/replays/`, D61 matchup 3) | `pid`, `started_at`, `source`, `kind` (`match` \| `replay`), `source_match_id` (replay: the re-judged match) |
| `match_plan` | transcript `seed …` line | `seed`, `n_red`, `n_benign`, `planned` (kinds in slot order; `derived: true`, the orchestrator's `runner/schedule.plan`) |
| `target_reset` | transcript | `solved` |
| `library_loaded` | `<run>/library.json` | `library_version`, `n_rules` |
| `red_turn_start` | previous slot's `slot_done` + plan (`source: "transcript"`), or the round's first line (`source: "round_event"`) | `round`, `slot`, `derived: true` |
| `api_call` | `api_calls.jsonl` | `row`, `usd`, `usd_lower_bound` (stats/cost.py; D39 `rate_window` in `row`) |
| `red_unsent` | `red_unsent.jsonl` | `row` (`kind`: guard_block / brain_failure / instrument_failure) |
| `red_attack`, `benign_request` | `red_attacks.jsonl`, `benign_requests.jsonl` | `row` |
| `proxy_line` | `live/proxy.jsonl`, then `<run>/proxy.jsonl` after freeze | `row` (only lines whose `request_id` this match sent) |
| `snapshot` | `challenge_snapshots.jsonl` | `row`, `newly_solved` |
| `slot_done` | transcript slot line | `slot`, `kind`, `round` / `benign_id`, `text` |
| `proxy_frozen` | `<run>/proxy.jsonl` appears | — |
| `challenge_catalog` | `challenge_catalog.json` (free-play) | `categories` |
| `landed`, `verdict`, `rule`, `rule_rejection`, `round_record`, `benign_result`, `anomaly`, `rule_result` | the Judge / Blue files, after traffic (D47) | `row` |
| `match_failed` | transcript `MATCH FAILED at step …` | `step`, `error` |
| `schedule_mismatch` | a slot line disagrees with the plan (derivation stops) | `slot`, `kind` |
| `tail_warning` | a malformed line | `file` |
| `match_finished` | `<run>/match.json`, after the lock is gone | `status`, `failed_step`, `error`, `cost_usd`, `tail_counts` (stray / unknown / malformed) |
| `lock_released` | lock removed | — |

**Order.** Each poll reads files in reverse causal order (effects first) and emits in causal
order: Red call → Red record → proxy line → snapshot, all traffic before Blue's calls, Blue's
calls before verdicts, the Judge last. A proxy line is emitted only after the record carrying
its `request_id`. Lines with an empty id are stray; ids this match never sent (the previous
match's log, before rotation) are counted as unknown, never emitted.

**"Red thinking" (#12 finding).** stdout prints nothing before a Red call: the slot line comes
after the send and the snapshot. The start of Red's turn is therefore derived: the
transcript's seed line gives the planned slot kinds (seed + counts are all
`runner/schedule.plan` needs), and when slot *k* is reported done and slot *k+1* is Red, Red's
turn starts. Marked `derived: true`; it is triggered by a real stdout line (D50).
