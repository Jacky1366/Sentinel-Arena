# Stage 5.5 gate evidence: 12 Blue replays (rule invention off / shadow / on)

These folders are a copy of the Stage 5.5 gate run (Part F),
`data/replays/gate-5.5-20261114T052856Z-b29c/`. The gate was run on Nov 13, 2026 with
`tools/stage5_5_check.py --real-calls` after the designer's GO. It completed 12/12
replays and left the golden folders unchanged. AI output is not reproducible, so the run
is kept here instead of being re-run.

Each folder is one replay (D17, `tools/replay_blue.py`). Blue and the full Judge ran on
a copy of a frozen golden match's inputs, so no traffic was sent. Each replay started
with zero rules (D7).

## Configuration

| Setting | Value |
|---|---|
| Code | commit `072e9d72daa8` (branch `stage5.5-rules-invention`), `git.dirty: false` |
| Judge | `JUDGE_VERSION` 0.6.0 |
| Blue | Anthropic `claude-haiku-5-5`, `anthropic==2.3.0`, `chunk_size` 1, `max_output_tokens` 512 (all modes), thinking disabled, effort low, structured output |
| Prompts | off: v1 (sha256 `938ea67c385a…`, identical to Stage 5.4); shadow and on: v2 (sha256 `cf440507f446…`) |
| Rules | `max_rules` 10; shadow = validated + recorded + scored, never hot-loaded; on = hot-loaded |
| Price table | `config/prices.json` as of 2026-11-12 |

## Replays

| Folder | Source (golden) | Source match_id | Replay id | AI calls | Cost |
|---|---|---|---|---|---|
| `ai-red-luna-gate2-match1-off` | `ai-red-luna-gate2-match1` | `20261113T052633Z-77ac` | `20261114T052856Z-c33d` | 27 | $0.003230 |
| `ai-red-luna-gate2-match1-shadow` | 〃 | 〃 | `20261114T052939Z-2cb5` | 27 | $0.006304 |
| `ai-red-luna-gate2-match1-on` | 〃 | 〃 | `20261114T053020Z-749e` | 21 | $0.004743 |
| `ai-red-luna-gate2-match2-off` | `ai-red-luna-gate2-match2` | `20261113T052837Z-01d4` | `20261114T053048Z-da88` | 27 | $0.003226 |
| `ai-red-luna-gate2-match2-shadow` | 〃 | 〃 | `20261114T053128Z-c123` | 27 | $0.006261 |
| `ai-red-luna-gate2-match2-on` | 〃 | 〃 | `20261114T053207Z-98e0` | 23 | $0.005261 |
| `ai-red-luna-gate2-match3-off` | `ai-red-luna-gate2-match3` | `20261113T053039Z-4645` | `20261114T053239Z-3984` | 26 | $0.003080 |
| `ai-red-luna-gate2-match3-shadow` | 〃 | 〃 | `20261114T053320Z-bbad` | 26 | $0.005965 |
| `ai-red-luna-gate2-match3-on` | 〃 | 〃 | `20261114T053402Z-4c54` | 24 | $0.005478 |
| `scripted-baseline-benign-match-off` | `scripted-baseline-benign-match` | `20261109T021518Z-7d72` | `20261114T053436Z-3a56` | 24 | $0.002852 |
| `scripted-baseline-benign-match-shadow` | 〃 | 〃 | `20261114T053512Z-883e` | 24 | $0.005491 |
| `scripted-baseline-benign-match-on` | 〃 | 〃 | `20261114T053546Z-a4a7` | 22 | $0.004996 |

Total: 298 calls, **$0.0569**. There were no refusals, failed attempts or
`max_tokens` stops. The results and their interpretation are in `docs/progress.md`
(Stage 5.5, gate results).

## Integrity

- Each folder's `replay.json` → `artifacts` lists every other file with its sha256 and
  size.
- `replay.json` → `source` records the golden match's `match.json` sha256 and its
  artifact hashes. The copied inputs (proxy log, Red attacks, benign requests,
  snapshots, red_unsent) match those hashes byte for byte.
- The verdicts keep the source `match_id`, so the source's D16 audit
  (`data/golden/audits/`) applies to each replay.

`tests/test_gate_5_5_evidence.py` checks the hashes and the links to the sources. It also
re-runs the Judge offline on each folder (fact 1, round records, fact 4a, red facts,
facts 3 + 4b with the rule cross-check) and requires byte-identical outputs. A future
Judge change (a new `JUDGE_VERSION`) that changes these outputs must update that test
on purpose; the files here are never rewritten.
