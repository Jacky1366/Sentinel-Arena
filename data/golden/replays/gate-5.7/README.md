# Stage 5.7 Gates 2 and 2b evidence: 8 cached Blue replays (rules on / off, caching on)

These folders are copies of two real-call gate runs. Each ran after the designer's GO, on
Nov 14, 2026:

- **Gate 2** (rules on): `data/replays/gate2-5.7-20261114T064924Z-9c51/`, run with
  `tools/stage5_7_check.py --gate 2 --real-calls`.
- **Gate 2b** (rules off): `data/replays/gate2b-5.7-20261114T071658Z-9e46/`, run with
  `tools/stage5_7_check.py --gate 2 --rules-mode off --real-calls`.

AI output is not reproducible, so the runs are kept here rather than re-run.

Each folder is one replay (D17, `tools/replay_blue.py`) of a golden match's inputs, with
claude Blue and caching on. Together with the committed gate-5.5 `*-off` and `*-on` replays
(`../gate-5.5/`, caching off), they make the 2×2 of rules off/on × caching off/on on the
same traffic. Each replay started with zero rules (D7).

## Configuration

| Setting | Value |
|---|---|
| Code | Gate 2: commit `5d6013d964a6`; Gate 2b: commit `bb4eeeb2c84f` (adds only `--rules-mode` to the gate tool). Both from a clean tree (`git.dirty: false`). |
| Judge | `JUDGE_VERSION` 0.6.0 |
| Blue | Anthropic `claude-haiku-5-5`, `anthropic==2.3.0`, `chunk_size` 1, `max_output_tokens` 512, thinking disabled, effort low, structured output |
| Caching | on: one explicit breakpoint on the system block, 5-minute TTL (`blue_params.caching = {mode: on, ttl: 5m}`) |
| Prompts | `*-off-cached`: v1 (sha256 `938ea67c385a…`, as Stage 5.4); `*-on-cached`: v2 (sha256 `cf440507f446…`) |
| Rules | `max_rules` 10; rules on = hot-loaded |
| Price table | `config/prices.json` as of 2026-11-12 |

## Replays

| Folder | Source (golden) | Replay id | AI calls | Cost | Cache read / write (tok) |
|---|---|---|---|---|---|
| `ai-red-luna-gate2-match1-on-cached` | `ai-red-luna-gate2-match1` | `20261114T064924Z-41d0` | 21 | $0.001557 | 35,920 / 1,796 |
| `ai-red-luna-gate2-match2-on-cached` | `ai-red-luna-gate2-match2` | `20261114T064956Z-6b0b` | 23 | $0.001522 | 41,308 / 0 |
| `ai-red-luna-gate2-match3-on-cached` | `ai-red-luna-gate2-match3` | `20261114T065026Z-f287` | 24 | $0.001574 | 43,104 / 0 |
| `scripted-baseline-benign-match-on-cached` | `scripted-baseline-benign-match` | `20261114T065100Z-c831` | 22 | $0.001439 | 39,512 / 0 |
| `ai-red-luna-gate2-match1-off-cached` | `ai-red-luna-gate2-match1` | `20261114T071658Z-e814` | 27 | $0.001421 | 20,280 / 780 |
| `ai-red-luna-gate2-match2-off-cached` | `ai-red-luna-gate2-match2` | `20261114T071737Z-05f4` | 27 | $0.001342 | 21,060 / 0 |
| `ai-red-luna-gate2-match3-off-cached` | `ai-red-luna-gate2-match3` | `20261114T071816Z-ddf7` | 26 | $0.001261 | 20,280 / 0 |
| `scripted-baseline-benign-match-off-cached` | `scripted-baseline-benign-match` | `20261114T071851Z-d884` | 24 | $0.001177 | 18,720 / 0 |

**Totals.** Gate 2 cost $0.006092 for 90 calls; the same calls would have cost $0.020433
uncached. Gate 2b cost $0.005201 for 104 calls, against $0.012412 uncached.

Only the first replay of each gate paid a cache write. The later replays reused that entry,
because they ran with the same prompt within 5 minutes.

Every verdict matches the committed gate-5.5 replay with the same rules mode exactly, so
whole-match detection, FP and type accuracy are unchanged. There were no `max_tokens`
stops, no refusals and no unpriced usage. The four-facts check gives PASS for every
`*-on-cached` folder and N/A (no rules) for every `*-off-cached` folder. The results and
the 2×2 are in `docs/progress.md` (Stage 5.7).

## Integrity

`replay.json` (schema 0.2) lists every other file with its sha256 and size. Its `source`
field records the golden match's `match.json` sha256 and that match's artifact hashes; the
copied inputs match them byte for byte.

`tests/test_gate_5_7_evidence.py` checks:
- the hashes, the links to the sources and the configuration;
- that every verdict equals the committed gate-5.5 counterpart;
- the headline numbers;
- that the Judge, re-run offline on each folder, produces byte-identical outputs.

A Judge change that alters these outputs must update that test on purpose. The files here
are never rewritten.
