# Stage 6.1b Gate 2 (M5): library replay evidence

Six Blue replays (D17), from `ARENA_GO=gate-6.1b-2 tools/stage6_1_check.py --gate 2
--library data/library/rule_library_v0005.json --real-calls`.
- **Run on** 2026-11-18, from a clean tree at commit `fe37b2f`.
- **Copied from** `data/replays/gate2-6.1-20261119T012107Z-20d7/`. Never rewritten.
- **Design (D29):** the three Stage 5.7 Gate 3 sources (TEST data, S6-1) are each replayed
  twice, with all else identical: claude Blue Haiku 5.5, rules on, caching on.
  - `-empty`: the explicitly loaded empty library v0000 (sha256 `152ca18cbd45…`).
  - `-library`: library v5, 19 rules (sha256 `324a1eceace9…`), promoted from the Gate 1
    train matches only.
  - Each folder holds `replay.json` (source hashes, `blue_params.library`) and the
    `library.json` snapshot.

## Result

| source | arm | AI calls | cost | lines answered: library / in-match rule / AI | detection (raw / audited) | FP |
|---|---|---|---|---|---|---|
| gate3-match1 | empty | 23 | $0.001753 | 0 / 3 / 23 of 26 | 9/9 / 9/9 | 0/17 |
| gate3-match1 | library | 17 | $0.000963 | 9 / 0 / 17 of 26 | 9/9 / 9/9 | 0/17 |
| gate3-match2 | empty | 23 | $0.001476 | 0 / 3 / 23 of 26 | 8/9 / 8/8 | 0/17 |
| gate3-match2 | library | 18 | $0.001005 | 8 / 0 / 18 of 26 | 8/9 / 8/8 | 0/17 |
| gate3-match3 | empty | 24 | $0.001602 | 0 / 3 / 24 of 27 | 10/10 / 10/10 | 0/17 |
| gate3-match3 | library | 17 | $0.000965 | 10 / 0 / 17 of 27 | 10/10 / 10/10 | 0/17 |
| **total** | empty | **70** | **$0.004831** | 0 / 9 / 70 | | |
| **total** | library | **52** | **$0.002933** | 27 / 0 / 52 | | |

- **Primary (AI calls and cost):** −18 calls (−26%) and −$0.001898 (−39%) with the
  library. Detection, type accuracy and FP are identical between the arms.
- **In-match rules:** the empty arm invented 6, 5 and 7 rules. The library arm invented
  none, because the library answered every attack line before the AI saw it.
- **Holdout:** 0 hits for every one of the 19 library rules on `benign/holdout_v1.jsonl`
  (offline, scoring only).
- **Gate cost:** $0.007764 (6 replays, Blue only).
