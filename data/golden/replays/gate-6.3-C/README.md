# Stage 6.3 Gate C: Blue arms on the Gate B traffic

Six Blue replays (D17), from `ARENA_GO=gate-6.3-C tools/stage6_3_check.py --gate C --matches
data/golden/eval-6.3-gateB-match{1,2,3} --real-calls`.
- **Run on** 2026-11-18, from a clean tree at commit `ea07305`.
- **Copied from** `data/replays/gate-6.3-C-20261119T062226Z-0ce5/`. Never rewritten.
- **Sources:** the three Gate B eval matches (TEST data, D35). Red is `gpt-6-luna` at effort
  high with an 8192-token output budget (D38).
- **Design (D34 as amended):** each source is replayed twice. Both arms use claude Blue,
  rules on, caching on, prompt v2.
  - `-sonnet-v5`: Sonnet 5.5 with library v5 (19 rules, sha256 `324a1eceace9…`). Thinking is
    off as `between_tools`, which Sonnet 5.5 requires because it rejects `disabled`. The
    prompt and the other request settings are the same.
  - `-haiku-empty`: Haiku 5.5 with the explicitly loaded empty library v0000 (thinking
    `disabled`, as in Gate B). This isolates library transfer.
  - The live Gate B match itself is the third arm: Haiku 5.5 with library v5.

## Result (raw detection; the full audit is pending)

| source | arm | AI calls | cost | lines answered: library / in-match rule / AI | detection | FP |
|---|---|---|---|---|---|---|
| gateB-match1 | Haiku + v5 (live) | 19 | $0.001307 | 8 / 0 / 19 of 27 | 9/10 | 0/17 |
| gateB-match1 | Sonnet + v5 | 19 | $0.022905 | 8 / 0 / 19 of 27 | 9/10 | 0/17 |
| gateB-match1 | Haiku + empty | 25 | $0.001674 | 0 / 2 / 25 of 27 | 9/10 | 0/17 |
| gateB-match2 | Haiku + v5 (live) | 20 | $0.001189 | 6 / 1 / 20 of 27 | 9/10 | 0/17 |
| gateB-match2 | Sonnet + v5 | 20 | $0.020302 | 6 / 1 / 20 of 27 | 9/10 | 0/17 |
| gateB-match2 | Haiku + empty | 25 | $0.001657 | 0 / 2 / 25 of 27 | 9/10 | 0/17 |
| gateB-match3 | Haiku + v5 (live) | 20 | $0.001255 | 7 / 0 / 20 of 27 | 10/10 | 0/17 |
| gateB-match3 | Sonnet + v5 | 20 | $0.021366 | 7 / 0 / 20 of 27 | 10/10 | 0/17 |
| gateB-match3 | Haiku + empty | 25 | $0.001717 | 0 / 2 / 25 of 27 | 10/10 | 0/17 |

- **Gate C total:** 129 calls, $0.069621.
- **Ceiling:** every arm detects the same rounds, so neither the stronger Red nor the
  stronger Blue moved detection off the ceiling. The two missed rounds are the
  `GET /#/search` proposals discussed in the Gate B audit sheet.
- **Library transfer:** v5, learned from Luna-low train traffic, answered 6–8 of 27 lines per
  match on Luna-high traffic. Against the empty library it saved 5–6 AI calls per match
  (Haiku) at equal detection and FP.
- **Live-arm figures** come from the Gate B `match.json` files; the "lines answered" column is
  read from their verdicts.

`tests/test_gate_6_3_gateC_evidence.py` checks every file against its `replay.json` hash,
the source links, the library snapshots, the arm configuration and the cost.
