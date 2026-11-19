# Stage 6.1b Gate 2b: the rules-off arm on the M5 sources

Three Blue replays (D17), from `ARENA_GO=gate-6.1b-2b tools/stage6_1_check.py --gate 2b
--real-calls`.
- **Run on** 2026-11-18, from a clean tree at commit `d65e2cd`.
- **Copied from** `data/replays/gate2b-6.1-20261119T012825Z-6943/`. Never rewritten.
- **Design (designer, 2026-11-18):** the same three Stage 5.7 Gate 3 sources as Gate 2
  (`../gate-6.1b-2/`, TEST data, S6-1), replayed with claude Blue Haiku 5.5, rules **off**
  (prompt v1), caching on, no library.
- **Why:** all three arms (rules off / rules on with the empty library / rules on with
  library v5) are then like-for-like on the same sources.

## Result, and the three arms

| arm | AI calls | Blue cost | lines: library / in-match rule / AI | detection (raw / audited) | FP |
|---|---|---|---|---|---|
| rules off (this folder) | **79** (26 / 26 / 27) | **$0.003945** | 0 / 0 / 79 | 27/28 / 27/27 | 0/51 |
| rules on, empty v0000 (Gate 2) | 70 (23 / 23 / 24) | $0.004831 | 0 / 9 / 70 | identical | 0/51 |
| rules on, library v5 (Gate 2) | 52 (17 / 18 / 17) | $0.002933 | 27 / 0 / 52 | identical | 0/51 |

Per source, rules off: $0.001385, $0.001232 and $0.001328. Detection, type accuracy and FP
are identical in all three arms. Gate cost: $0.003945.
