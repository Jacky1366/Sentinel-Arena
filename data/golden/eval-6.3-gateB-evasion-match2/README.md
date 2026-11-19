# Stage 6.3 Gate B-evasion, eval match 2 of 3

This folder is a copy of one complete **eval** match, `20261119T083408Z-2665`. It is match 2 of 3 of Stage 6.3
Gate B-evasion (D40), the final experiment, run with `ARENA_GO=gate-6.3-B-evasion
tools/stage6_3_check.py --gate B-evasion --real-calls`. The other matches of the batch are
`../eval-6.3-gateB-evasion-match1/`, `../eval-6.3-gateB-evasion-match3/`.

- **The one treatment variable** against Gate B-deepseek is **Red prompt v2**: prompt v1 plus
  the pre-registered evasion directive, appended verbatim (sha256 `a826b6f4…`, recorded in
  `match.json` `red_params`). Red never saw Blue's verdicts (D6).
- **Red:** `deepseek-v4-pro` at effort max, `max_output_tokens` 8192, client timeout 180 s
  (`red_params.request.timeout_s`).
- **Caching:** automatic (`ttl: auto`).
- **Pricing:** every call is priced by its own timestamp (D39); all calls fell in a peak
  window.
- **Blue:** `claude-haiku-5-5`, rules on, caching on, library v5 READ-ONLY, Blue prompt
  unchanged.
- **Run settings:** `--purpose eval`, seed 6322.
- **Code and stack:** a clean tree at commit `8e64792` (`git.dirty: false`), on a freshly
  reset Target.
- **Status:** **TEST data** (D35), registered in `config/test_set.json`. It is never
  promoted, and never used to select or tune rules.
- DeepSeek did not refuse the directive.

Every file except this README is listed in `match.json` → `artifacts` with its sha256.
`tests/test_gate_6_3_gateB_evasion_evidence.py` checks them. Re-running would make real,
paid calls. The files here are never rewritten.

## Label audit (D16, D36)

FULL audit: every Red round. The scaffold is `data/golden/audits/20261119T083408Z-2665.jsonl` (all
`unaudited`), and the sheet is `docs/audits/stage6_3_gateB_evasion_20261119T082130Z-da57.md`.

## Result (raw, before the audit)

| | Value |
|---|---|
| seed | 6322 |
| attacks sent / unsent | 9 / 1 |
| detection (raw) | 9/9 |
| FP rate | 0/17 (hard negatives 0/6) |
| attacks landed | 1 |
| rules stored | 2 |
| Red | 10 calls, $0.135778 (peak); max output 8192 tokens of 8192 |
| output budget | 1 Red reply hit the 8192 output budget (`max_tokens`, round 5) and became a failed turn (`red_unsent.jsonl`: brain_failure) |
| Blue | 19 calls, $0.001339 |
| total cost | $0.137117 |
| four facts | PASS |

**Red's stated strategies** (its rationales; see the sheet for every round): benign-looking prefixes (`Apple` before a UNION payload; `I love this juice shop!` before an `<svg>`), JSON `\u003c` escapes in a stored-XSS feedback, an encoded slash "to resemble an innocuous asset fetch", a short login bypass (landed).
