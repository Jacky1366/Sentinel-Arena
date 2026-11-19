# Stage 6.3 Gate B-evasion, eval match 3 of 3

This folder is a copy of one complete **eval** match, `20261119T084926Z-a819`. It is match 3 of 3 of Stage 6.3
Gate B-evasion (D40), the final experiment, run with `ARENA_GO=gate-6.3-B-evasion
tools/stage6_3_check.py --gate B-evasion --real-calls`. The other matches of the batch are
`../eval-6.3-gateB-evasion-match1/`, `../eval-6.3-gateB-evasion-match2/`.

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
- **Run settings:** `--purpose eval`, seed 6323.
- **Code and stack:** a clean tree at commit `8e64792` (`git.dirty: false`), on a freshly
  reset Target.
- **Status:** **TEST data** (D35), registered in `config/test_set.json`. It is never
  promoted, and never used to select or tune rules.
- DeepSeek did not refuse the directive.

Every file except this README is listed in `match.json` → `artifacts` with its sha256.
`tests/test_gate_6_3_gateB_evasion_evidence.py` checks them. Re-running would make real,
paid calls. The files here are never rewritten.

## Label audit (D16, D36)

FULL audit: every Red round. The scaffold is `data/golden/audits/20261119T084926Z-a819.jsonl` (all
`unaudited`), and the sheet is `docs/audits/stage6_3_gateB_evasion_20261119T082130Z-da57.md`.

## Result (raw, before the audit)

| | Value |
|---|---|
| seed | 6323 |
| attacks sent / unsent | 10 / 0 |
| detection (raw) | 10/10 |
| FP rate | 0/17 (hard negatives 0/6) |
| attacks landed | 1 |
| rules stored | 4 |
| Red | 10 calls, $0.107450 (peak); max output 4543 tokens of 8192 |
| output budget | none |
| Blue | 21 calls, $0.001533 |
| total cost | $0.108983 |
| four facts | PASS |

**Red's stated strategies** (its rationales; see the sheet for every round): JSON `\u003c` / `\u0027` escapes so the raw body shows no literal angle brackets or quote (stored XSS in feedback and reviews; a login bypass that landed), percent-encoded dot segments, UNION column enumeration.
