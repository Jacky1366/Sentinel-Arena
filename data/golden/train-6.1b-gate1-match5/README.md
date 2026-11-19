# Stage 6.1b Gate 1, train match 5 of 5

This folder is a copy of one complete **train** match, `20261119T010114Z-500b`. It is match 5 of 5 of Stage
6.1b Gate 1 (`ARENA_GO=gate-6.1b-1 tools/stage6_1_check.py --gate 1 --real-calls`). The
other matches of the batch are `../train-6.1b-gate1-match1/`, `../train-6.1b-gate1-match2/`, `../train-6.1b-gate1-match3/`, `../train-6.1b-gate1-match4/`.

- **Run settings:** `--purpose train --red ai --blue claude --blue-rules-mode on
  --blue-caching on --red-caching on --seed 6105`, no rule library (D28).
- **Code and stack:** a clean tree at commit `a8d7969` (`match.json` has
  `git.dirty: false`), on a freshly reset Target.
- **Status:** this is TRAIN data (S6-1). It fed the rule library through
  `tools/promote_rules.py`. It is not in `config/test_set.json`, and promotion refuses
  folders under `data/golden/`, so this copy can never be promoted again.

Every file except this README is listed in `match.json` → `artifacts` with its sha256.
`tests/test_gate_6_1b_gate1_evidence.py` checks the hashes, the configuration, the audit
and the retention evidence. Re-running would make real, paid calls, and model output is not
expected to repeat. The files here are never rewritten.

## Label audit (D16, D30)

The designer's audit is `data/audits/20261119T010114Z-500b.jsonl`, committed. It covers only the source
rounds of candidate rules (D30): rounds [1, 2, 3, 6, 10], all valid (designer,
2026-11-18). The basis was whether the label describes the attack type, whatever the
landing; every CWE-22 source contains a real `..` traversal. The read-only sheet is
`docs/audits/stage6_1_gate1_20261119T005133Z-0b84.md`.

## Result

| | Value |
|---|---|
| seed | 6105 |
| detection (AI Blue) | 9/9 |
| FP rate | 0/17 |
| rules stored | 5 |
| Red | 10 calls, $0.001097 |
| Blue | 22 calls, $0.001437 |
| total cost | $0.002534 |
| retention | 2 retained (r-002→lib-0018, r-005→lib-0019); 3 rejected (r-001 (duplicate_exact); r-003 (duplicate_exact); r-004 (offline_fixture_hit)) |

Retention evidence: `data/library/retention/20261119T010114Z-500b/` (`variants.jsonl`, `retention.jsonl`,
`retention.json`). The library version this match produced is
`data/library/rule_library_v0005.json`.
