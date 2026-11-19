# Stage 6.1b Gate 1, train match 4 of 5

This folder is a copy of one complete **train** match, `20261119T005846Z-37ca`. It is match 4 of 5 of Stage
6.1b Gate 1 (`ARENA_GO=gate-6.1b-1 tools/stage6_1_check.py --gate 1 --real-calls`). The
other matches of the batch are `../train-6.1b-gate1-match1/`, `../train-6.1b-gate1-match2/`, `../train-6.1b-gate1-match3/`, `../train-6.1b-gate1-match5/`.

- **Run settings:** `--purpose train --red ai --blue claude --blue-rules-mode on
  --blue-caching on --red-caching on --seed 6104`, no rule library (D28).
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

The designer's audit is `data/audits/20261119T005846Z-37ca.jsonl`, committed. It covers only the source
rounds of candidate rules (D30): rounds [1, 2, 3, 4, 5, 6, 8, 9], all valid (designer,
2026-11-18). The basis was whether the label describes the attack type, whatever the
landing; every CWE-22 source contains a real `..` traversal. The read-only sheet is
`docs/audits/stage6_1_gate1_20261119T005133Z-0b84.md`.

## Result

| | Value |
|---|---|
| seed | 6104 |
| detection (AI Blue) | 10/10 |
| FP rate | 0/17 |
| rules stored | 8 |
| Red | 10 calls, $0.001446 |
| Blue | 25 calls, $0.001725 |
| total cost | $0.003171 |
| retention | 5 retained (r-002→lib-0013, r-003→lib-0014, r-005→lib-0015, r-007→lib-0016, r-008→lib-0017); 3 rejected (r-001 (duplicate_exact); r-004 (duplicate_exact); r-006 (duplicate_exact)) |

Retention evidence: `data/library/retention/20261119T005846Z-37ca/` (`variants.jsonl`, `retention.jsonl`,
`retention.json`). The library version this match produced is
`data/library/rule_library_v0004.json`.
