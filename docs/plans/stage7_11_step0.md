# Stage 7 · issue #11 — Step 0 plan: housekeeping, the ledger-scan slip, D59

*Written 2026-11-24. Issue #11 (epic #20). Zero tokens; no test-set folder is read by
anything built or run here, apart from the `match_id` / `purpose` filter fields that D59 itself
requires. Labels: none (stage7), so the PR may be self-merged under the Stage 7 merge policy
if the designer approves this plan unchanged. If Q1 below changes what counts as test data,
the PR comes to the designer instead.*

## 1. Close issue #5 (Stage 6 epic)

- `gh issue close 5` with a comment: Stage 6 merged in PRs #6, #7, #8, #9; Stage 7 continues
  in epic #20.
- Done after the PR for this issue is merged, so #5 never closes on an unmerged change.

## 2. Record the 2026-11-24 slip in `docs/progress.md`

- New section `### Stage 7 — planning and housekeeping (Nov 24)` at the top of "Completed"
  (newest first, as for Stage 6.3), with:
  - **What happened:** during the Stage 7 timing analysis, a scan over `data/runs/` and
    `data/golden/` filtered by folder name. Golden eval folders are not named by match id, so
    it opened `api_calls.jsonl` in 9 test-set folders (Gate B-deepseek, B-evasion,
    B-freeplay). It printed only the number of DeepSeek calls per file. Nothing was used.
  - **Fix:** D59 and the helper below.
  - Plus whatever Q1 decides about incident `20261119T173532Z-e624` (see below).
- Also refresh the stale `## Next` section (it still lists Stage 6 as next): point it at
  epic #20 and the Stage 7 plan. Docs only.

## 3. Apply D59: a shared helper fits

There is no shared test-data check today. Three places each read `config/test_set.json`
their own way (`library/writer.py`, `tools/promote_rules.py`, `tools/stage6_1_check.py`), and
none is reusable from a scan: `library/` may not be imported outside promotion
(`tests/test_train_test_wall.py`), and `promote_rules.check_match` refuses everything that is
not a train match. So a helper fits.

**New file `stats/test_data.py`** (pure reads; imports nothing from `library/`, `blue/`,
`red/` or the Judge):

- `load_registry(path=config/test_set.json)` → match ids, `test_purposes`, sealed paths.
- `classify(folder, registry)` → one of:
  - `test`: `match.json` `match_id` in `match_ids`; or `purpose` in `test_purposes` (D35,
    "test by construction"); or a replay folder whose `replay.json` `source.match_id` is test
    (a replay of a test match carries its traffic).
  - `not_test`: a readable `match.json` or `replay.json` that is none of the above.
  - `unknown`: no manifest (probe folders, `live/`), unreadable or malformed manifest.
  It reads only `match_id`, `purpose` and `source.match_id`. It never looks at the folder
  name.
- `scannable(folders, registry, allow_unknown=False)` → (folders to scan, skipped counts by
  kind). `unknown` is skipped unless the caller opts in (probe folders, for example, are not
  test data but carry no manifest to prove it).
- `is_sealed(path, registry)` for the holdout / fixture files.

**Not retrofitted:** existing tools take explicit folder lists and do not scan, and
`promote_rules` / `library/writer` checks define promotion evidence (category 3). They stay
as they are.

**Rule, in CLAUDE.md working notes:** "Any scan over match or replay folders goes through
`stats/test_data.scannable()`; never filter by folder name (D59)." Plus a directory-map line.

**New test file `tests/test_test_data.py`** (synthetic folders in `tmp_path` and a synthetic
registry; it never opens a real test-set folder):
- the slip reproduced: a folder named like a golden eval folder whose `match.json` holds a
  registered id → `test`;
- a folder named like a match id that is not registered → `not_test`;
- purpose `eval` with an unregistered id → `test`;
- a replay of a test match → `test`; of a dev match → `not_test`;
- no manifest, broken JSON, missing `match_id` → `unknown`, skipped by default;
- the helper never reads any file other than the manifests (a planted `api_calls.jsonl` that
  raises on open is never touched);
- `load_registry` on the real `config/test_set.json` loads (reads the registry only).

## Q1 — for the designer: eval-purpose runs that are not in `match_ids`

D35 makes every `purpose: eval` match test data from the moment it exists, but CLAUDE.md's
test-set rule names only the `match_ids` and the holdout. They disagree on one folder:
incident `20261119T173532Z-e624` (Gate B-freeplay run 2, failed: all 10 Red calls HTTP 400;
`purpose: eval`; removed from `match_ids` after the failure).

In the 2026-11-24 timing analysis I read that incident's `match.json` and `api_calls.jsonl`
(Red error types and latencies, Blue latencies and tokens) and used the Blue figures in the
Part B estimate. Under CLAUDE.md's rule that is allowed; under D35 it is a test-data read.

Options:
- **A (recommended):** follow D35. The helper treats any `purpose: eval` folder as test, the
  progress entry records the e624 read as part of the same slip, and CLAUDE.md's rule gains
  "and any match with a purpose in `test_purposes`". This changes the rule's wording, so this
  PR comes to you.
- **B:** follow CLAUDE.md. Only `match_ids` count; failed eval runs dropped from the registry
  are not test data. The helper's purpose check is dropped, and the e624 read needs no record.

## Files

| File | Change |
|---|---|
| `docs/plans/stage7_11_step0.md` | new (this plan) |
| `stats/test_data.py` | new |
| `tests/test_test_data.py` | new |
| `docs/progress.md` | slip entry; `## Next` refreshed |
| `CLAUDE.md` | D59 rule in working notes; map lines for the two new files |

Not touched: the Judge, `docs/contract.md`, `data/library/`, `data/golden/`,
`config/test_set.json`, `agents/llm_client.py`.

## Done when

#5 closed, the slip recorded in `docs/progress.md`, `stats/test_data.py` + tests in place and
the CLAUDE.md rule added; suite passes.
