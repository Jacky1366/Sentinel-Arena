# Incident archive

Failed / instrument-failure runs are archived here, never deleted (raw evidence is never
deleted; instrument failures are excluded from stats by D13, not removed). Nothing here is
in `config/test_set.json` and nothing here is scored.

## 20261119T172128Z-c145 — Stage 6.3 Gate B-freeplay, run 1 (deleted in error, then archived)

- **What it was:** the first Gate B-freeplay match (seed 6331, git `334308a`, Judge 0.7.0),
  started 2026-11-19T17:21:28Z (off-peak).
- **What happened:** all 10 Red (`deepseek-v4-pro`, prompt v3) calls returned HTTP 400
  **before generation** (latencies 945/364/515/420/444/471/342/346/374/336 ms), recorded as
  10 `instrument_failure (api_error)` / 0 attacks sent. The match otherwise completed on
  benign-only traffic: Blue 17 calls, FP 0/17.
- **Cost:** Blue $0.001160 (cache read 28736 / write 1796 tok); the 10 DeepSeek 400s billed
  $0 (pre-generation rejection). Match total $0.001160.
- **Cause:** a build bug — the free-play output schema had OPTIONAL `technique` / `headers`,
  but OpenAI/DeepSeek strict json_schema requires every property in `required`. DeepSeek
  rejected it with a 400 before generation (evidence that strict schema is validated, not
  silently ignored; contract §6.9b). Fixed in commit `27f49ca`.
- **Handling error:** the run folder `data/runs/20261119T172128Z-c145/` was **deleted in
  error** (category 3, which needed the designer's GO) while cleaning up. The folder is
  gitignored and was not recoverable; this transcript
  (`20261119T172128Z-c145.transcript.log`) is the surviving record of its artifacts and
  api_calls. The designer's correction (2026-11-19): failed runs are archived and marked,
  never deleted (now a CLAUDE.md rule).

## 20261119T173532Z-e624 — Stage 6.3 Gate B-freeplay, run 2 (strict-valid schema; preserved)

- The re-run after the strict-schema fix (`fdb6659`), seed 6331, started 2026-11-19T17:35:32Z
  (off-peak). All 10 `deepseek-v4-pro` prompt-v3 Red calls AGAIN returned HTTP 400 before
  generation (0.3–0.9 s) -> 10 `instrument_failure`, 0 attacks sent. Blue ran on benign-only
  traffic. Spend: Blue $0.001179; the 10 DeepSeek 400s billed $0.
- The output schema is strict-compliant by the OpenAI rule (static test
  `tests/test_ai_red.py::test_red_output_schemas_are_strict_compliant`), yet DeepSeek still
  rejects it. Possible causes (undistinguished without the 400 body, which is not stored):
  a provider-side block, or a narrower DeepSeek strict subset (nullable via `type: [T,"null"]`,
  or a nested nullable object) that v1/v2's flat all-required schema never exercised.
- Per the designer's instruction, the gate STOPPED and did not retry or reword. This folder is
  **preserved** (not deleted); its copy under `data/runs/` remains too. The match id was
  auto-registered in `config/test_set.json` by the gate before the FAIL — pending the
  designer's direction on removing it (archived failed runs do not belong in test_set.json).

## gate-6.3-C-open-run1 (20261119T184904Z-e35c) — open-Blue replays FAILED (build bug; preserved)

- The first gate-6.3-C-open run (D42). The prompt-FP check (2c) COMPLETED and is valid:
  original v2 FP 0/57, open v3-open FP 7/57 (holdout + fixture). The 6 open-Blue REPLAYS
  (2a free-play, 2b deepseek) FAILED: open Blue's `other` verdict (and a benign line labelled
  `other`) hit Judge schemas that still had only the taxonomy values — `benign_result` (fact
  4a), `round_record`'s detected-true branch, and the `unmatched_verdict` anomaly. The fake
  offline test never labelled a BENIGN line `other`, so these paths were uncovered.
- Build bug, not a provider/safety issue. Fixed by extending those three current schemas to
  allow `other`, requiring a library for open mode (0.4 rows), and adding a full-Judge offline
  test that labels an attack AND a benign line `other`. The gate was then re-run.
- Preserved here (not deleted). Nothing from this run is in test_set.json.
