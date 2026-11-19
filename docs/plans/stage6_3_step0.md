# Stage 6.3 — Step 0 plan: flagship gate (M7)

*Written 2026-11-18 under the autonomy policy. The designer pre-approved the decisions
below; they are recorded as D33–D37 in `docs/stage6_decisions.md`. Tooling and tests are
built on the fake provider. Every gate (A, B, C) has its own `ARENA_GO` token and runs only
after the designer's GO.*

## Questions

1. Does a stronger Red break the ceiling effect?
2. Does library v5 (learned from Luna traffic) transfer to a stronger Red's attacks?
3. Does a stronger Blue do better on the same stronger-Red traffic?

## Decisions (pre-approved)

- **D33 One Red treatment variable, "Red strength":** `gpt-6.1-sol` with reasoning effort
  `medium` (model and effort together). Everything else is the Gate 3 configuration: Red
  prompt v1, round cap 10, D15 guard, caching on, `max_output_tokens` 2048. No diversity
  directive in 6.3 (it would confound); it stays open.
- **D34 Blue arms.**
  - Haiku 5.5 live (rules on, caching on, library v5 READ-ONLY).
  - Sonnet 5.5 via replay (D17) on the same frozen logs, with library v5, thinking
    disabled, the same prompt and the same request settings.
  - Haiku 5.5 with the EMPTY library v0000 via replay, to isolate library transfer.
- **D35 The new matches are TEST data.**
  - Pre-registered by purpose: `run_match.py --purpose eval`, a new `purpose` value.
    `config/test_set.json` gains `test_purposes: ["eval"]`, so every eval match is test
    data from the moment it exists.
  - Gate B adds its match ids to `test_set.json` `match_ids`.
  - `tools/promote_rules.py` refuses an eval match (by purpose and by `test_purposes`), and
    the writer refuses test-set ids.
  - An eval match, like a train match, needs a clean tree.
- **D36 Full D16 audit** of every Red round in the eval matches (they are scored).
  `audit_scope` scopes only train matches, so eval matches get a full scaffold.
- **D37 Gate structure.**
  - **Gate A** (zero / near-zero):
    - the designer verifies the `gpt-6.1-sol` and `claude-sonnet-5-5` prices against the
      official pages (including any long-context tier), and the dated price table is
      updated;
    - `--estimate` (zero tokens) gives the expected and worst-case cost of Gates B and C;
    - an optional `--probe` (token `gate-6.3-A`) makes ONE Sol Red proposal (dry run,
      nothing sent) and ONE Sonnet Blue call on a non-test line, to confirm the usage
      mapping and reasoning-token use at effort medium.
  - **Gate B** (token `gate-6.3-B`): 3 live matches, Sol Red vs Haiku Blue + library v5,
    new seeds 6301–6303, purpose eval. Then the ids are registered, full audits are
    scaffolded and the sheet is written.
  - **Gate C** (token `gate-6.3-C`): Gate B's 3 frozen logs replayed with Sonnet + v5 and
    with Haiku + v0000.

## Implementation

- **`run_match.py`:** `--red-effort` (via `llm_client.with_effort`, recorded in
  `red_params.request.reasoning_effort` as before) and `--purpose eval` (clean tree).
- **Schemas and contract:**
  - `match_manifest` 0.8 purpose enum gains `eval`. Additive; old manifests stay valid.
  - `test_set.schema.json` gains `test_purposes`.
  - Contract §6.2 and §6.12 are updated.
- **`tools/stage6_3_check.py`:** `--gate A --estimate`, `--gate A --probe --real-calls`,
  `--gate B --real-calls`, `--gate C --matches DIR... --real-calls`. Every real path is
  token-gated, refuses a dirty tree, and refuses an unverified price.
  - **The estimate** uses the token profile of the committed Gate 1 TRAIN matches (same
    configuration, Luna Red / Haiku Blue; no test-set read). It reprices the profile at
    Sol / Sonnet prices, with Sol's output tokens at ×1 and ×3 (medium effort uses more
    reasoning tokens), and adds a worst case from the per-agent and per-match caps.
- **Tests:**
  - `--red-effort` and `--purpose eval` wiring;
  - promote refuses eval;
  - the test-set registry accepts `test_purposes`;
  - the GO-token table gains gates A / B / C;
  - offline Gates B and C on the fake provider (sources are fake eval matches);
  - the estimate math.

## Open items for the designer

- **Gate A:** the price verification itself is the designer's (the verified flag is
  designer-owned and tested).
- **Sol `max_output_tokens`:** 2048 includes reasoning tokens. At effort medium this may
  cut replies off (`max_tokens` → brain failure). Raising it would be a second variable;
  the probe measures it first.

## Addendum (2026-11-18): Gate A candidate tracks

- OpenAI's stronger models were refused by its cyber safeguards; Luna at high was allowed.
- Gemini and DeepSeek were estimated over half a day each: future work.
- Anthropic Red candidate (Opus 5.5, fallback Sonnet 5.5), ~4 h: turn caching for Red in the
  Anthropic adapter (5-minute breakpoint on the latest user turn), `stop_details` surfaced
  for refusals, probe candidates with provider switch and an 8192 probe output budget. No
  new files; tests in `tests/test_caching.py` and `tests/test_stage6_3_offline.py`.
- Same-family design note recorded in `docs/stage6_decisions.md`.

## New files

- `docs/plans/stage6_3_step0.md`
- `tools/stage6_3_check.py`
- `tests/test_stage6_3_offline.py`
