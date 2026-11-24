# Stage 7 · issue #16 — Step 0 plan: analyst summary builder + grounding check

*Written 2026-11-24. Issue #16 (epic #20), **important lane** (`needs-GO`, `test-set`): this
plan waits for the designer's review, and so will the PR. Zero tokens: no provider call
anywhere in #16 (the analyst call itself is #17). Decisions D53 and D55.*

## What #16 delivers

1. **D60 — confidence rules, pre-registered** in `docs/stage7_decisions.md` and committed
   **before** any summary code (the first commit of the branch).
2. **`summary.json` builder:** every figure the report may cite, computed by code from frozen
   evidence, each with its sources and a confidence from D60. Plus a few descriptive fields.
   No raw payloads.
3. **Grounding check:** a draft is accepted only if:
   - every `{{placeholder}}` resolves to a summary figure;
   - no bare number appears outside an allowlist;
   - it is schema-valid.
   A rejection says why, per draft location.
4. **Tests on fixtures only** (synthetic folders and non-test golden folders). Building the
   REAL summary reads test-set data and needs a separate GO (see "The real build").

## 1. D60 — confidence rules (proposal, Q1)

Each figure gets a **basis**:

| basis | what | examples |
|---|---|---|
| `audited` | a rate over Red rounds whose labels or attempts the designer audited (D16 / D41 binary) | Gate B detection 28/28; free-play detection 12/19 and 14/19 |
| `ground_truth` | a rate over designer-approved benign data (benign set, sealed holdout, fixture) | FP 0/17 per match; FP check 0/57 and 6/57 |
| `raw` | a rate over unaudited AI-Red labels | Gate B-deepseek 26/26, B-evasion 29/29 (D43) |
| `measured` | an exact count, cost or duration from the ledgers (not a sampled rate) | calls 70 → 52; cost per arm |

Confidence of a **rate** figure:
- `audited` or `ground_truth` with n ≥ 20 → **High**;
- `audited` or `ground_truth` with n < 20 → **Moderate**;
- `raw` → **Low**.
- **Cap:** a figure from an arm known to vary run to run (open Blue, D42 2c instability) is
  capped at **Moderate**.

A `measured` figure has no confidence of its own (`null`); it is exact for the runs it covers.

Confidence of a **finding** is the lowest confidence among the rate figures it cites. A finding
that cites only `measured` figures gets **High**. The analyst never sets confidence: the draft
schema has no such field, and code fills it in.

Every rate carries k, n and the Clopper–Pearson 95% interval (`stats/autonomy.py`, reused).

## 2. `summary.json`

**New code (package `analyst/`):**
- `analyst/summary.py` (pure) builds the summary from a **source manifest**: a small JSON list
  of named evidence groups (folder paths plus their role). Figures come from existing pure
  code, so they match the committed tables and the terminal summary:
  - `stats/match_stats.py` for detection, FP and type accuracy;
  - `stats/match_stats.apply_audit` for the audited views;
  - `stats/free_play.py` for free-play detection over audited attempts and landing categories;
  - `stats/autonomy.py` for CP intervals, rule coverage and calls;
  - `stats/cost.py` for cost (D39).
- `analyst/confidence.py` (pure): D60 as code, one function per rule, with tests per row of
  the table above.

**New schema `schemas/analyst_summary.schema.json`** (contract §6.15, new section):
- `schema_version`, `built_at`, `git` (commit, dirty), `judge_version`, `confidence_rules`
  ("D60").
- `sources[]`: `id`, `path`, `match_id` / `replay_id`, `purpose`, `sha256` of each artifact
  read, `test_data` (from `stats/test_data.classify`, D59).
- `figures{}`, keyed by stable ids like `freeplay.original.detection` or `fp_check.open.fp`.
  Each has `kind` (rate | count | usd | duration), `value`, `k`, `n`, `ci95`, `basis`,
  `confidence`, `source_ids`, and `definition` (one plain sentence, written by code).
- `descriptive{}`:
  - model ids and dates per arm;
  - free-play `technique` strings (D41; truncated to 120 characters, control characters
    removed);
  - challenge names and categories of landed rounds.
  Never a payload, path, body or rationale (D53).

**Proposed figure catalog** (the report cites only these; the designer may cut or add):
- **Gate B:** audited and raw detection, FP, type accuracy.
- **Gate B-deepseek / B-evasion:** raw detection and FP.
- **Free-play:** original and open Blue detection over audited attempts, landed rounds by
  category, and misses by Blue.
- **FP check (2c):** original 0/57 and open 6/57, each with its CI.
- **Cost:** per arm and per match. The 6.1b M5 library effect (calls, cost, detection / FP
  unchanged). The cost paradox (rules on vs off), if #19's arms exist; otherwise from the
  committed 6.1b tables.
- **Gate C:** Sonnet + v5 and Haiku + v0000 versus Haiku + v5 (detection, FP, cost).
- **Counts:** matches, rounds, attack attempts and benign lines per arm (for the scope
  section).

**CLI:** `tools/build_summary.py --manifest <sources.json> --out <file>`.
- It classifies every source with `stats/test_data.classify` (D59).
- If any source is test data, it refuses unless `ARENA_GO` holds a well-formed token
  (`runner/go_token.valid`). The GO for a test-set read is then visible in the command, the
  same as for a paid call.
- `--check <summary.json>` re-validates a file against the schema.

## 3. Grounding check

**New code:** `analyst/grounding.py` (pure). **New schemas:**
- `schemas/analyst_draft.schema.json` (the analyst's JSON);
- `schemas/grounding_result.schema.json` (contract §6.16, §6.17).

**Draft shape** (the AI writes prose only):
- `sections{}`, keyed by the D57 sections the AI writes: executive summary, methodology
  notes, results narrative, risk register, deployment options, decision criteria and
  limitations;
- `findings[]`: `id` "F-NN", `title`, `text`, `figure_refs[]`, `evidence_refs[]`;
- `options[]` for A / B / C (D54): `id`, `summary`, `strengths`, `weaknesses`;
- `criteria[]`: "if you value X, option Y fits".

The schema has no recommendation field and no confidence field. Everything that is code- or
human-written (document control, scope tables, the evidence manifest, the decision record) is
not in the draft.

**Checks**, each failure a machine-readable reason with a JSON path:
1. **schema:** schema-valid (types, required fields, `F-NN` ids unique, no extra keys).
2. **placeholder:** every `{{key}}` or `{{key.field}}` (field ∈ value, k, n, ci_low, ci_high,
   pct) resolves in `summary.figures`. Malformed braces are rejected too.
3. **bare_number:** after placeholders are removed, no digit may remain, except allowlisted
   tokens:
   - `CWE-\d+`, `F-\d{2}`, `D\d{1,3}`, section references `§\d+(\.\d+)*`;
   - model ids from `descriptive` (they contain digits, e.g. `claude-haiku-5-5`);
   - `v\d+` for library and prompt versions.
4. **number_word:** spelled-out quantities are rejected the same way (Q2).
5. **refs:**
   - every `figure_refs` entry is a figure key;
   - every placeholder used in a finding is listed in its `figure_refs`;
   - every `evidence_refs` entry is a source id.
6. **recommendation:** phrases such as "we recommend", "should choose" or "the best option" are
   rejected (D54). This is a small fixed list, and the human still reviews the draft.

`check(draft, summary) -> {ok, errors[], stats}` returns all errors, not just the first, so a
retry in #17 can be told exactly what to fix.

## 4. Tests (new files)

- `tests/test_analyst_confidence.py`: every row of the D60 table, the n = 20 boundary, the
  open-Blue cap, the finding minimum, measured-only findings.
- `tests/test_analyst_summary.py`:
  - figures from synthetic match / replay folders equal the existing stats functions on the
    same folders;
  - every figure has sources and a confidence;
  - no payload / path / body / rationale anywhere in the output;
  - technique text truncated and cleaned;
  - the CLI refuses test-data sources without `ARENA_GO`, using synthetic folders classified
    as test by a synthetic registry;
  - schema-valid output.
- `tests/test_analyst_grounding.py`: planted bad drafts are rejected with the right reason
  (unknown placeholder, malformed braces, bare number, number word, wrong shape, unknown
  figure / evidence ref, a placeholder missing from `figure_refs`, recommendation phrasing).
  A valid draft is accepted. Allowlisted tokens (`CWE-89`, `F-03`, `D42`, model ids) pass.

No test opens a test-set folder (rule 3; offline tests use synthetic or non-test data).

## The real build (after the PR, separate GO)

- `ARENA_GO=manual-analyst-summary tools/build_summary.py --manifest config/analyst_sources.json
  --out <path>` reads the 6.1b / 6.3 golden folders (test data) and their audits.
- Output location: Q3.
- Before the report uses it, a spot check: the summary's figures must equal the numbers
  already committed in `docs/progress.md` and the gate READMEs. A mismatch is a bug in the
  builder, not a new result.

## Files

| File | Change |
|---|---|
| `docs/plans/stage7_16_step0.md` | new (this plan) |
| `docs/stage7_decisions.md` | D60 confidence rules (first commit, after approval) |
| `analyst/__init__.py`, `analyst/confidence.py`, `analyst/summary.py`, `analyst/grounding.py` | new |
| `tools/build_summary.py` | new |
| `config/analyst_sources.json` | new: the source manifest (paths and roles only; nothing read) |
| `schemas/analyst_summary.schema.json`, `schemas/analyst_draft.schema.json`, `schemas/grounding_result.schema.json` | new |
| `docs/contract.md` | §6.15–6.17 (summary, draft, grounding result) |
| `tests/test_analyst_confidence.py`, `tests/test_analyst_summary.py`, `tests/test_analyst_grounding.py` | new |
| `CLAUDE.md` | directory map, including the lines for #12's `liveserver/` and its tests (held back from the fast-lane PR #22) |

Not touched: the Judge, `data/library/`, `data/golden/`, `config/test_set.json`,
`agents/llm_client.py`.

## Questions for the designer

- **Q1 — D60 as proposed?** In particular:
  - Do benign-set / holdout rates count as `ground_truth`, at the same level as `audited`?
  - Is the open-Blue cap at Moderate right?
  - Should `measured`-only findings be High?
- **Q2 — number words.** Reject digits only, or also spelled-out quantities? The proposal is to
  also reject `two`…`twenty`, `hundred`, `thousand`, `dozen`, `half`, `twice`, `double`,
  `triple`, `percent`. `one` stays allowed ("one of the …"). The cost of a stricter check is
  more rejected drafts, and those retries stay within the $1 analyst cap.
- **Q3 — where the real `summary.json` lives.** It is derived from test data but holds no
  payloads.
  - Option (a): `data/runs/analyst/` (git-ignored) until #17.
  - Option (b): commit it under `docs/` as report input.
  - The scope freeze keeps it out of `data/golden/` either way. I propose (a) now, with the
    decision in #17.

## Done when

The grounding check rejects the planted bad drafts and accepts a valid one, D60 is committed
before the summary code, and the suite passes.
