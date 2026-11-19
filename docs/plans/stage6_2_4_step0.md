# Stage 6.2 + 6.4 — Step 0 plan: autonomy table (M6) + dashboard MVP (M8)

*Written 2026-11-18 under the autonomy policy (CLAUDE.md). The designer pre-approved the
decisions in the 6.2/6.4 brief. This plan records how they are built; anything outside
them is escalated. Zero tokens: no provider call anywhere in this stage.*

## 6.2 Autonomy table (M6): pure code

- **`stats/autonomy.py`** (pure, no file access).
  - **Rows:** CWE-89, CWE-79, CWE-22 and total, aggregated over a list of frozen
    match / replay folders (one "arm").
  - **Columns:**
    - detection, raw and audited (D16 audited view via `tools/audit_match.py`; an
      incomplete audit gives `null`);
    - type-correct rate;
    - verdict FP rate;
    - rule coverage, split by `rule_origin` (library / match);
    - AI calls and cost.
  - **Definitions.** These reuse `stats/match_stats.py` and `stats/cost.py`, so the
    numbers match the terminal summary.
    - A CWE row's detection and type accuracy cover the attack rounds Red labelled with
      that CWE.
    - The verdict FP rate per CWE counts benign lines given that CWE as the verdict,
      over all benign lines. The total row gives the overall FP rate.
    - Rule coverage per CWE covers the verdicts on that CWE's attack lines. The total row
      covers all verdict lines, attack and benign.
    - AI calls and cost per CWE are Blue calls attributed to a line through
      `log_seq_first` (chunk size 1, D4). The total row adds benign lines and every agent
      (Red too, in live matches).
- **Rates.** Every rate is `k/n`. For `0/n` the exact Clopper–Pearson 95% upper bound,
  1 − 0.025^(1/n), is shown too.
- **Library FP table:** for each library rule, its hits on the holdout (TEST, read-only
  per the designer's GO; expected 0/40), on `fixture_v1` (17) and on
  `fixture_v2_offline` (6).
- **`tools/autonomy_table.py`** (CLI): `--arm NAME DIR...` (repeatable), `--library`,
  `--out` → Markdown + JSON.
- **Committed evidence:** `data/golden/stats/autonomy_6.1b.{md,json}` for the three 6.1b
  arms (rules off / rules on with the empty library / rules on with v5, from
  `data/golden/replays/gate-6.1b-2{,b}/`), plus a test that regenerates both files from
  the committed folders and compares them byte for byte.
- **Contract:** new §6.13 and `schemas/autonomy_table.schema.json`.

**Tripwires (Should): deferred.** Moving the existing checks (orphan, snapshot_missing,
instrument_failure, …) into `anomalies.jsonl` would change Judge output. The committed
golden evidence is re-scored byte for byte (gate evidence tests), so it would also need a
`JUDGE_VERSION` bump and golden re-scores, which is policy category 3. Instead, the table
JSON and the dashboard bundle carry the existing counts and anomalies read-only. Recorded
as a limitation.

## 6.4 Dashboard MVP (M8)

- **`tools/export_dashboard.py <folder> [--name N]`** (pure reader) writes one JSON bundle
  per frozen match or replay folder. Contract §6.14,
  `schemas/dashboard_bundle.schema.json`. It contains:
  - the meta (ids, engines, models, library, git, Judge version);
  - one step per proxy line in log order:
    - Red: label / round / rationale, or the benign id;
    - the request;
    - Judge facts: landed, newly_solved, detected, type_correct, FP;
    - Blue: verdict, source, `rule_origin`, fired rule ids, rationale;
    - running cost: calls, tokens and USD from `api_calls.jsonl`;
  - the rules, the anomalies and the Judge counts.

  Nothing new is judged; every value is copied from an artifact.
- **`dashboard/`** is a Vite + React + Tailwind app.
  - **Offline:** no CDN, no runtime network. Bundles load as `<script>` data files
    (`window.ARENA_BUNDLES`), so `dist/index.html` works from `file://`.
  - **Layout:** three columns, Red / Judge / Blue. Step controls (prev / next / play),
    a cost strip, and the verdict source and `rule_origin` shown. No world map (S6-5).
- **Default demo data:** Gate 1 train match 1 (`data/golden/train-6.1b-gate1-match1`) and
  the library arm of Gate 2 match 1
  (`data/golden/replays/gate-6.1b-2/ai-vs-ai-gate3-match1-library`).
- **Build:** `dashboard/dist/` is committed (static, offline). npm dependencies are pinned
  in `package-lock.json`; `node_modules/` is ignored.

## New files

- `docs/plans/stage6_2_4_step0.md`
- `stats/autonomy.py`, `tools/autonomy_table.py`
- `tests/test_autonomy.py`, `tests/test_autonomy_6_1b_evidence.py`
- `schemas/autonomy_table.schema.json`
- `data/golden/stats/autonomy_6.1b.md`, `data/golden/stats/autonomy_6.1b.json`
- `tools/export_dashboard.py`, `tests/test_export_dashboard.py`,
  `schemas/dashboard_bundle.schema.json`
- `dashboard/` (`package.json`, `package-lock.json`, `vite.config.js`,
  `tailwind.config.js`, `postcss.config.js`, `index.html`, `src/*`, `public/data/*`,
  `dist/*`, `README.md`)

## Tests

- **Autonomy:** synthetic folders, every column, the CP bound and the audit nulls.
- **Committed stats:** regenerated equals committed.
- **Export:** the bundle validates against its schema, every step matches the artifacts,
  the cost is cumulative and equals the folder's total, and no field is computed that
  isn't in an artifact.
- **Dashboard (static check):** no `http(s)://` URLs in `dist/`.
