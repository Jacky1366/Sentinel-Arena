# Stage 6.1 — Step 0 plan: rule library, retention, variants, holdout, library replay

Written before any code. Approved by the designer on 2026-11-17, with the amendments below
already applied (marked **[amended]**). Branch `stage6.1a-rule-library` (from `main` at
`fd65f88`, after the Stage 5.7 merge). Stage 6 is tracked in GitHub issue #5. Its
**Decided** section (D19, S6-1, S6-2, S6-3) is binding. Scope: M1–M5 only (M6–M8 are later
sub-stages).

**Split (approved).**
- **6.1a**: M1–M4 + the M5 tooling, fake provider only. The holdout and
  `fixture_v2_offline` are sealed and committed here.
- **6.1b**: Gates 1–2. Each needs a separate GO from a clean committed tree.

Why split:
- Pre-registration requires the holdout to be sealed before any train match.
- A human audit sits between the train matches and promotion.
- Gate tools run only from a clean committed tree.

## 1. Library artifact (M1)

- **Location.** Immutable versioned files at `data/library/rule_library_vNNNN.json`.
  - Each promotion writes a new file and never overwrites an old one: raw evidence is
    never deleted.
  - `v0000` is an explicitly empty library. The M5 "without library" arm uses it.
  - Every load names one file and records its sha256. There is no implicit "latest".
- **Schema.** `schemas/rule_library.schema.json`, `schema_version "0.1"`:

```json
{"schema_version":"0.1","library_version":3,
 "parent":{"path":"data/library/rule_library_v0002.json","sha256":"…"},
 "created_at":"…","judge_version":"0.7.0","normalization_version":"2",
 "mutator_version":"1","retention_version":"1",
 "fixtures":[{"path":"benign/fixture_v1.jsonl","sha256":"…"},
             {"path":"benign/fixture_v2_offline.jsonl","sha256":"…"}],
 "entries":[{"library_id":"lib-0001","canonical_sha256":"…",
   "rule":{ …rule.schema.json unchanged, created_match REQUIRED here… },
   "promoted_from":{"match_id":"…","rule_id":"r-003"},
   "promoted_in_version":1,
   "retention_ref":{"path":"data/library/retention/<match_id>/retention.jsonl","line":3}}]}
```

- **Provenance per rule.**
  - The source `match_id` and in-match `rule_id`.
  - The rule's own `source_request_id` / `created_match` / `created_at_log_seq`, inside
    `rule`.
  - The library version that added it, and a pointer to its retention row.
- **No Red ground truth in the library.** `source_label`, the fact 3/4b values and the
  variant results live only in the retention log (§3). So Blue's body can read the library
  without breaking the information wall.
- **IDs.** `lib-NNNN` (`^lib-[0-9]{4,}$`) can never collide with the per-match `r-NNN`.
  Library order is the promotion order, which is also the tie-break order.
- **Cap.** 50 entries. Beyond that the rejection reason is `library_cap_reached`.
- **Dedup: exact duplicates are rejected (binding).**
  - The canonical form is the `cwe` plus the conditions sorted by
    `(field, op, pattern, case_insensitive)`.
  - `contains` / `equals` patterns are lowercased when `case_insensitive` is set, since
    the engine lowercases them anyway.
  - A `regex` pattern is never rewritten: lowercasing would turn `\S` into `\s`.
  - `canonical_sha256` is the sha256 of the canonical JSON. A collision is rejected as
    `duplicate_exact` with `duplicate_of: lib-NNNN`.
- **Dedup: semantic duplicates are advisory only (D25).** If two rules fire on exactly the
  same set over the retention corpus, the flag `behavioural_duplicate_of` is set. It is
  recorded and never rejects. The retention corpus is the train proxy lines + both
  fixtures + the variants.
- **Contract.**
  - New §5.3 "Rule library".
  - New §8 rows: Rule library, Library snapshot, Retention log, Variants, Holdout benign
    set, Offline fixture v2, Test-set registry.
  - D20 supersedes the unwritten `rules.json` cross-match role. `rules_file.schema.json`
    0.1 stays as the input format of `tools/score_rules.py`.

## 2. Load semantics (D4, D9)

- **Preloaded, live from line 1.** `rules/hotload.py` gains `HotLoad(preloaded=…)`.
  - Library rules fire for every `log_seq ≥ 1`.
  - In-match rules keep D4: they apply only from the line after the one that created them.
  - Tie-break: library rules first (library order), then in-match rules (creation order).
- **In-match invention is unchanged.**
  - `max_rules` (10) counts in-match rules only.
  - A line a library rule answers gets no AI call, so it gets no proposal either.
- **The prompt does not see library rules (D21, confirmed).** Prompt v2 stays
  byte-identical: same version, same sha256, same cached prefix. This is consistent with
  D14 / §4.1.
- **Provenance field.** Verdict `0.4` adds `rule_origin: "library" | "match" | null`.
  - It describes the tie-break winner and is non-null iff `source == "rule"`.
  - `fired_rule_ids` may mix `lib-NNNN` and `r-NNN`. The winner's id pattern agrees with
    `rule_origin` (checked by the schema).
  - `source` is not split: the mechanism (rule engine, no call) is the same for both
    origins.
  - M6 rule coverage = `source == "rule"`, split by `rule_origin`.
- **Snapshot.** The orchestrator or replay tool copies the named library into the run
  folder as `library.json`, verifies its hash, and lists it in `artifacts`.
  - Blue's body reads only the snapshot.
  - The Judge's rule-verdict cross-check re-runs hot-load with the same snapshot, and
    raises on a sha mismatch with `blue_params.library.sha256`.
- **No `--library`** means exact Stage 5.5/5.7 behaviour, with verdicts still `0.3`.

## 3. Retention pipeline (M2)

- **Where.** `tools/promote_rules.py --match <train match> --library <vNNNN> [--seed S]`.
  - A post-match step, run by hand after the designer's D16 audit of the candidate source
    rounds (D30).
  - Zero tokens. The decision logic is pure (`judge/retention.py`).
- **Inputs.**
  - From the match: `rules.jsonl`, `rule_results.jsonl` (facts 3 + 4b), `red_attacks.jsonl`,
    `proxy.jsonl`, `match.json`, the D16 audit.
  - The input library.
  - `benign/fixture_v1.jsonl` **and `benign/fixture_v2_offline.jsonl`** **[amended]**.
  - **Never the holdout.**
- **Criteria**, per rule, in `rules.jsonl` order. Every failing criterion is listed:
  - (a) `replay_fires == true` and `cwe_matches_source == true` (fact 3).
  - (b) Zero hits on `fixture_v1` (fact 4b, from `rule_results.jsonl`) **and** zero hits
    on `fixture_v2_offline` (computed by retention with the same engine) **[amended]**.
  - (c) The source round is audited `valid` (D30).
  - (d) Blocks ≥ 1 counting variant (§4).
  - (e) Not an exact duplicate.
  - (f) The library is under its cap.
- **Outputs**, under `data/library/retention/<match_id>/`, never in the match folder:
  - `variants.jsonl`: every variant generated, counting or not, and why.
  - `retention.jsonl`: one row per candidate, with `decision`, `reasons[{code, detail}]`,
    the variant ids generated / counting / blocked, and the seed. Reason codes:
    `fact3_false`, `cwe_mismatch`, `fixture_hit`, `offline_fixture_hit`,
    `source_label_invalid`, `source_unaudited`, `no_counting_variant`,
    `no_variant_blocked`, `duplicate_exact`, `library_cap_reached`.
  - `retention.json`: a manifest with input hashes and versions.
  - The new library file.

  `no_counting_variant` (a gap in the mutator) is kept separate from `no_variant_blocked`
  (the rule is too narrow).
- **Order.** Promotion is sequential in ascending `match_id`.

## 4. Variants (M3, S6-2)

- **Generator.** `judge/variants.py`, pure and deterministic, per source request.
  - Seed = `sha256(MUTATOR_VERSION | base_seed | source_match_id | source_request_id)`.
  - Each applicable transformation is applied once. Seeded parameters cover choices like
    the case pattern or the tautology constant.
  - At most 12 variants per source. Anchors come from fixed token lists, so no AI is
    involved. No anchor means no variant.
  - Variants are never sent: they are syntactic equivalents, not attacks verified to land.
- **Per-variant classification.** A variant is **normalizer-neutralized** iff, for every
  field, `forms(variant) ⊇ forms(source)`. Every rule firing on the source then fires on
  the variant by construction, so a neutralized variant never counts. A variant is also
  excluded when:
  - it is identical to the source;
  - it climbs **above root** (nginx would log it as stray);
  - its transformation is marked non-equivalent on this Target.
- **Above root [amended].** The predicate moves to the neutral module `rules/paths.py`.
  - `red/red_guard.py` and `judge/variants.py` both import it. `judge/` never imports
    `red/`.
  - `tools/verify_red_guard.py` points at the single definition.
  - The behaviour is unchanged: the Stage 5.6 guard tests and the zero-token nginx probe
    still apply.

| ID | CWE | Transformation | Does normalization v2 undo it? | Counts? |
|---|---|---|---|---|
| E1 | all | Percent-encode payload characters (one level) | **Yes, neutralized** | no |
| E2 | all | Double-encode, depth ≤ 3 in total | **Yes, neutralized** | no |
| E3 | all | Flip hex case of existing escapes | Survives for raw-literal case-sensitive rules | when not a superset |
| E4 | all | Decode one level where legal raw | **Survives** | when not a superset |
| E5 | 89/79 | Space ↔ `+` ↔ `%20` in query/body | space→`+` neutralized; `+`→`%20` survives for raw `+` rules | per instance |
| S1 | 89 | Keyword case (seeded) | **Survives** | yes |
| S2 | 89 | Whitespace class (`%09`, `%0a`, multiple spaces) | **Survives** | yes |
| S3 | 89 | Inline comment as whitespace | **Survives** | yes |
| S4 | 89 | Tautology swap (`N=N`, `'x'='x'`) | **Survives** | yes |
| S5 | 89 | Terminator swap (`--` ↔ `-- -` ↔ `/*`) | **Survives** | yes |
| X1 | 79 | Event handler swap, same tag | **Survives** | yes |
| X2 | 79 | Tag/attribute case | **Survives** | yes |
| X3 | 79 | Separator: space → `/` or tab | **Survives** | yes |
| X4 | 79 | Attribute quoting | **Survives** | yes |
| X5 | 79 | Sink swap (`confirm` / `prompt`) | **Survives** | yes |
| X6 | 79 | HTML entities in attribute values | **Survives** | yes |
| X7 | 79 | `javascript:` case + embedded tab | **Survives** | yes |
| T1 | 22 | Plain `../` → `%2e%2e%2f` | **Neutralized** | no |
| T1r | 22 | Encoded → plain `../` | Survives for raw-encoded rules | yes |
| T2 | 22 | Double encoding | **Neutralized** | no |
| T3 | 22 | Redundant segments, net depth preserved | **Survives** | yes |
| T5 | 22 | Null-byte suffix extension swap | **Survives** | yes |
| T6 | 22 | Target file swap in the same directory | **Survives** | yes |
| T4 | 22 | Backslash separator `..%5c` | Survives, not equivalent on Node/Linux | **no** |
| T7 | 22 | Overlong UTF-8 `%c0%ae` | Not equivalent | **no** |

The per-variant check is the authority. The table is an expectation.

**"Blocks a variant".** The rule, validated and evaluated **alone** (no hot-load), fires on
at least one variant with `counting == true`: `engine.fires(rule, engine.forms(variant))`
under normalization v2.

## 5. Train/test enforcement (S6-1, S6-3)

1. **One writer.** `library/writer.py` is imported only by `tools/promote_rules.py`. The
   in-match and replay code imports only the read-only `rules/library.py`.
2. **Train-only acceptance.** Anything else is refused with exit 2 and nothing written. The
   source must be:
   - a `match.json` with `purpose: "train"` (old manifests and replay folders are refused);
   - clean;
   - audited for its candidate source rounds;
   - not in `config/test_set.json`;
   - not under `data/golden/`.
3. **Explicit purpose.** `run_match.py --purpose train` is explicit; the default is `dev`.
   `replay_blue.py` has no `--purpose`.
4. **Pre-registration in code.** The holdout (and `fixture_v2_offline`), with its sealed
   sha256, must exist at the train match's recorded `git.commit`.

**Leak tests.**
- Provenance is disjoint from the test set.
- The AST import closure contains no writer.
- A replay with rule invention never writes back.
- Every refusal above.
- The holdout is never opened during promotion.

## 6. New benign data (M4)

- **Holdout `benign/holdout_v1.jsonl` (test).** 40 entries.
  - 12 normal and 28 hard negatives: CWE-89 look-alikes 9, CWE-79 look-alikes 9,
    CWE-22 look-alikes 10.
  - Ids `xn01…` / `xh01…`.
  - Drafted from the pre-registered categories below, never scored against any rule
    before sealing.
- **Offline train fixture `benign/fixture_v2_offline.jsonl` [amended, D31].** About 6
  CWE-22 look-alikes.
  - Same categories as the holdout, disjoint instances. Ids `yh01…`.
  - Used **only** by retention criterion (b). Never sent in a match, never part of Judge
    fact 4b output.
- **Categories.**
  - CWE-89: apostrophes in names and text, SQL words in natural text, `--` / `=` inside
    passwords.
  - CWE-79: `<3`, `a<b`, "Tom & Jerry", "onload"/"script" as words, angle brackets in
    review text.
  - CWE-22: double dots in file names, ellipses, version ranges, deep asset paths, `/ftp/`
    names with several dots.
- **Capture [amended].** `tools/build_holdout.py` sends each entry once through the shared
  client to a freshly reset Target, **outside any match**. It copies
  `method/path/query/body` verbatim from the logged line, then **resets the Target after
  capture**. Zero tokens. One tool captures both files.
- **Seal.** Both files plus `.meta.json` files (sha256, sealed date, category counts,
  capture provenance) go **in the same commit**, before the first train match. §6.7
  limitation 1 is updated on seal.

## 7. Train matches and M5

- **Train.** K = 5 matches.
  - `--red ai --blue claude --blue-rules-mode on --caching on --purpose train`.
  - Dev models (D12), seeds 6101–6105, independent, no library.
  - Cost ≈ $0.015. The cap worst case is $2.50.
- **Then:** the D16 audit of the candidate source rounds (D30), then promotion
  v0001 → v0005.
- **M5.** The 3 Gate 3 sources × {`v0000` empty, final library}, 6 Blue replays.
  - Every replay: rules on, caching on.
  - Primary: AI calls and cost.
  - Secondary: detection and FP (raw + audited), coverage by `rule_origin`, holdout hits
    per library rule.
  - A zero-token prediction of library-answered lines is pre-registered in
    `progress.md` before GO.

## 8. Versions

| Item | Change | Frozen copy |
|---|---|---|
| `verdict` | 0.3 → **0.4** (`rule_origin`), only with a library | `verdict_v0_3` |
| `match.json` | 0.7 → **0.8** (`purpose`, `blue_params.library`, `library.json` artifact) | `match_manifest_v0_7` |
| `replay.json` | 0.2 → **0.3** (`blue_params.library`) | `replay_manifest_v0_2` |
| New 0.1 | `rule_library`, `retention_row`, `retention_manifest`, `variant`, `benign_holdout` (holdout + fixture v2), `test_set` | — |
| `JUDGE_VERSION` | 0.6.0 → **0.7.0** | — |
| Unchanged | rounds, benign results, api_calls, rule_result, rule, rules_file, match_rule, rule_rejection, the prompts, `NORMALIZATION_VERSION "2"` | — |

New constants: `MUTATOR_VERSION "1"`, `RETENTION_VERSION "1"`.

## 9. Decisions (`docs/stage6_decisions.md`)

D19, S6-1, S6-2 and S6-3 as decided. Then:
- **D20.** The library supersedes the `rules.json` cross-match role; `created_match` is
  required in library entries.
- **D21.** Library rules are invisible to the AI, preloaded, and first in the tie-break.
- **D22.** `rule_origin` field.
- **D23.** Retention criteria.
- **D24.** Variant counting.
- **D25.** Exact dedup, behavioural advisory.
- **D26.** One writer, train-only acceptance.
- **D27.** The holdout: offline, captured outside matches, sealed before training.
- **D28.** Train protocol.
- **D29.** M5 design.
- **D30 [amended].** Audit-before-promotion, scoped to the **source rounds of candidate
  rules only**. For train matches, `tools/audit_match.py` scaffolds and sheets only those
  rounds.
- **D31 [new].** `fixture_v2_offline`.
- **D32 [new].** The above-root predicate lives in neutral `rules/paths.py`.

## 10. New files (announced)

- **Code:** `rules/library.py`, `rules/paths.py`, `judge/variants.py`,
  `judge/retention.py`, `library/__init__.py`, `library/writer.py`,
  `tools/promote_rules.py`, `tools/build_holdout.py`, `tools/stage6_1_check.py`.
- **Data:** `benign/holdout_v1.jsonl` (+ `.meta.json`),
  `benign/fixture_v2_offline.jsonl` (+ `.meta.json`), `config/test_set.json`,
  `data/library/rule_library_v0000.json`.
- **Schemas:**
  - New: `rule_library`, `retention_row`, `retention_manifest`, `variant`,
    `benign_holdout`, `test_set`.
  - Frozen copies: `verdict_v0_3`, `match_manifest_v0_7`, `replay_manifest_v0_2`.
- **Docs:** `docs/stage6_decisions.md`, this plan.
- **Tests:** `test_rule_library.py`, `test_rule_paths.py`, `test_variants.py`,
  `test_retention.py`, `test_promote_rules.py`, `test_train_test_wall.py`,
  `test_hotload_library.py`, `test_blue_library.py`, `test_rule_verdicts_library.py`,
  `test_holdout_set.py`, `test_stage6_1_gates_offline.py`.
- **Extended tests:** `test_replay_blue.py`, `test_run_match_rules.py`, `test_schemas.py`,
  `test_audit.py`, `test_red_guard.py`.

## 11. Gates

| Gate | What | Cost |
|---|---|---|
| 0 (zero token, touches the Target, GO) | `tools/build_holdout.py`: capture, reset, seal, commit | $0 |
| — | Zero-token prediction on the Gate 3 logs | $0 |
| **1 (paid, GO)** | 5 train matches, then audit + promotion ($0) | ≈ $0.015 (cap $2.50) |
| **2 (paid, GO)** | 6 M5 replays | ≈ $0.010 |

## 12. Conflicts (resolutions approved)

- D20 supersedes `rules.json`'s cross-match role (§5, §8).
- §5.2's "every match and every replay starts with zero rules" becomes "…unless a library
  is loaded".
- `created_match` is required in library entries.
- §6.7 limitation 1 is updated on seal.
- Unrelated external schedule lines in `docs/progress.md` are removed in the 6.1a wrap-up.
