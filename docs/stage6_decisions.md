# Stage 6 — Decisions

*Recorded 2026-11-17 (Stage 6.1, Step 0 plan `docs/plans/stage6_1_step0.md`, approved by the
designer with amendments). Stage 6 is tracked in GitHub issue #5. D19 and S6-1 to S6-3 were
decided in the issue; D20–D32 were proposed in the 6.1 Step 0 plan and approved on
2026-11-17, with the designer's answers applied. Changing one is a designer decision,
recorded here with a date. Where a decision touches an artifact format,
`docs/contract.md` remains the source of truth. Stage 5 decisions (D1–D18) stay in
`docs/stage5_decisions.md`.*

## Sub-stage map

| Sub-stage | Scope |
|---|---|
| 6.1a | M1 rule library, M2 retention, M3 variant mutator, M4 offline benign data (sealed), the M5 tooling: body only, fake provider |
| 6.1b | Gate 1 (train matches) and Gate 2 (M5 library replay), each after a separate GO |
| later | M6 autonomy table, M7 flagship gate, M8 dashboard (own Step 0 plans) |

## Decided in the issue

**D19 — Red stays stateless across matches** (D7 unchanged). Red's only feedback is its own
HTTP result (D6), so memory could learn what lands but not what evades Blue; and a learning
Red would make the attack distribution non-stationary, confounding the Match 1 vs Match N
comparison. The ceiling effect is addressed by a stronger Red model (M7) instead. "Arms race
mode" (both sides learning) is a stretch item, reported separately if ever run.

**S6-1 — Train / test split.** Selection (train) = matches run during Stage 6 + the
17-request benign fixture (and, D31, `fixture_v2_offline`). Scoring (test) = the 6 audited
AI-Red matches in `data/golden/` (3 Stage 5.6 Gate 2 + 3 Stage 5.7 Gate 3) + the new
never-sent benign set (M4). Rules are never selected using test data.

**S6-2 — Variants are code-generated only**: deterministic and seeded, never AI-generated.
The transformation list is in the 6.1 Step 0 plan §4 and `judge/variants.py`.

**S6-3 — Library write rule.** The library is written only after a **train** match ends,
and only with rules that pass retention (M2). Every run on test data (golden matches, new
benign set) loads the library **read-only** and never writes back. In-match semantics are
unchanged (D4: a new rule applies from the next line).

## Approved 2026-11-17 (6.1 Step 0)

**D20 — The rule library.** Immutable versioned files `data/library/rule_library_vNNNN.json`
(version 0 = empty, committed); every promotion writes a new file and never overwrites one.
It supersedes the cross-match role first planned for `rules.json` (which stays the input of
`tools/score_rules.py`). Entries carry provenance (source match and rule id, the version
that added them, a pointer to the retention row) and NO Red ground truth. `created_match`
is required in a library entry (optional in a rule).

**D21 — Library rules are invisible to the AI** (designer: confirmed). The prompt (v2) and
every message are byte-identical with and without a library (D14 unchanged). Library rules
are preloaded into the hot-load set: live from line 1, first in the tie-break, before every
in-match rule. In-match invention is unchanged; `max_rules` counts in-match rules only. A
library needs claude Blue in rules mode on.

**D22 — Verdict provenance by a field.** Verdicts 0.4 carry `rule_origin` (`library` |
`match` | null; the tie-break winner's origin), and `fired_rule_ids` may mix `lib-NNNN` and
`r-NNN`. `source` is not split: the mechanism (rule engine, no call) is the same, and
splitting it would make every existing `source == "rule"` reader miss library verdicts.

**D23 — Retention criteria** (pure code, `judge/retention.py`): (a) fact 3 fires and the CWE
matches the source; (b) zero hits on `fixture_v1` and on `fixture_v2_offline`; (c) the
source round is audited valid; (d) the rule blocks at least one counting variant; (d′) the
rule blocks every applicable `encoding_only` variant (D24 amendment, 2026-11-18); (e) not an
exact duplicate; (f) the library has room. Every failing criterion is recorded with its own
code; raw evidence is never deleted.

**D24 — What counts as a variant.** Classified per variant: a probe (re-encoding only), a
non-equivalent transformation, a path above the web root and a normalizer-neutralized
variant (forms(variant) ⊇ forms(source)) never count. "Blocks a variant": the rule alone
fires on at least one counting variant.
*Amendment, proposed 2026-11-17 during 6.1a, APPROVED by the designer 2026-11-18 with an
addition:*
- **Exclusion.** **Encoding-only** variants (the fully decoded request equals the source's:
  E3 hex case, E4 decode one level, E5 `+`/`%20`, T1r) never count for (d). Exclusion reason
  `encoding_only`, recorded.
- **Criterion (d′)** (designer addition): a rule must block **all** applicable
  `encoding_only` variants of its source, else reason `encoding_fragile`. It is vacuously
  true when the source has none. "Applicable" means exclusion reason `encoding_only`;
  probes, non-equivalent, above-root and neutralized variants are not inputs.
- **Rationale, a logical argument independent of any data.**
  - An encoding-only variant has the same fully decoded request as its source, and the
    server reads both identically. So it cannot show that a rule generalises.
  - It can show that a rule is fragile. A rule that tests a decoded form fires on the
    variant iff it fires on the source, because that decoded form is among the variant's
    forms too. Such a rule passes (d′) by construction.
  - A rule anchored to one raw spelling (for example case-sensitive raw `..%2f`) misses a
    variant that spells the same bytes another way. (d′) rejects exactly the rules whose
    match depends on one encoding of the attack.
  - The argument uses only the normalizer and the rule language.

**D25 — Dedup.** Exact duplicates (same canonical form) are rejected. Behavioural duplicates
(the same non-empty firing set over the retention corpus) are an advisory flag only
(designer: confirmed).

**D26 — One writer, train-only.** `library/writer.py` is imported only by
`tools/promote_rules.py`; the in-match and replay code paths import only the read-only
`rules/library.py` (tested on the import graph). Promotion accepts only a frozen match with
`purpose: "train"`, completed, from a clean tree, not in `config/test_set.json`, not under
`data/golden/`; a replay is never a source. `run_match.py --purpose train` (default `dev`)
is refused on a dirty tree. The writer itself also refuses test-set match ids.

**D27 — The holdout.** Offline only: never sent in a match, never read by retention or any
selection code. Captured verbatim through the Target **outside any match**
(`tools/build_holdout.py`; the Target is reset after capture, designer answer 2), sealed by
sha256 in `config/test_set.json` and committed before the first train match.
Pre-registration is enforced in code: promotion refuses a train match whose recorded commit
does not contain the sealed files with those hashes.

**D28 — Train protocol.** K = 5 independent train matches, no library loaded, the Gate 3
configuration (AI Red gpt-6-luna effort low, AI Blue Haiku 5.5, rules on, caching on for
both; dev models, D12), seeds 6101–6105 (benign schedule only). Promotion in ascending
`match_id` order after the audits (designer: confirmed).

**D29 — M5 design.** The 3 Gate 3 sources replayed with the explicitly loaded empty library
v0000 vs the final library, all else identical. Primary: AI calls and cost. Secondary:
detection and FP (raw + audited), coverage by `rule_origin`, holdout hits per library rule.
A zero-token prediction of the library-answered lines is recorded before the GO.

**D30 — Audit before promotion, scoped** (designer amendment): only the **source rounds of
candidate rules** (the rounds whose request produced a rule) are audited for a train match,
not every round. `tools/audit_match.py` scaffolds, validates and sheets exactly those rounds
for train matches. Scripted labels stay valid by construction (D16).

**D31 — `benign/fixture_v2_offline.jsonl`** (designer answer 3, new): a small TRAIN-side
offline fixture, 6 CWE-22 look-alikes, the holdout's categories with disjoint instances.
Used ONLY by retention criterion (b) alongside `fixture_v1`; never sent, never part of Judge
fact 4b output. Sealed in the same commit as the holdout. Reason: `fixture_v1` has no CWE-22
hard negative, so without it retention cannot catch an over-broad traversal rule.

**D32 — One above-root predicate** (designer answer 7, new): `rules/paths.py` `above_root` is
the single definition, imported by `red/red_guard.py` and `judge/variants.py`; `judge/` never
imports `red/` (tested). `tools/verify_red_guard.py` checks that definition against the real
nginx. Behaviour unchanged.

**Standing rule (designer, 2026-11-18).** Nothing is run on `data/golden/` or on any
test-set data (the matches in `config/test_set.json`, the sealed holdout) without the
designer's explicit GO. This includes read-only debugging, and committed tests or tools
whose inputs include those folders.

## Implementation notes (Stage 6.1a, 2026-11-17)

- **Formats.** Verdicts 0.4 (only with a library; 0.3 frozen as `verdict_v0_3`); `match.json`
  0.8 (`purpose`, `blue_params.library`, `failed_step` `library`; 0.7 frozen); `replay.json`
  0.3 (`blue_params.library`; 0.2 frozen). New schemas: `rule_library`, `variant`,
  `retention_row`, `retention_manifest`, `benign_holdout`, `benign_offline_draft`,
  `test_set`. `JUDGE_VERSION` 0.7.0. Normalization, prompts and their hashes unchanged.
- **An empty library is a loaded library.** v0000 makes Blue write 0.4 verdicts and
  snapshot `library.json`, exactly like a non-empty one, so M5's two arms differ only in the
  library's contents (found by the offline Gate 2 test: `Library` defines `__len__`, so an
  empty one was falsy and was silently dropped; fixed with `__bool__` and explicit
  `is not None` checks; regression-tested).
- **X1 is a whole-vector swap, not a handler swap.** The plan listed X1 as "event handler
  swap, same tag". Swapping only the handler is not an equivalent attack
  (`<img src=x onload=…>` never fires), so X1 replaces the element's opening part up to
  `handler=` with another self-firing vector (`img src=x onerror`, `svg onload`, `body onload`,
  `details open ontoggle`, `input autofocus onfocus`), keeping the sink and the field's
  encoding. Reported to the designer.
- **Mutator sanity check on golden rules, disclosed.** While building the mutator, it was run
  once (read-only, offline) on the Stage 5 rules stored in the golden Gate 3 folders to check
  it produced well-formed variants. That run exposed three objective bugs, all fixed: the
  `=` of `q=` being encoded, word boundaries after `%XX` escapes, and the X1 equivalence
  above. It also led to the D24 amendment proposal. The golden folders are TEST data. No
  library rule was selected with them (none exists yet), and no transformation was tuned to
  change any golden rule's outcome. The unit tests use synthetic sources only.
- **Promotion order** compares `match_id` strings. Within one second, two ids order by their
  random suffix; train matches take minutes, so this only matters in tests (which use
  ascending ids).
- **gitleaks.** Fake passwords in the holdout draft are multi-word phrases. High-entropy
  single tokens tripped the generic-api-key rule. No allowlist was added.
