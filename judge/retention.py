"""Rule retention (Stage 6.1, M2, D23, D25, D30, D31). PURE: no network, no file access;
the caller (tools/promote_rules.py) loads the artifacts and writes the outputs.

Decides, for every rule a TRAIN match stored (rules.jsonl, in order), whether it enters
the rule library. Every failing criterion is recorded, not just the first:

  (a) fact 3        replay_fires is true          else  fact3_false
                    cwe_matches_source is true    else  cwe_mismatch
  (b) fact 4b       0 hits on benign/fixture_v1    else  fixture_hit
                    0 hits on benign/fixture_v2_offline (D31; computed here with the
                    same engine)                   else  offline_fixture_hit
  (c) audit (D30)   the source round is audited valid
                                       invalid  -> source_label_invalid
                                       missing / unaudited -> source_unaudited
  (d) variants      >= 1 counting variant (judge/variants.py)  else no_counting_variant
                    the rule, ALONE, fires on >= 1 of them      else no_variant_blocked
  (d')  encoding    the rule, ALONE, fires on EVERY applicable encoding_only variant of
                    its source (exclusion_reason "encoding_only"; vacuously true when
                    there is none)                               else encoding_fragile
  (e) dedup (D25)   canonical form not already in the library, nor retained earlier in
                    this promotion                              else duplicate_exact
  (f) cap           only for a rule that passes (a)-(e): the library has room
                                                                else library_cap_reached

`no_counting_variant` (the mutator found nothing to vary: a mutator gap) is kept apart
from `no_variant_blocked` (the rule is too narrow).

Why (d') (D24 amendment, designer decision 2026-11-18). An encoding_only variant has the
same fully decoded request as its source, so it cannot show that a rule generalises: it is
never counted for (d). It can show the opposite. A rule that tests a decoded form fires on
the variant iff it fires on the source, because that decoded form is among the variant's
forms too; such a rule passes (d') by construction. A rule anchored to one raw spelling
(e.g. case-sensitive raw `..%2f`) fails on a variant that spells the same bytes another
way, although the server reads both identically. So (d') rejects exactly the rules whose
match depends on one encoding of the attack. The argument is about the normalizer and the
rule language only, not about any data.

Behavioural duplicates (D25) are ADVISORY: `behavioural_duplicate_of` names the first
library entry (or earlier retained rule) that fires on exactly the same, non-empty set of
requests of the retention corpus (this match's judged proxy lines, both fixtures and all
variants generated in this promotion). It never rejects.

The holdout set (benign/holdout_v1.jsonl) is TEST data: nothing here reads it (S6-1).
Rows hold Red ground truth (source label, facts): Blue never reads them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from judge import variants as variants_mod
from rules import engine, library as rule_library, validator

RETENTION_VERSION = "1"
REASONS = ("fact3_false", "cwe_mismatch", "fixture_hit", "offline_fixture_hit",
           "source_label_invalid", "source_unaudited", "no_counting_variant",
           "no_variant_blocked", "encoding_fragile", "duplicate_exact",
           "library_cap_reached")


@dataclass
class Candidate:
    rule_row: dict                 # one rules.jsonl row
    result: dict                   # its rule_results.jsonl row (facts 3 + 4b)
    source_round: int | None       # the Red round of source_request_id
    source_label: str | None       # Red's label of that round
    audit_verdict: str | None      # valid | invalid | unaudited | None (no line)
    variants: list[variants_mod.Variant] = field(default_factory=list)


def _reason(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


def _hits(v: validator.Validated, rows: list[dict]) -> list[str]:
    return [r["benign_id"] for r in rows
            if engine.fires(v, engine.forms(engine.Request.from_log(r)))]


def _fires_on(v: validator.Validated, corpus_forms: list[dict]) -> frozenset[int]:
    return frozenset(i for i, f in enumerate(corpus_forms) if engine.fires(v, f))


def decide(match_id: str, candidates: list[Candidate], library: rule_library.Library,
           offline_fixture: list[dict], corpus: list[dict], base_seed: int,
           cap: int = rule_library.MAX_ENTRIES) -> list[dict]:
    """retention.jsonl rows, one per candidate, in order (schemas/retention_row)."""
    corpus_forms = [engine.forms(engine.Request.from_log(r)) for r in corpus]
    canon_ids = {rule_library.canonical_sha256(lr.validated.rule): lr.library_id
                 for lr in library.entries}
    known = [(lr.library_id, _fires_on(lr.validated, corpus_forms)) for lr in library.entries]
    next_n = len(library.entries) + 1
    rows = []
    for c in candidates:
        rule = c.rule_row["rule"]
        v = validator.validate_rule(0, rule, set())
        if not v.valid:  # rules.jsonl is cross-checked by the Judge: never happens
            raise ValueError(f"{rule.get('rule_id')}: stored rule is invalid")
        res = c.result
        reasons: list[dict] = []
        if res["replay_fires"] is not True:
            reasons.append(_reason("fact3_false", f"replay_fires {res['replay_fires']} "
                                   f"({res['replay_reason'] or 'did not fire'})"))
        if res["cwe_matches_source"] is False:
            reasons.append(_reason("cwe_mismatch", f"rule cwe {rule['cwe']} vs source label "
                                   f"{res['source_label']}"))
        if res["fixture_fires"] != 0:
            reasons.append(_reason("fixture_hit", f"fires on fixture_v1 "
                                   f"{res['fixture_benign_ids']}"))
        off_hits = _hits(v, offline_fixture)
        if off_hits:
            reasons.append(_reason("offline_fixture_hit", f"fires on fixture_v2_offline "
                                   f"{off_hits}"))
        if c.audit_verdict == "invalid":
            reasons.append(_reason("source_label_invalid", f"source round {c.source_round} "
                                   f"is audited invalid (D16)"))
        elif c.audit_verdict != "valid":
            reasons.append(_reason("source_unaudited", f"source round {c.source_round} has "
                                   f"audit verdict {c.audit_verdict!r} (D30)"))
        counting = [x for x in c.variants if x.counting]
        blocked = [x.variant_id for x in counting
                   if engine.fires(v, engine.forms(engine.Request.from_log(x.request)))]
        if not counting:
            reasons.append(_reason("no_counting_variant", f"{len(c.variants)} variants "
                                   f"generated, none counting"))
        elif not blocked:
            reasons.append(_reason("no_variant_blocked", f"fires on 0 of {len(counting)} "
                                   f"counting variants"))
        encoding = [x for x in c.variants if x.exclusion_reason == "encoding_only"]
        enc_blocked = [x.variant_id for x in encoding
                       if engine.fires(v, engine.forms(engine.Request.from_log(x.request)))]
        if len(enc_blocked) < len(encoding):
            missed = [f"{x.transformation} {x.variant_id}" for x in encoding
                      if x.variant_id not in enc_blocked]
            reasons.append(_reason("encoding_fragile", f"fires on {len(enc_blocked)} of "
                                   f"{len(encoding)} encoding_only variants; misses {missed}"))
        canon = rule_library.canonical_sha256(rule)
        dup_of = canon_ids.get(canon)
        if dup_of is not None:
            reasons.append(_reason("duplicate_exact", f"same canonical form as {dup_of}"))
        fired = _fires_on(v, corpus_forms)
        behavioural = next((lid for lid, s in known if fired and s == fired), None)
        if not reasons and next_n - 1 >= cap:
            reasons.append(_reason("library_cap_reached", f"library holds {next_n - 1} rules "
                                   f"(max {cap})"))
        retained = not reasons
        lib_id = f"lib-{next_n:04d}" if retained else None
        if retained:
            next_n += 1
            canon_ids[canon] = lib_id
            known.append((lib_id, fired))
        rows.append({
            "schema_version": "0.1", "retention_version": RETENTION_VERSION,
            "match_id": match_id, "rule_id": rule["rule_id"], "cwe": rule["cwe"],
            "decision": "retained" if retained else "rejected", "library_id": lib_id,
            "reasons": reasons, "canonical_sha256": canon,
            "duplicate_of": dup_of, "behavioural_duplicate_of": behavioural,
            "source_request_id": rule["source_request_id"], "source_round": c.source_round,
            "source_label": c.source_label, "audit_verdict": c.audit_verdict,
            "replay_fires": res["replay_fires"], "replay_reason": res["replay_reason"],
            "cwe_matches_source": res["cwe_matches_source"],
            "fixture_v1_hits": list(res["fixture_benign_ids"]),
            "fixture_v2_hits": off_hits,
            "variants_generated": [x.variant_id for x in c.variants],
            "variants_counting": [x.variant_id for x in counting],
            "variants_blocked": blocked,
            "variants_encoding": [x.variant_id for x in encoding],
            "variants_encoding_blocked": enc_blocked,
            "base_seed": base_seed, "mutator_version": variants_mod.MUTATOR_VERSION})
    return rows
