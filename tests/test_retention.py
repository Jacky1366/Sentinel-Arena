"""Retention decisions (Stage 6.1, M2, D23, D25, D30, D31): judge/retention.py is pure; every
failing criterion is recorded with its own code; dedup and the cap depend on library
state; behavioural duplicates are advisory only. Synthetic inputs only."""

from __future__ import annotations

import json

from jsonschema import Draft202012Validator

from llm_fakes import REPO
from test_rule_library import make_library, rule
from judge import retention, variants  # noqa: E402
from rules import library as rule_library  # noqa: E402

M = "20261121T000000Z-cccc"
ROW = Draft202012Validator(json.loads((REPO / "schemas" / "retention_row.schema.json").read_text()))
SQLI = {"method": "GET", "path": "/rest/products/search", "query": "q=%27%20OR%201%3D1--",
        "body": ""}


def result(r, replay=True, cwe_ok=True, fixture=()):
    return {"rule_id": r["rule_id"], "replay_fires": replay, "replay_reason": None,
            "cwe_matches_source": cwe_ok, "source_label": "CWE-89",
            "fixture_fires": len(fixture), "fixture_benign_ids": list(fixture)}


def cand(r, audit="valid", vs=None, **kw):
    return retention.Candidate(
        rule_row={"schema_version": "0.1", "match_id": M, "hot_loaded": True, "rule": r},
        result=result(r, **kw), source_round=1, source_label="CWE-89", audit_verdict=audit,
        variants=variants.generate(SQLI, "CWE-89", 1, M, r["source_request_id"])
        if vs is None else vs)


def mrule(i, pattern="or 1=1", **kw):
    return rule(i, pattern=pattern, match=M, **kw)


def empty_lib(tmp_path):
    return rule_library.load(REPO / "data" / "library" / "rule_library_v0000.json")


def decide(tmp_path, cands, lib=None, offline=(), corpus=(), cap=50):
    rows = retention.decide(M, cands, lib or empty_lib(tmp_path), list(offline), list(corpus),
                            1, cap)
    for r in rows:
        ROW.validate(r)
    return rows


def codes(row):
    return [x["code"] for x in row["reasons"]]


def test_a_good_rule_is_retained_with_its_evidence(tmp_path):
    [row] = decide(tmp_path, [cand(mrule(1))])
    assert row["decision"] == "retained" and row["library_id"] == "lib-0001"
    assert row["variants_blocked"] and set(row["variants_blocked"]) <= set(row["variants_counting"])
    assert row["source_label"] == "CWE-89" and row["audit_verdict"] == "valid"
    # (d'): a rule on decoded text blocks every encoding_only variant by construction
    assert row["variants_encoding"] and row["variants_encoding_blocked"] == row["variants_encoding"]


def test_every_failing_criterion_is_recorded(tmp_path):
    [row] = decide(tmp_path, [cand(mrule(1), audit="invalid", replay=False, cwe_ok=False,
                                   fixture=("h01",))],
                   offline=[{"benign_id": "yh01", "method": "GET", "path": "/",
                             "query": "q=or 1=1", "body": ""}])
    assert row["decision"] == "rejected" and row["library_id"] is None
    assert codes(row) == ["fact3_false", "cwe_mismatch", "fixture_hit", "offline_fixture_hit",
                          "source_label_invalid"]
    assert row["fixture_v2_hits"] == ["yh01"]


def test_unaudited_source_is_its_own_reason(tmp_path):
    [row] = decide(tmp_path, [cand(mrule(1), audit="unaudited")])
    assert codes(row) == ["source_unaudited"]
    [row] = decide(tmp_path, [cand(mrule(1), audit=None)])
    assert codes(row) == ["source_unaudited"]


def test_no_counting_variant_vs_no_variant_blocked(tmp_path):
    [row] = decide(tmp_path, [cand(mrule(1), vs=[])])
    assert codes(row) == ["no_counting_variant"]
    narrow = mrule(2, pattern="q=%27%20OR%201%3D1--", op="equals", field="query", ci=False)
    [row] = decide(tmp_path, [cand(narrow)])
    # fires on its source only; also raw-anchored, so (d') fails too
    assert codes(row) == ["no_variant_blocked", "encoding_fragile"]


def test_exact_duplicates_against_the_library_and_within_one_promotion(tmp_path):
    lib = rule_library.load(make_library(tmp_path / "dup", ("20261120T010000Z-aaaa",
                                                            [rule(1, pattern="OR 1=1")]))[-1])
    rows = decide(tmp_path, [cand(mrule(1, pattern="or 1=1")), cand(mrule(2, pattern="union"))],
                  lib=lib)
    assert codes(rows[0]) == ["duplicate_exact"] and rows[0]["duplicate_of"] == "lib-0001"
    rows = decide(tmp_path, [cand(mrule(1)), cand(mrule(2, pattern="OR 1=1"))])
    assert rows[0]["decision"] == "retained"
    assert codes(rows[1]) == ["duplicate_exact"] and rows[1]["duplicate_of"] == "lib-0001"


def test_the_cap_only_applies_to_a_rule_that_passes_everything_else(tmp_path):
    rows = decide(tmp_path, [cand(mrule(1)), cand(mrule(2, pattern="1=1")),
                             cand(mrule(3, pattern="or 1"), audit="invalid")], cap=1)
    assert rows[0]["decision"] == "retained"
    assert codes(rows[1]) == ["library_cap_reached"]
    assert codes(rows[2]) == ["source_label_invalid"]  # not also the cap


def test_behavioural_duplicate_is_advisory_only(tmp_path):
    corpus = [SQLI, {**SQLI, "query": "q=apple"}]
    rows = decide(tmp_path, [cand(mrule(1, pattern="or 1=1")),
                             cand(mrule(2, op="regex", pattern="or\\s+1=1"))], corpus=corpus)
    assert [r["decision"] for r in rows] == ["retained", "retained"]
    assert rows[1]["behavioural_duplicate_of"] == "lib-0001"
    assert rows[0]["behavioural_duplicate_of"] is None


def test_retention_never_reads_the_holdout():
    src = (REPO / "judge" / "retention.py").read_text()
    assert "holdout" not in src.replace("The holdout set (benign/holdout_v1.jsonl) is TEST "
                                        "data: nothing here reads it (S6-1).", "")


def test_encoding_fragile_rule_is_rejected_although_it_generalises(tmp_path):
    """(d'), D24 amendment: a rule anchored to one raw spelling (case-sensitive `1%3D1`)
    still blocks counting variants (keyword case, whitespace), so it passes (d); it misses
    the variant that only flips the hex case of the same escape (E3), which the server reads
    identically: encoding_fragile."""
    raw = mrule(1, pattern="1%3D1", ci=False)
    [row] = decide(tmp_path, [cand(raw)])
    assert codes(row) == ["encoding_fragile"] and row["decision"] == "rejected"
    assert row["variants_blocked"]  # (d) holds
    t = {x.variant_id: x.transformation for x in cand(raw).variants}
    missed = set(row["variants_encoding"]) - set(row["variants_encoding_blocked"])
    assert "E3" in {t[m] for m in missed}
    assert "E3" in row["reasons"][0]["detail"]


def test_encoding_criterion_is_vacuous_without_encoding_variants(tmp_path):
    vs = [x for x in cand(mrule(1)).variants if x.exclusion_reason != "encoding_only"]
    [row] = decide(tmp_path, [cand(mrule(1), vs=vs)])
    assert row["decision"] == "retained" and row["variants_encoding"] == []


def test_encoding_criterion_counts_only_encoding_only_variants(tmp_path):
    """Probes, non-equivalent, above-root and neutralized variants are not (d') inputs."""
    [row] = decide(tmp_path, [cand(mrule(1))])
    by_id = {x.variant_id: x for x in cand(mrule(1)).variants}
    assert all(by_id[i].exclusion_reason == "encoding_only" for i in row["variants_encoding"])
    assert {i for i, x in by_id.items() if x.exclusion_reason == "encoding_only"} \
        == set(row["variants_encoding"])
