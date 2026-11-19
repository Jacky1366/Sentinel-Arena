"""The variant mutator (Stage 6.1, M3, S6-2, D24): pure, seeded, deterministic; each
transformation does what it says and keeps the request's structure and field encoding;
each variant is classified on its own (probe, non-equivalent, above root, neutralized,
encoding-only, counting). Synthetic sources only: never golden (test) data."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
from judge import variants as V  # noqa: E402

M = "20261120T010000Z-aaaa"
RID = "33333333-3333-4333-8333-333333333301"
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "variant.schema.json").read_text()))


def src(path="/rest/products/search", query="", body="", method="GET"):
    return {"method": method, "path": path, "query": query, "body": body}


SQLI_Q = src(query="q=%27%20OR%201%3D1--")
SQLI_UNION = src(query="q=%27))%20UNION%20SELECT%20id,email%20FROM%20Users--")
SQLI_JSON = src("/rest/user/login", body='{"email":"\' OR 1=1--","password":"x"}', method="POST")
XSS_Q = src(query="q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
XSS_JS = src(query="q=%3Ciframe%20src%3D%22javascript:alert(1)%22%3E")
TRAV = src("/ftp/../ftp/legal.md")
TRAV_ENC = src("/ftp/..%2fpackage.json")
NULLB = src("/ftp/coupons_2013.md.bak%2500.md")


def gen(s, cwe, seed=1):
    return V.generate(s, cwe, seed, M, RID)


def by_t(vs):
    return {v.transformation: v for v in vs}


def test_deterministic_and_order_independent():
    a = [V.row(v, M, RID, "CWE-89", 1) for v in gen(SQLI_UNION, "CWE-89")]
    b = [V.row(v, M, RID, "CWE-89", 1) for v in gen(SQLI_UNION, "CWE-89")]
    assert a == b
    gen(XSS_Q, "CWE-79")  # generating something else first changes nothing
    assert [V.row(v, M, RID, "CWE-89", 1) for v in gen(SQLI_UNION, "CWE-89")] == a
    assert V.seed_for(1, M, RID) != V.seed_for(2, M, RID)


def test_rows_are_schema_valid():
    for s, cwe in ((SQLI_Q, "CWE-89"), (SQLI_JSON, "CWE-89"), (XSS_Q, "CWE-79"),
                   (XSS_JS, "CWE-79"), (TRAV, "CWE-22"), (TRAV_ENC, "CWE-22"),
                   (NULLB, "CWE-22")):
        for v in gen(s, cwe):
            SCHEMA.validate(V.row(v, M, RID, cwe, 1))
            assert v.counting == (v.exclusion_reason is None)


def test_no_anchor_means_no_variant():
    assert gen(src("/rest/basket/1"), "CWE-22") == []
    with pytest.raises(ValueError):
        gen(SQLI_Q, "benign")


def test_at_most_max_variants_and_no_duplicates():
    for s, cwe in ((SQLI_UNION, "CWE-89"), (XSS_Q, "CWE-79"), (TRAV, "CWE-22")):
        vs = gen(s, cwe)
        assert len(vs) <= V.MAX_VARIANTS
        ids = [v.variant_id for v in vs]
        assert len(ids) == len(set(ids)) and V.variant_id(s) not in ids


# ---- classification ---------------------------------------------------------------

def test_probes_never_count_and_are_neutralized():
    t = by_t(gen(TRAV, "CWE-22"))
    assert t["T1"].request["path"] == "/ftp/%2e%2e%2fftp/legal.md"
    assert t["T1"].neutralized and t["T1"].exclusion_reason == "normalizer_probe"
    assert t["T2"].exclusion_reason == "normalizer_probe" and not t["T2"].counting


def test_encoding_only_variants_never_count():
    t = by_t(gen(TRAV_ENC, "CWE-22"))
    assert t["E3"].request["path"] == "/ftp/..%2Fpackage.json"
    assert t["E3"].encoding_only and t["E3"].exclusion_reason == "encoding_only"
    assert t["T1r"].request["path"] == "/ftp/../package.json"
    assert t["T1r"].exclusion_reason == "encoding_only"
    assert t["T3"].counting and t["T3"].request["path"] in ("/ftp/./..%2fpackage.json",
                                                            "/ftp/.%2f..%2fpackage.json")


def test_neutralized_and_above_root_are_classified_as_such():
    double = {**SQLI_Q, "query": "q=%2527%2520OR%25201%253D1--"}
    assert V.classify(SQLI_Q, "S1", double).exclusion_reason == "normalizer_neutralized"
    above = {**TRAV, "path": "/../../etc/passwd"}
    assert V.classify(TRAV, "T3", above).exclusion_reason == "above_root"
    t = by_t(gen(TRAV, "CWE-22"))
    assert t["T4"].exclusion_reason == "non_equivalent" and "T7" in t


# ---- transformations ---------------------------------------------------------------

def test_e1_keeps_query_structure_and_skips_json():
    s = src(query="q=a'b&sort=(x)")
    v = V.e1_encode(dict(s), None)
    assert v["query"] == "q=a%27b&sort=%28x%29"
    assert V.e1_encode(dict(SQLI_JSON), None) is None  # a JSON body is never URL-decoded


def test_sql_transformations():
    t = by_t(gen(SQLI_UNION, "CWE-89"))
    assert t["S1"].request["query"].lower() == SQLI_UNION["query"].lower()
    assert t["S1"].request["query"] != SQLI_UNION["query"]
    assert "%09UNION%09SELECT%09" in t["S2"].request["query"]
    assert "/**/UNION/**/SELECT/**/" in t["S3"].request["query"]
    assert t["S5"].request["query"].endswith("Users/*")
    q = by_t(gen(SQLI_Q, "CWE-89"))
    n = q["S4"].request["query"]
    assert n.startswith("q=%27%20OR%20") and n.endswith("--") and "1%3D1" not in n
    left, right = n[len("q=%27%20OR%20"):-2].split("%3D")
    assert left == right and left != "1"


def test_sql_in_a_json_body_uses_json_escapes():
    t = by_t(gen(SQLI_JSON, "CWE-89"))
    assert "'\\tOR\\t1=1--" in t["S2"].request["body"]
    json.loads(t["S2"].request["body"])  # still valid JSON
    assert "E1" not in t and "E4" not in t


def test_xss_transformations():
    t = by_t(gen(XSS_Q, "CWE-79"))
    x1 = t["X1"].request["query"]
    assert "alert(1)" in x1 and "%3Cimg" not in x1 and x1.startswith("q=%3C")
    assert t["X2"].request["query"].lower() == XSS_Q["query"].lower()
    assert "%3Cimg/src" in t["X3"].request["query"]
    assert "onerror%3D%22alert(1)%22" in t["X4"].request["query"]
    assert ("confirm(1)" in t["X5"].request["query"]) or ("prompt(1)" in t["X5"].request["query"])
    assert "%26%23x61%3Blert(1)" in t["X6"].request["query"]
    j = by_t(gen(XSS_JS, "CWE-79"))["X7"].request["query"]
    assert "%09" in j and j.lower().replace("%09", "") == XSS_JS["query"].lower()


def test_traversal_transformations():
    t = by_t(gen(NULLB, "CWE-22"))
    assert t["T5"].request["path"].startswith("/ftp/coupons_2013.md.bak%2500.")
    assert not t["T5"].request["path"].endswith(".md") and t["T5"].counting
    assert t["T6"].request["path"].endswith("%2500.md")
    assert "coupons_2013.md.bak" not in t["T6"].request["path"]
    assert by_t(gen(TRAV, "CWE-22"))["T6"].request["path"].startswith("/ftp/../ftp/")


def test_every_listed_transformation_is_reachable():
    seen = set()
    for s, cwe in ((SQLI_Q, "CWE-89"), (SQLI_UNION, "CWE-89"), (src(query="q=a+b'c"), "CWE-89"),
                   (XSS_Q, "CWE-79"), (XSS_JS, "CWE-79"), (TRAV, "CWE-22"),
                   (TRAV_ENC, "CWE-22"), (NULLB, "CWE-22")):
        seen |= {v.transformation for v in gen(s, cwe)}
    assert seen == set(V.TRANSFORMATIONS), set(V.TRANSFORMATIONS) - seen
