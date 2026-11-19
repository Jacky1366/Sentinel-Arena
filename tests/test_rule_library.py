"""The rule library (Stage 6.1, M1, D20, D25): the read-only reader (rules/library.py),
the canonical form and exact dedup, and the single writer (library/writer.py): versioned,
immutable files, never overwritten, never under data/golden/. Pure file work in tmp."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from llm_fakes import REPO
from library import writer  # noqa: E402
from rules import library as rule_library  # noqa: E402

M1, M2 = "20261120T010000Z-aaaa", "20261120T020000Z-bbbb"
RID = "22222222-2222-4222-8222-2222222222%02d"
NOW = "2026-11-20T00:00:00.000Z"


def rule(i=1, cwe="CWE-89", pattern="union", field="query", op="contains", ci=True, match=M1):
    return {"rule_id": f"r-{i:03d}", "cwe": cwe,
            "conditions": [{"field": field, "op": op, "pattern": pattern,
                            "case_insensitive": ci}],
            "source_request_id": RID % i, "created_at_log_seq": i, "created_match": match}


def retained(r, match=M1, line=1):
    return {"rule": r, "promoted_from": {"match_id": match, "rule_id": r["rule_id"]},
            "retention_ref": {"path": f"data/library/retention/{match}/retention.jsonl",
                              "line": line}}


def make_library(d: Path, *batches) -> list[Path]:
    """v0000, then one promotion per (match_id, [rules]) batch. Returns every file."""
    paths = [writer.write(writer.empty_doc(NOW), d)]
    for mid, rules in batches:
        parent = rule_library.load(paths[-1])
        doc = writer.next_doc(json.loads(paths[-1].read_text()), parent.path, parent.sha256,
                              mid, [retained(r, mid, i) for i, r in enumerate(rules, 1)],
                              NOW, [])
        paths.append(writer.write(doc, d))
    return paths


def test_empty_library_v0000_is_committed_and_valid():
    lib = rule_library.load(REPO / "data" / "library" / "rule_library_v0000.json")
    assert lib.library_version == 0 and len(lib) == 0
    assert lib  # an empty library is still a loaded library (never mistaken for "none")


def test_promotions_write_new_versions_and_never_overwrite(tmp_path):
    paths = make_library(tmp_path, (M1, [rule(1), rule(2, "CWE-22", "../", "path")]),
                         (M2, [rule(3, "CWE-79", "<script", match=M2)]))
    assert [p.name for p in paths] == ["rule_library_v0000.json", "rule_library_v0001.json",
                                       "rule_library_v0002.json"]
    lib = rule_library.load(paths[-1])
    assert [e.library_id for e in lib.entries] == ["lib-0001", "lib-0002", "lib-0003"]
    doc = json.loads(paths[-1].read_text())
    assert doc["promoted_matches"] == [M1, M2]
    assert doc["parent"]["sha256"] == rule_library.load(paths[1]).sha256
    assert [e["promoted_in_version"] for e in doc["entries"]] == [1, 1, 2]
    before = paths[1].read_bytes()
    with pytest.raises(FileExistsError):
        writer.write(json.loads(paths[1].read_text()), tmp_path)
    assert paths[1].read_bytes() == before


def test_a_match_is_promoted_once_and_in_ascending_order(tmp_path):
    paths = make_library(tmp_path, (M2, [rule(1, match=M2)]))
    parent = rule_library.load(paths[-1])
    doc = json.loads(paths[-1].read_text())
    with pytest.raises(ValueError, match="already promoted"):
        writer.next_doc(doc, parent.path, parent.sha256, M2, [], NOW, [])
    with pytest.raises(ValueError, match="ascending"):
        writer.next_doc(doc, parent.path, parent.sha256, M1, [], NOW, [])


def test_writer_refuses_a_test_match_id(tmp_path):
    paths = make_library(tmp_path)
    parent = rule_library.load(paths[-1])
    test_id = json.loads((REPO / "config" / "test_set.json").read_text())["match_ids"][0]
    with pytest.raises(ValueError, match="test data"):
        writer.next_doc(json.loads(paths[-1].read_text()), parent.path, parent.sha256,
                        test_id, [], NOW, [])


def test_writer_refuses_data_golden():
    with pytest.raises(ValueError, match="golden"):
        writer.write(writer.empty_doc(NOW), REPO / "data" / "golden" / "lib")


def test_canonical_form_dedup():
    a = rule(1, pattern="UNION SELECT")
    b = rule(2, pattern="union select")                       # ci contains: same rule
    c = rule(3, pattern="UNION SELECT", ci=False)             # case-sensitive: different
    d = rule(4, op="regex", pattern="\\S+union")
    e = rule(5, op="regex", pattern="\\s+union")              # a regex is never lowercased
    assert rule_library.canonical_sha256(a) == rule_library.canonical_sha256(b)
    assert rule_library.canonical_sha256(a) != rule_library.canonical_sha256(c)
    assert rule_library.canonical_sha256(d) != rule_library.canonical_sha256(e)
    two = {**a, "conditions": a["conditions"] + [{"field": "path", "op": "contains",
                                                   "pattern": "/rest", "case_insensitive": True}]}
    swapped = {**two, "conditions": list(reversed(two["conditions"]))}
    assert rule_library.canonical_sha256(two) == rule_library.canonical_sha256(swapped)
    other_cwe = {**a, "cwe": "CWE-79"}
    assert rule_library.canonical_sha256(a) != rule_library.canonical_sha256(other_cwe)


def test_an_exact_duplicate_cannot_enter_the_library(tmp_path):
    with pytest.raises(rule_library.LibraryError, match="exact duplicate"):
        make_library(tmp_path, (M1, [rule(1, pattern="UNION"), rule(2, pattern="union")]))


@pytest.mark.parametrize("tamper,match", [
    (lambda d: d["entries"][0].update(canonical_sha256="0" * 64), "canonical_sha256"),
    (lambda d: d["entries"][0].update(library_id="lib-0007"), "promotion order"),
    (lambda d: d["entries"][0]["rule"].pop("created_match"), "schema-invalid"),
    (lambda d: d["entries"][0]["rule"]["conditions"][0].update(op="regex",
                                                               pattern="(?=x)"), "validator"),
    (lambda d: d["entries"][0]["promoted_from"].update(match_id=M2), "promoted_matches"),
    (lambda d: d.update(promoted_matches=[M2, M1]), "ascending"),
    (lambda d: d.update(parent=None), "parent"),
    (lambda d: d["entries"][0].update(promoted_in_version=9), "promoted_in_version"),
])
def test_reader_rejects_a_tampered_library(tmp_path, tamper, match):
    paths = make_library(tmp_path, (M1, [rule(1)]))
    doc = json.loads(paths[-1].read_text())
    bad = copy.deepcopy(doc)
    tamper(bad)
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(rule_library.LibraryError, match=match):
        rule_library.load(p)


def test_library_params_are_the_provenance_block(tmp_path):
    paths = make_library(tmp_path, (M1, [rule(1)]))
    lib = rule_library.load(paths[-1], display="data/library/x.json")
    assert lib.params() == {"path": "data/library/x.json", "sha256": lib.sha256,
                            "library_version": 1, "entries": 1}
