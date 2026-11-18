"""rules/hotload.py with a library (Stage 6.1, D21): library rules are preloaded, live from
line 1, first in the tie-break, and report origin "library"; without a library nothing
changes. Pure."""

from __future__ import annotations

from llm_fakes import REPO  # noqa: F401  (adds repo to sys.path)
from test_rule_library import make_library, rule
from rules import engine, hotload, library as rule_library, validator


def req(query="", path="/rest/products/search"):
    return engine.Request("GET", path, query, "")


def lib_of(tmp_path, *rules):
    return rule_library.load(make_library(tmp_path, ("20261120T010000Z-aaaa", list(rules)))[-1])


def in_match(i, seq, **kw):
    r = {**rule(i, **kw), "created_at_log_seq": seq, "created_match": "20261121T000000Z-cccc"}
    return validator.validate_rule(0, r, set())


def test_library_rules_fire_from_line_one(tmp_path):
    hl = hotload.HotLoad(lib_of(tmp_path, rule(1, pattern="union")).entries)
    f = hl.fire(req("q=union+select"), 1)
    assert f.rule_ids == ["lib-0001"] and f.cwe == "CWE-89" and f.origin == "library"
    assert hl.preloaded == 1 and len(hl) == 0


def test_library_rules_come_first_in_the_tie_break(tmp_path):
    hl = hotload.HotLoad(lib_of(tmp_path, rule(1, cwe="CWE-79", pattern="union")).entries)
    hl.add(in_match(1, 1, cwe="CWE-89", pattern="union"))
    f = hl.fire(req("q=union"), 5)
    assert f.rule_ids == ["lib-0001", "r-001"]
    assert f.cwe == "CWE-79" and f.origin == "library" and f.conflict


def test_in_match_rule_wins_when_no_library_rule_fires(tmp_path):
    hl = hotload.HotLoad(lib_of(tmp_path, rule(1, pattern="drop table")).entries)
    hl.add(in_match(1, 1, pattern="union"))
    f = hl.fire(req("q=union"), 2)
    assert f.rule_ids == ["r-001"] and f.origin == "match"
    assert hl.fire(req("q=union"), 1).rule_ids == []  # D4 still holds for in-match rules


def test_without_a_library_behaviour_is_stage_5_5(tmp_path):
    hl = hotload.HotLoad()
    assert hl.fire(req("q=union"), 1) == hotload.Firing([], None, False)
    hl.add(in_match(1, 1, pattern="union"))
    f = hl.fire(req("q=union"), 2)
    assert (f.rule_ids, f.cwe, f.conflict, f.origin) == (["r-001"], "CWE-89", False, "match")


def test_nothing_fires_means_no_origin(tmp_path):
    hl = hotload.HotLoad(lib_of(tmp_path, rule(1, pattern="union")).entries)
    assert hl.fire(req("q=apple"), 3).origin is None
