"""rules/hotload.py (Stage 5.5, D4, D9): a rule applies only to LATER lines; the
earliest hot-loaded rule wins a CWE tie-break; a conflict is flagged. Pure."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from rules import engine, hotload, validator  # noqa: E402

SRC = "11111111-1111-4111-8111-111111111111"


def rule(rid, cwe, seq, field="query", op="contains", pattern="union", ci=True):
    r = {"rule_id": rid, "cwe": cwe, "source_request_id": SRC, "created_at_log_seq": seq,
         "conditions": [{"field": field, "op": op, "pattern": pattern,
                         "case_insensitive": ci}]}
    v = validator.validate_rule(0, r, set())
    assert v.valid, v.reasons
    return v


def req(query="", path="/rest/products/search", body="", method="GET"):
    return engine.Request(method, path, query, body)


def test_a_rule_never_applies_to_its_own_line_only_to_later_ones():
    hl = hotload.HotLoad()
    hl.add(rule("r-001", "CWE-89", 5))
    hit = req("q=UNION select")
    assert hl.fire(hit, 5).rule_ids == []          # the line that produced it
    assert hl.fire(hit, 4).rule_ids == []          # earlier lines, obviously
    f = hl.fire(hit, 6)                            # the next line
    assert (f.rule_ids, f.cwe, f.conflict) == (["r-001"], "CWE-89", False)


def test_nothing_fires_on_a_non_matching_line():
    hl = hotload.HotLoad()
    hl.add(rule("r-001", "CWE-89", 1))
    assert hl.fire(req("q=apple"), 9) == hotload.Firing([], None, False)


def test_tie_break_earliest_rule_wins_and_conflict_is_flagged():
    hl = hotload.HotLoad()
    hl.add(rule("r-001", "CWE-79", 2, pattern="<"))
    hl.add(rule("r-002", "CWE-89", 3, pattern="union"))
    hl.add(rule("r-003", "CWE-89", 4, pattern="select"))
    f = hl.fire(req("q=<b>union select"), 10)
    assert f.rule_ids == ["r-001", "r-002", "r-003"] and f.cwe == "CWE-79" and f.conflict


def test_same_cwe_from_several_rules_is_not_a_conflict():
    hl = hotload.HotLoad()
    hl.add(rule("r-001", "CWE-89", 2, pattern="union"))
    hl.add(rule("r-002", "CWE-89", 3, pattern="select"))
    f = hl.fire(req("q=union select"), 4)
    assert f.rule_ids == ["r-001", "r-002"] and f.cwe == "CWE-89" and not f.conflict


def test_a_rule_only_counts_once_its_line_has_passed_even_when_others_are_live():
    hl = hotload.HotLoad()
    hl.add(rule("r-001", "CWE-22", 2, field="path", pattern="..", ci=False))
    hl.add(rule("r-002", "CWE-89", 7, field="path", pattern="ftp"))
    line = req(path="/ftp/../x")
    assert hl.fire(line, 7).rule_ids == ["r-001"]
    assert hl.fire(line, 8).rule_ids == ["r-001", "r-002"]


def test_decoded_forms_count_like_everywhere_else():
    hl = hotload.HotLoad()
    hl.add(rule("r-001", "CWE-89", 1, pattern="' or 1=1"))
    assert hl.fire(req("q=%27+OR+1%3D1"), 2).rule_ids == ["r-001"]  # '+'-decoded query


def test_invalid_or_out_of_order_rules_are_refused():
    hl = hotload.HotLoad()
    bad = validator.validate_rule(0, {"rule_id": "r-001"}, set())
    with pytest.raises(ValueError, match="validated"):
        hl.add(bad)
    hl.add(rule("r-002", "CWE-89", 5))
    with pytest.raises(ValueError, match="in order"):
        hl.add(rule("r-003", "CWE-89", 4))
    assert len(hl) == 1
