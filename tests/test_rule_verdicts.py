"""Judge cross-check of rule verdicts and rule artifacts (judge/rule_verdicts.py,
Stage 5.5). A correct run passes; every tampered or inconsistent artifact raises.
Fake provider only (via test_blue_rules helpers); the Judge reads files only."""

from __future__ import annotations

import json

import pytest

from test_blue_rules import RIDS, cond, pline, run, union_brain, verdict
from judge import fact2_detected, rule_verdicts  # noqa: E402


def lines():
    return [pline(RIDS[0], query="q=1 union select"),   # AI CWE-89 + r-001
            pline(RIDS[1], query="q=apple"),             # AI benign
            pline(RIDS[2], query="q=2 union all"),       # rule r-001
            pline(RIDS[3], query="q=bad"),               # AI CWE-89 + invalid r-002
            pline(RIDS[4], query="q=pear")]              # AI benign


def brain(view):
    if view["query"] == "q=bad":
        return verdict("CWE-89", {"conditions": []})
    return union_brain(view)


def write(d, name, rows):
    (d / name).write_text("".join(json.dumps(r) + "\n" for r in rows))


@pytest.fixture
def match(tmp_path):
    """A consistent rules-mode-on run dir: proxy, verdicts, rules, rejections, calls."""
    out, _, _ = run(tmp_path, lines(), brain)
    write(tmp_path, "verdicts.jsonl", out.verdicts)
    write(tmp_path, "rules.jsonl", out.rules)
    write(tmp_path, "rule_rejections.jsonl", out.rejections)
    return tmp_path, out


def rows(d, name):
    return [json.loads(l) for l in (d / name).read_text().splitlines()]


def check(d):
    return fact2_detected.load_verdicts(d)


def test_a_consistent_run_passes(match):
    d, out = match
    got = check(d)
    assert [r["source"] for r in got] == ["ai", "ai", "rule", "ai", "ai"]
    assert got[2]["fired_rule_ids"] == ["r-001"]


def tamper(d, name, i, **change):
    rs = rows(d, name)
    rs[i] = {**rs[i], **change}
    write(d, name, rs)


@pytest.mark.parametrize("desc,name,i,change,msg", [
    ("rule verdict relabeled", "verdicts.jsonl", 2, {"verdict": "CWE-22"}, "fire"),
    ("rule verdict passed off as AI", "verdicts.jsonl", 2,
     {"source": "ai", "fired_rule_ids": [], "reason": "ai verdict"}, "fire"),
    ("fired ids padded", "verdicts.jsonl", 2, {"fired_rule_ids": ["r-001", "r-002"]}, "fire"),
    ("AI verdict claims a rule", "verdicts.jsonl", 1,
     {"verdict": "CWE-89", "source": "rule", "fired_rule_ids": ["r-001"],
      "reason": "rule r-001 fired"}, "no hot-loaded rule fires"),
    ("rule source moved", "rules.jsonl", 0, None, "that line's verdict"),
    ("rule cwe differs from the line's label", "rules.jsonl", 0, None, "label"),
    ("rejection on a benign line it was not proposed on", "rule_rejections.jsonl", 0,
     {"created_at_log_seq": 2, "source_request_id": RIDS[1]}, "label"),
    ("rejection id reuses a stored id", "rule_rejections.jsonl", 0, {"rule_id": "r-001"},
     "more than once"),
])
def test_tampering_raises(match, desc, name, i, change, msg):
    d, _ = match
    if name == "rules.jsonl":
        r = rows(d, name)[0]
        rule = dict(r["rule"])
        if "moved" in desc:
            rule.update(created_at_log_seq=2, source_request_id=RIDS[1])
        else:
            rule["cwe"] = "CWE-22"
        write(d, name, [{**r, "rule": rule}])
    else:
        tamper(d, name, i, **change)
    with pytest.raises(ValueError, match=msg):
        check(d)


def test_an_invalid_rule_in_rules_jsonl_raises(match):
    d, _ = match
    r = rows(d, "rules.jsonl")[0]
    bad = {**r, "rule": {**r["rule"], "conditions": [cond(op="regex", pattern="(?=x)")]}}
    write(d, "rules.jsonl", [bad])
    with pytest.raises(ValueError, match="invalid rule"):
        check(d)


def test_a_schema_invalid_rules_line_raises(match):
    d, _ = match
    write(d, "rules.jsonl", [{**rows(d, "rules.jsonl")[0], "hot_loaded": "yes"}])
    with pytest.raises(ValueError, match="schema-invalid"):
        check(d)


def test_mixed_hot_loaded_raises(match):
    d, out = match
    r = rows(d, "rules.jsonl")[0]
    extra = {**r, "hot_loaded": False,
             "rule": {**r["rule"], "rule_id": "r-009", "created_at_log_seq": 4,
                      "source_request_id": RIDS[3]}}
    write(d, "rules.jsonl", [r, extra])
    with pytest.raises(ValueError, match="mixes hot_loaded"):
        check(d)


def test_deleting_the_rules_file_exposes_the_rule_verdicts(match):
    d, _ = match
    (d / "rules.jsonl").unlink()
    (d / "rule_rejections.jsonl").unlink()
    with pytest.raises(ValueError, match="no rules.jsonl"):
        check(d)


def test_dropping_a_rule_exposes_its_verdicts(match):
    d, _ = match
    write(d, "rules.jsonl", [])
    with pytest.raises(ValueError, match="no hot-loaded rule fires"):
        check(d)


def test_shadow_rules_must_never_answer(tmp_path):
    out, _, _ = run(tmp_path, lines(), brain, mode="shadow")
    write(tmp_path, "verdicts.jsonl", out.verdicts)
    write(tmp_path, "rules.jsonl", out.rules)
    write(tmp_path, "rule_rejections.jsonl", out.rejections)
    assert [r["source"] for r in check(tmp_path)] == ["ai"] * 5
    # Claiming a shadow rule fired is caught: shadow rules are never applied.
    tamper(tmp_path, "verdicts.jsonl", 4, verdict="CWE-89", source="rule",
           fired_rule_ids=["r-001"], reason="rule r-001 fired")
    vs = rows(tmp_path, "verdicts.jsonl")
    vs[4].pop("rationale", None)  # a rule verdict carries none
    write(tmp_path, "verdicts.jsonl", vs)
    with pytest.raises(ValueError, match="no hot-loaded rule fires"):
        check(tmp_path)


def test_instrument_failure_claimed_where_a_rule_fires_raises(tmp_path):
    out, _, _ = run(tmp_path, lines(), brain, blue={"max_calls": 1})
    write(tmp_path, "verdicts.jsonl", out.verdicts)
    write(tmp_path, "rules.jsonl", out.rules)
    write(tmp_path, "rule_rejections.jsonl", out.rejections)
    assert [r["source"] for r in check(tmp_path)] == ["ai", None, "rule", None, None]
    # Blue cannot hide a firing rule's line as a harness failure either.
    tamper(tmp_path, "verdicts.jsonl", 2, verdict=None, source=None, fired_rule_ids=[],
           no_verdict_reason="instrument_failure", failure_detail="refused_by_body",
           reason="instrument failure: refused_by_body")
    with pytest.raises(ValueError, match="fire"):
        check(tmp_path)


def test_matches_without_rule_artifacts_are_unaffected(tmp_path):
    out, _, _ = run(tmp_path, lines(), brain, mode="off")
    write(tmp_path, "verdicts.jsonl", out.verdicts)
    assert len(check(tmp_path)) == 5
    assert rule_verdicts.load_rules(tmp_path) == []
