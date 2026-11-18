"""A match with a rule library, end to end on FakeOps + the fake provider (Stage 6.1): the
library is snapshotted into the match folder, Blue preloads it, match.json 0.8 records it,
the Judge's rule-verdict cross-check re-runs hot-load WITH the snapshot and raises on any
inconsistency (tampered snapshot, wrong rule_origin, missing snapshot, a 0.3 row)."""

from __future__ import annotations

import hashlib
import json

import pytest

from test_blue_rules import cond, verdict
from test_rule_library import make_library, rule
from test_run_match_failure import assert_finalized
from test_run_match_rules import RulesOps, dirs, rows  # noqa: F401 (fixture)
from judge import fact2_detected, rule_verdicts  # noqa: E402
import run_match  # noqa: E402

XSS_LIB = rule(1, cwe="CWE-79", pattern="<script")


def benign_brain(view):
    return verdict("benign")


def go(dirs, lib_path, answer=benign_brain, **kw):
    live, runs = dirs
    out: list[str] = []
    code, d = run_match.run_match(ops=RulesOps(live, answer=answer), live_dir=live,
                                  runs_dir=runs, engine="claude", blue_rules_mode="on",
                                  library=lib_path, out=out.append, **kw)
    return code, d, "\n".join(out)


@pytest.fixture
def lib(tmp_path):
    return make_library(tmp_path / "lib", ("20261120T010000Z-aaaa", [XSS_LIB]))[-1]


def test_match_with_a_library_snapshots_it_and_records_it(dirs, lib):
    before = hashlib.sha256(lib.read_bytes()).hexdigest()
    code, d, out = go(dirs, lib)
    assert code == 0, out
    m = assert_finalized(dirs[0], d)
    assert m["schema_version"] == "0.8" and m["purpose"] == "dev"
    assert m["blue_params"]["library"]["sha256"] == before
    assert m["blue_params"]["library"]["library_version"] == 1
    assert (d / "library.json").read_bytes() == lib.read_bytes()
    assert m["artifacts"]["library.json"]["sha256"] == before
    assert hashlib.sha256(lib.read_bytes()).hexdigest() == before  # never written
    v = rows(d, "verdicts.jsonl")
    assert [r["rule_origin"] for r in v] == [None, "library", None, None]
    assert v[1]["fired_rule_ids"] == ["lib-0001"]
    r = {x["request_id"]: x for x in rows(d, "rounds.jsonl")}
    assert r["22222222-2222-4222-8222-222222222222"]["verdict_source"] == "rule"
    assert "rule library v1 (1 rules, read-only)" in out


def test_library_needs_claude_blue_in_mode_on(dirs, lib):
    live, runs = dirs
    for kw in ({"engine": "scripted"}, {"engine": "claude", "blue_rules_mode": "shadow"}):
        out: list[str] = []
        code, d = run_match.run_match(ops=RulesOps(live), live_dir=live, runs_dir=runs,
                                      library=lib, out=out.append, **kw)
        assert code == 2 and d is None, out


def test_a_bad_library_is_refused_at_preflight(dirs, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    code, d, out = go(dirs, bad)
    assert code == 2 and d is None and "schema-invalid library" in out


def _judge(d):
    return fact2_detected.load_verdicts(d)


def test_judge_raises_on_a_tampered_snapshot(dirs, lib):
    code, d, _ = go(dirs, lib)
    assert code == 0
    _judge(d)  # consistent as written
    doc = json.loads((d / "library.json").read_text())
    doc["entries"][0]["rule"]["conditions"][0]["pattern"] = "<iframe"
    from rules import library as rule_library
    doc["entries"][0]["canonical_sha256"] = rule_library.canonical_sha256(doc["entries"][0]["rule"])
    (d / "library.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="no hot-loaded rule fires"):
        _judge(d)


def test_judge_raises_on_a_wrong_origin(dirs, lib):
    code, d, _ = go(dirs, lib)
    v = rows(d, "verdicts.jsonl")
    v[1]["rule_origin"] = "match"
    v[1]["fired_rule_ids"] = ["r-001"]
    (d / "verdicts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in v))
    with pytest.raises(ValueError):
        _judge(d)


def test_judge_raises_without_the_snapshot(dirs, lib):
    code, d, _ = go(dirs, lib)
    (d / "library.json").unlink()
    with pytest.raises(ValueError, match="no library.json"):
        _judge(d)


def test_judge_raises_on_a_0_3_row_next_to_a_library(dirs, lib):
    code, d, _ = go(dirs, lib)
    v = rows(d, "verdicts.jsonl")
    v[0] = {k: x for k, x in v[0].items() if k != "rule_origin"} | {"schema_version": "0.3"}
    (d / "verdicts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in v))
    with pytest.raises(ValueError, match="with a library every row is 0.4"):
        _judge(d)


def test_library_and_in_match_rules_together_cross_check(dirs, lib):
    def brain(view):  # proposes a rule for the SQLi login, labels the rest benign
        if "OR 1=1" in view["body"]:
            return verdict("CWE-89", {"conditions": [cond(field="body", pattern="or 1=1")]})
        return verdict("benign")
    code, d, out = go(dirs, lib, answer=brain)
    assert code == 0, out
    assert len(rows(d, "rules.jsonl")) == 1
    rule_verdicts.check(d, _judge(d))


def test_purpose_train_needs_a_clean_tree(dirs, lib):
    live, runs = dirs

    class Dirty(RulesOps):
        def git_info(self):
            return {"commit": "f" * 40, "dirty": True}
    out: list[str] = []
    code, d = run_match.run_match(ops=Dirty(live), live_dir=live, runs_dir=runs,
                                  engine="claude", blue_rules_mode="on", purpose="train",
                                  out=out.append)
    assert code == 2 and "clean committed tree" in "\n".join(out)
    code, d = run_match.run_match(ops=RulesOps(live), live_dir=live, runs_dir=runs,
                                  engine="claude", blue_rules_mode="on", purpose="train",
                                  out=out.append)
    assert code == 0 and json.loads((d / "match.json").read_text())["purpose"] == "train"
    code, _ = run_match.run_match(ops=RulesOps(live), live_dir=live, runs_dir=runs,
                                  purpose="test", out=out.append)
    assert code == 2
