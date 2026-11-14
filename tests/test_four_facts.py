"""tools/four_facts.py: the Stage 5 done-when check (Stage 5.7). Three outcomes:
PASS, N/A (no rules) and FAIL. Pure file reads; built on the committed gate-5.5
replays (rules off / shadow / on) and the golden matches."""

from __future__ import annotations

import json
import shutil

import pytest

from llm_fakes import REPO
from tools import four_facts as ff  # noqa: E402

GATE = REPO / "data" / "golden" / "replays" / "gate-5.5"
ON = GATE / "ai-red-luna-gate2-match1-on"
OFF = GATE / "ai-red-luna-gate2-match1-off"


def copy(src, tmp_path):
    d = tmp_path / src.name
    shutil.copytree(src, d)
    return d


def test_rules_on_with_stored_rules_is_pass():
    r = ff.check(ON)
    assert r["status"] == ff.PASS and r["rules_mode"] == "on"
    assert set(r["facts"].values()) == {"computed"}
    assert r["counts"]["rule_results.jsonl"] == 4


def test_shadow_scores_its_rules_too():
    assert ff.check(GATE / "ai-red-luna-gate2-match1-shadow")["status"] == ff.PASS


def test_rules_off_is_na_by_design():
    r = ff.check(OFF)
    assert r["status"] == ff.NA and "rule invention off" in r["reasons"][0]
    assert r["facts"]["fact1_landed"] == r["facts"]["fact4a_benign_fp"] == "computed"


def test_scripted_blue_is_na():
    r = ff.check(REPO / "data" / "golden" / "scripted-baseline-benign-match")
    assert r["status"] == ff.NA and "scripted Blue" in r["reasons"][0]


def test_rules_on_but_blue_stored_no_rule_is_na_not_fail(tmp_path):
    d = copy(ON, tmp_path)
    (d / "rule_results.jsonl").write_text("")  # valid and empty: no rule to score
    r = ff.check(d)
    assert r["status"] == ff.NA and "stored no rule" in r["reasons"][0]


@pytest.mark.parametrize("break_it,why", [
    (lambda d: (d / "rule_results.jsonl").unlink(), "rule_results.jsonl missing"),
    (lambda d: (d / "rounds.jsonl").unlink(), "rounds.jsonl missing"),
    (lambda d: (d / "rounds.jsonl").write_text(""), "rounds.jsonl is empty"),
    (lambda d: (d / "benign_results.jsonl").write_text(""), "benign_results.jsonl is empty"),
    (lambda d: (d / "benign_results.jsonl").unlink(), "benign_results.jsonl missing"),
    (lambda d: (d / "rule_results.jsonl").write_text("{not json\n"), "not JSON"),
    (lambda d: (d / "rule_results.jsonl").write_text(json.dumps({"schema_version": "0.1"})
                                                     + "\n"), "schema-invalid"),
    (lambda d: (d / "rounds.jsonl").write_text(json.dumps({"schema_version": "9"}) + "\n"),
     "unknown schema_version"),
])
def test_missing_or_invalid_artifacts_fail(tmp_path, break_it, why):
    d = copy(ON, tmp_path)
    break_it(d)
    r = ff.check(d)
    assert r["status"] == ff.FAIL
    assert any(why in x for x in r["reasons"]), r["reasons"]


def test_old_match_without_benign_traffic_fails():
    r = ff.check(REPO / "data" / "golden" / "scripted-baseline-match")
    assert r["status"] == ff.FAIL and r["reasons"] == ["benign_results.jsonl missing"]


def test_cli_exit_codes(capsys):
    assert ff.main(["--run-dir", str(ON)]) == 0
    assert ff.main(["--run-dir", str(OFF)]) == 3
    assert ff.main(["--run-dir", str(REPO / "data" / "golden" / "scripted-baseline-match")]) == 1
    assert "four facts: PASS" in capsys.readouterr().out


def test_check_writes_nothing(tmp_path):
    d = copy(ON, tmp_path)
    before = sorted(p.name for p in d.iterdir())
    ff.check(d)
    assert sorted(p.name for p in d.iterdir()) == before
