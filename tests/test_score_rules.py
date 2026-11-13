"""tools/score_rules.py: writes only into its own new output dir, never into a
match folder; outputs schema-valid; deterministic."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import score_rules  # noqa: E402

GOLDEN = REPO / "data" / "golden" / "scripted-baseline-benign-match"
RULES = REPO / "tools" / "stage5_3_rules.json"


def tree_hash(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(d).as_posix().encode() + p.read_bytes())
    return h.hexdigest()


def schema(name):
    return Draft202012Validator(json.loads((REPO / "schemas" / f"{name}.schema.json").read_text()))


def test_scores_into_a_new_dir_and_never_touches_the_match(tmp_path):
    before = tree_hash(GOLDEN)
    out = tmp_path / "out"
    m = score_rules.run(RULES, GOLDEN, out)
    assert tree_hash(GOLDEN) == before
    assert sorted(p.name for p in out.iterdir()) == ["anomalies.jsonl", "rule_results.jsonl",
                                                    "rule_score.json"]
    schema("rule_score").validate(m)
    for l in (out / "rule_results.jsonl").read_text().splitlines():
        schema("rule_result").validate(json.loads(l))
    for l in (out / "anomalies.jsonl").read_text().splitlines():
        schema("anomaly").validate(json.loads(l))
    assert m["normalization_version"] == "2" and m["judge_version"] == "0.6.0"
    assert m["re2_version"] == "1.1.20251105"
    assert m["fixture"] == {"path": "benign/fixture_v1.jsonl", "version": "1",
                            "sha256": hashlib.sha256((REPO / "benign" / "fixture_v1.jsonl")
                                                     .read_bytes()).hexdigest(), "entries": 17}
    assert m["summary"] == {"valid": 18, "invalid": 15, "replay_fires": 13, "replay_misses": 3,
                            "replay_null": 17, "rules_with_fixture_hits": 6, "anomalies": 1}


def test_deterministic(tmp_path):
    a = score_rules.run(RULES, GOLDEN, tmp_path / "a", now=lambda: "2026-11-09T00:00:00.000Z")
    b = score_rules.run(RULES, GOLDEN, tmp_path / "b", now=lambda: "2026-11-09T00:00:00.000Z")
    assert a == b
    for name in ("rule_results.jsonl", "anomalies.jsonl", "rule_score.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


@pytest.mark.parametrize("where", [lambda: GOLDEN, lambda: GOLDEN / "scores",
                                   lambda: GOLDEN / "a" / "b"])
def test_refuses_to_write_into_a_match_folder(where):
    before = tree_hash(GOLDEN)
    with pytest.raises(score_rules.Refused, match="immutable"):
        score_rules.run(RULES, GOLDEN, where())
    assert tree_hash(GOLDEN) == before and not (GOLDEN / "scores").exists()


def test_refuses_any_dir_that_holds_a_match_json(tmp_path):
    fake_match = tmp_path / "runs" / "20261109T000000Z-abcd"
    fake_match.mkdir(parents=True)
    (fake_match / "match.json").write_text("{}")
    with pytest.raises(score_rules.Refused):
        score_rules.run(RULES, GOLDEN, fake_match / "out")


def test_refuses_a_non_empty_out_dir(tmp_path):
    (tmp_path / "x").write_text("keep me")
    with pytest.raises(score_rules.Refused, match="not an empty directory"):
        score_rules.run(RULES, GOLDEN, tmp_path)
    assert (tmp_path / "x").read_text() == "keep me"


def test_bad_wrapper_is_refused_and_main_exits_2(tmp_path):
    bad = tmp_path / "rules.json"
    bad.write_text(json.dumps({"rules": []}))
    assert score_rules.main(["--rules", str(bad), "--match", str(GOLDEN),
                             "--out", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out").exists()


def test_not_a_frozen_match(tmp_path):
    with pytest.raises(score_rules.Refused, match="not a frozen match"):
        score_rules.run(RULES, tmp_path, tmp_path / "out")


def test_main_succeeds(tmp_path, capsys):
    assert score_rules.main(["--rules", str(RULES), "--match", str(GOLDEN),
                             "--out", str(tmp_path / "out")]) == 0
    assert "ANOMALY rule_source_benign" in capsys.readouterr().out
