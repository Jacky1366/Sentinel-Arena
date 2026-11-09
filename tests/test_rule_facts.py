"""Judge facts 3 and 4b on the golden benign match, against the designer-approved
hand predictions (tools/stage5_3_expected.json). Pure; no Docker."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import score_rules  # noqa: E402
from judge import rule_facts  # noqa: E402

GOLDEN = REPO / "data" / "golden" / "scripted-baseline-benign-match"
RULES_PATH = REPO / "tools" / "stage5_3_rules.json"
RULES = json.loads(RULES_PATH.read_text())["rules"]
EXPECTED = json.loads((REPO / "tools" / "stage5_3_expected.json").read_text())
FIXTURE = [json.loads(l) for l in (REPO / "benign" / "fixture_v1.jsonl").read_text().splitlines()]


def score(match_dir=GOLDEN, rules=RULES):
    return rule_facts.score(rules, score_rules.load_match(match_dir), FIXTURE, "a" * 64)


def test_every_hand_rule_matches_its_prediction():
    results, _ = score()
    assert len(results) == len(RULES) == len(EXPECTED["rules"])
    for rule, got in zip(RULES, results):
        tag = rule["note"].split(" ")[0]
        e = EXPECTED["rules"][tag]
        assert {"valid": got["valid"],
                "invalid_codes": [r["code"] for r in got["invalid_reasons"]],
                "replay_fires": got["replay_fires"], "replay_reason": got["replay_reason"],
                "cwe_matches_source": got["cwe_matches_source"],
                "fixture_benign_ids": got["fixture_benign_ids"]} == e, tag


def test_anomalies_are_exactly_the_predicted_one():
    _, anomalies = score()
    s1 = next(r for r in RULES if r["note"].startswith("S1 "))
    assert anomalies == [{"schema_version": "0.1", "match_id": "20261109T021518Z-7d72",
                          "kind": "rule_source_benign", "request_id": s1["source_request_id"],
                          "detail": {"rule_id": s1["rule_id"], "benign_id": "h06"}}]


def test_source_label_is_reds_label():
    results, _ = score()
    m1 = next(r for r, rule in zip(results, RULES) if rule["note"].startswith("M1 "))
    assert (m1["cwe"], m1["source_label"], m1["cwe_matches_source"]) == ("CWE-79", "CWE-89", False)


def test_s3_orphan_source(tmp_path):
    # S3: the source is a Red record with no proxy line. Built on a COPY of the
    # golden match (never modify the golden folder): round 5's line removed.
    copy = tmp_path / "match"
    shutil.copytree(GOLDEN, copy)
    red5 = next(json.loads(l) for l in (copy / "red_attacks.jsonl").read_text().splitlines()
                if json.loads(l)["round"] == 5)
    proxy = copy / "proxy.jsonl"
    proxy.write_text("".join(l + "\n" for l in proxy.read_text().splitlines()
                             if red5["request_id"] not in l))
    s3 = {"rule_id": "r-900", "cwe": "CWE-22", "source_request_id": red5["request_id"],
          "created_at_log_seq": 16, "note": "S3 orphan source",
          "conditions": [{"field": "path", "op": "contains", "pattern": "%2500",
                          "case_insensitive": False}]}
    [got], anomalies = score(copy, [s3])
    assert (got["replay_fires"], got["replay_reason"]) == (None, "source_orphan")
    assert got["fixture_benign_ids"] == [] and got["source_label"] is None
    assert anomalies == []
    # and on the intact golden match the same rule replays normally
    [intact], _ = score(GOLDEN, [s3])
    assert intact["replay_fires"] is True


def test_fixture_hits_follow_fixture_order():
    results, _ = score()
    for r in results:
        ids = [f["benign_id"] for f in FIXTURE]
        assert r["fixture_benign_ids"] == sorted(r["fixture_benign_ids"], key=ids.index)


def test_the_judge_never_imports_blue():
    # The rule machinery is neutral (rules/); the Judge must not depend on the
    # subject's package.
    import re
    for path in sorted((REPO / "judge").glob("*.py")) + sorted((REPO / "rules").glob("*.py")):
        text = path.read_text()
        assert not re.search(r"^\s*(from\s+blue\b|import\s+blue\b)", text, re.M), path.name
