"""The autonomy table (Stage 6.2, M6): stats/autonomy.py is pure and every column follows
its definition; the CLI is a pure reader over frozen folders (non-test golden folders and
synthetic data only here; the committed 6.1b table is checked in
tests/test_autonomy_6_1b_evidence.py)."""

from __future__ import annotations

import json
import math

import pytest

from llm_fakes import PRICES, REPO
from stats import autonomy  # noqa: E402
from tools import autonomy_table  # noqa: E402

M = "20261120T000000Z-dddd"


def rid(i):
    return f"00000000-0000-4000-8000-{i:012d}"


def rnd(i, label, detected=True, type_correct=True, source="ai", reason=None):
    return {"round": i, "request_id": rid(i), "label": label,
            "verdict": label if detected else "benign", "verdict_source": source,
            "landed": False, "landed_reason": None, "newly_solved": [],
            "detected": detected, "type_correct": type_correct if detected else None,
            "detected_reason": reason}


def ben(i, verdict="benign", fp=False):
    return {"request_id": rid(100 + i), "benign_id": f"n{i:02d}", "category": "normal",
            "verdict": verdict, "verdict_source": "ai", "false_positive": fp, "fp_reason": None}


def ver(seq, request_id, source="ai", origin=None):
    return {"log_seq": seq, "request_id": request_id, "source": source,
            "rule_origin": origin, "verdict": "x"}


def call(seq, agent="blue"):
    return {"agent": agent, "model": "fake-small", "log_seq_first": seq, "log_seq_last": seq,
            "refusal": None, "ok": True, "input_tokens": 1000, "output_tokens": 100,
            "cached_input_tokens": 0, "cache_write_tokens": 0}


def folder():
    rounds = [rnd(1, "CWE-89", source="rule"), rnd(2, "CWE-89"), rnd(3, "CWE-22", detected=False),
              rnd(4, "CWE-79", type_correct=False)]
    benign = [ben(1), ben(2, verdict="CWE-22", fp=True), ben(3)]
    verdicts = [ver(1, rid(1), "rule", "library"), ver(2, rid(2)), ver(3, rid(3)),
                ver(4, rid(4)), ver(5, rid(101)), ver(6, rid(102), "rule", "match"),
                ver(7, rid(103))]
    calls = [call(2), call(3), call(4), call(5), call(7), call(None, agent="red")]
    return autonomy.Folder("synthetic", rounds, benign, verdicts, calls, audit_rows=[],
                           scripted={1, 2, 3, 4})


def test_cp_upper_bound_is_exact_for_zero_successes():
    assert autonomy.cp_upper_zero(40) == pytest.approx(1 - 0.025 ** (1 / 40))
    assert autonomy.rate(0, 51)["upper95"] == pytest.approx(0.0698, abs=1e-4)
    assert autonomy.rate(0, 40)["upper95"] == pytest.approx(0.0881, abs=1e-4)
    assert "upper95" not in autonomy.rate(1, 40) and "upper95" not in autonomy.rate(0, 0)
    # the bound is the p at which P(X = 0) = 0.025
    n = 17
    p = autonomy.cp_upper_zero(n)
    assert math.isclose((1 - p) ** n, 0.025)


def test_every_column_follows_its_definition():
    t = autonomy.arm_table([folder()], PRICES)["rows"]
    assert (t["CWE-89"]["detection_raw"]["k"], t["CWE-89"]["detection_raw"]["n"]) == (2, 2)
    assert (t["CWE-22"]["detection_raw"]["k"], t["CWE-22"]["detection_raw"]["n"]) == (0, 1)
    assert (t["CWE-79"]["type_correct"]["k"], t["CWE-79"]["type_correct"]["n"]) == (0, 1)
    # verdict FP: benign lines given THAT cwe, over all scored benign lines
    assert (t["CWE-22"]["verdict_fp"]["k"], t["CWE-22"]["verdict_fp"]["n"]) == (1, 3)
    assert t["CWE-89"]["verdict_fp"]["k"] == 0 and t["total"]["verdict_fp"]["k"] == 1
    # rule coverage: CWE rows over that CWE's attack verdicts; total over every verdict
    c89, tot = t["CWE-89"]["rule_coverage"], t["total"]["rule_coverage"]
    assert (c89["rule"]["k"], c89["rule"]["n"], c89["library"]["k"], c89["match"]["k"]) == \
        (1, 2, 1, 0)
    assert (tot["rule"]["k"], tot["rule"]["n"], tot["library"]["k"], tot["match"]["k"]) == \
        (2, 7, 1, 1)
    # calls: CWE rows = Blue calls attributed by log_seq_first; total = every agent
    assert [t[c]["ai_calls"] for c in ("CWE-89", "CWE-79", "CWE-22")] == [1, 1, 1]
    assert t["total"]["ai_calls"] == 6
    assert t["CWE-89"]["cost_usd"] > 0 and t["total"]["cost_usd"] >= sum(
        t[c]["cost_usd"] for c in ("CWE-89", "CWE-79", "CWE-22"))


def test_audited_detection_excludes_invalid_and_is_null_when_incomplete():
    f = folder()
    f.scripted = set()
    f.audit_rows = [{"round": i, "verdict": "valid"} for i in (1, 2, 4)] + \
        [{"round": 3, "verdict": "invalid"}]
    t = autonomy.arm_table([f], PRICES)
    assert t["audit_complete"] and t["rows"]["CWE-22"]["detection_audited"]["n"] == 0
    assert t["rows"]["total"]["detection_audited"]["n"] == 3
    f.audit_rows = f.audit_rows[:2]
    t = autonomy.arm_table([f], PRICES)
    assert not t["audit_complete"] and t["rows"]["total"]["detection_audited"] is None


def test_arms_sum_their_folders():
    one = autonomy.arm_table([folder()], PRICES)["rows"]["total"]
    two = autonomy.arm_table([folder(), folder()], PRICES)["rows"]["total"]
    assert two["detection_raw"]["n"] == 2 * one["detection_raw"]["n"]
    assert two["ai_calls"] == 2 * one["ai_calls"]


def test_cli_reads_non_test_folders_and_is_deterministic(tmp_path):
    arms = [("scripted", [REPO / "data" / "golden" / "scripted-baseline-benign-match"]),
            ("train", [REPO / "data" / "golden" / "train-6.1b-gate1-match1"])]
    lib = REPO / "data" / "library" / "rule_library_v0001.json"
    fx = {"fixture_v1": REPO / "benign" / "fixture_v1.jsonl",
          "fixture_v2_offline": REPO / "benign" / "fixture_v2_offline.jsonl"}
    a = autonomy_table.build(arms, "t", lib, offline_sets=fx)
    b = autonomy_table.build(arms, "t", lib, offline_sets=fx)
    assert a == b
    j, m = autonomy_table.write(a, tmp_path / "x.1")
    assert j.name == "x.1.json" and m.name == "x.1.md"
    assert json.loads(j.read_text()) == a
    s = a["arms"]["scripted"]["rows"]["total"]
    assert s["ai_calls"] == 0 and s["rule_coverage"]["rule"]["k"] == 0
    tr = a["arms"]["train"]
    assert tr["audit_complete"] is False  # D30: train audits cover candidate rounds only
    assert tr["rows"]["total"]["detection_audited"] is None
    assert tr["rows"]["total"]["rule_coverage"]["match"]["k"] > 0
    assert set(a["library_fp"]["rules"]) == {"lib-0001", "lib-0002", "lib-0003", "lib-0004"}


def test_cli_refuses_a_folder_that_is_not_frozen(tmp_path, capsys):
    (tmp_path / "x").mkdir()
    assert autonomy_table.main(["--arm", "a", str(tmp_path / "x")]) == 2
    assert "not a frozen match or replay" in capsys.readouterr().out


def test_repeated_requests_are_counted_once_for_the_bound():
    """Pseudo-replication: the same benign request in two sources is ONE unit for the
    95% bound; k/n lines are still shown."""
    a, b = folder(), folder()
    for f in (a, b):  # identical requests in both "sources"
        f.requests = {rid(i): ("GET", f"/p{i}", "", "") for i in range(1, 104)}
    t = autonomy.arm_table([a, b], PRICES)["rows"]
    fp = t["CWE-89"]["verdict_fp"]
    assert (fp["k"], fp["n"], fp["unique"]) == (0, 6, {"k": 0, "n": 3})
    assert fp["upper95"] == round(autonomy.cp_upper_zero(3), 4)
    tot = t["total"]["verdict_fp"]
    assert (tot["k"], tot["n"], tot["unique"]) == (2, 6, {"k": 1, "n": 3})
    assert "upper95" not in tot
    det = t["CWE-89"]["detection_raw"]
    assert (det["k"], det["n"], det["unique"]) == (4, 4, {"k": 2, "n": 2})
    # distinct requests: no `unique` field, the bound is on lines
    one = autonomy.arm_table([folder()], PRICES)["rows"]["CWE-89"]["verdict_fp"]
    assert "unique" not in one and one["upper95"] == round(autonomy.cp_upper_zero(3), 4)


def test_unique_k_is_any_line_with_the_event():
    r = autonomy.lines_rate([(("a",), False), (("a",), True), (("b",), False)])
    assert (r["k"], r["n"], r["unique"]) == (1, 3, {"k": 1, "n": 2})
    assert "upper95" not in r
