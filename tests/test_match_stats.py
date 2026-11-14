"""Unit tests for stats/match_stats.py: denominators follow the contract exactly
(orphans excluded from everything, landed=null excluded from landing, no_verdict
counted as a detection miss). Pure; no Docker."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from stats import match_stats as ms  # noqa: E402


def rr(rnd, label="CWE-89", verdict="CWE-89", landed=True, landed_reason=None,
       detected=True, type_correct=True, detected_reason=None):
    return {"round": rnd, "request_id": f"{rnd:08d}-0000-4000-8000-000000000000",
            "label": label, "verdict": verdict, "landed": landed,
            "landed_reason": landed_reason, "newly_solved": [], "detected": detected,
            "type_correct": type_correct, "detected_reason": detected_reason}


ORPHAN = dict(verdict=None, detected=None, type_correct=None, detected_reason="orphan")
NO_VERDICT = dict(verdict=None, detected=False, type_correct=None,
                  detected_reason="no_verdict")
BENIGN = dict(verdict="benign", detected=False, type_correct=None)

MIXED = [
    rr(1),                                                  # landed, detected, correct
    rr(2, landed=False, verdict="CWE-22", type_correct=False),  # wrong type
    rr(3, label="CWE-79", verdict="CWE-79", landed=None, landed_reason="not_measurable"),
    rr(4, label="CWE-22", verdict="CWE-22", landed=None, landed_reason="already_solved"),
    rr(5, landed=None, landed_reason="snapshot_missing", **BENIGN),  # miss
    rr(6, landed=False, **NO_VERDICT),                      # miss
    rr(7, landed=False, **ORPHAN),                          # excluded everywhere
]


def test_landing_excludes_orphans_and_null_landed():
    r = ms.landing_rate(MIXED)
    assert (r.num, r.den) == (1, 3)  # rounds 1, 2, 6; orphan 7's landed=false dropped
    assert r.excluded == {"orphan": [7], "not_measurable": [3],
                          "already_solved": [4], "snapshot_missing": [5]}


def test_detection_excludes_orphans_and_counts_no_verdict_as_miss():
    r = ms.detection_rate(MIXED)
    assert (r.num, r.den) == (4, 6)  # 1,2,3,4 detected; 5 benign + 6 no_verdict = misses
    assert r.excluded == {"orphan": [7]}


def test_snapshot_missing_still_scored_for_detection():
    rounds = [rr(1, landed=None, landed_reason="snapshot_missing")]
    assert (ms.detection_rate(rounds).num, ms.detection_rate(rounds).den) == (1, 1)
    assert ms.landing_rate(rounds).den == 0


def test_type_accuracy_only_over_detected():
    r = ms.type_accuracy(MIXED)
    assert (r.num, r.den) == (3, 4)  # round 2 wrong type
    assert r.excluded == {"benign_verdict": [5], "no_verdict": [6], "orphan": [7]}


def test_counts():
    assert ms.counts(MIXED) == {"rounds": 7, "orphan": 1, "no_verdict": 1,
                                "instrument_failure": 0, "snapshot_missing": 1, "not_measurable": 1,
                                "already_solved": 1}


def test_zero_denominator_is_na_not_crash():
    r = ms.landing_rate([rr(1, label="CWE-79", landed=None, landed_reason="not_measurable")])
    assert r.pct is None and r.fmt() == "0/0 (n/a)"
    assert ms.detection_rate([]).fmt() == "0/0 (n/a)"


def test_fmt_n_over_d_and_percent():
    assert ms.Rate(7, 7).fmt() == "7/7 (100%)"
    assert ms.Rate(2, 3).fmt() == "2/3 (67%)"


def _manifest(status="completed"):
    return {"match_id": "20261109T153012Z-a1b2", "status": status,
            "failed_step": None if status == "completed" else "blue",
            "error": None if status == "completed" else "ValueError: boom",
            "judge_version": "0.1.0", "blue_engine": "scripted",
            "git": {"commit": "f" * 40, "dirty": False}}


def test_summary_states_rates_exclusions_and_footer():
    text = ms.format_summary(MIXED, _manifest())
    assert "detection      4/6 (67%)" in text
    assert "landing        1/3 (33%)" in text
    assert "type accuracy  3/4 (75%)" in text
    assert "orphan [7]" in text and "snapshot_missing [5]" in text
    assert "no_verdict counted as a miss" in text
    assert ms.DETECTION_FOOTER in text
    # one row per round, short request_id
    assert text.count("-0000-4000") == 0 and "00000007" in text


def test_summary_of_failed_match_without_rounds():
    text = ms.format_summary([], _manifest("failed"))
    assert "FAILED at step 'blue'" in text and "(no round records)" in text


def test_stats_never_mutate_input():
    import copy
    before = copy.deepcopy(MIXED)
    ms.compute(MIXED)
    ms.format_summary(MIXED, _manifest())
    assert MIXED == before


def test_summary_cost_line_and_stopped_line():
    from stats import cost
    m = {**_manifest(), "schema_version": "0.2", "cost": cost.summarize([], {"models": {}}),
         "budget": {"limits": {}, "stopped_by": None}}
    text = ms.format_summary(MIXED, m)
    assert "cost $0.00 (0 API calls)" in text and "STOPPED" not in text
    stopped = {**m, "status": "stopped",
               "budget": {"limits": {}, "stopped_by": {"scope": "blue", "reason": "max_usd"}}}
    text = ms.format_summary(MIXED, stopped)
    assert "STOPPED by the AI budget: blue max_usd" in text and "FAILED" not in text


def test_summary_of_v0_1_manifest_has_no_cost_line():
    assert "cost $" not in ms.format_summary(MIXED, _manifest())



# ---- Stage 5.2: benign traffic (fact 4a) -------------------------------------

def br(bid, verdict="benign", fp=False, reason=None, cat=None):
    cat = cat or ("hard_negative" if bid.startswith("h") else "normal")
    return {"benign_id": bid, "category": cat, "request_id": f"{bid}-x", "verdict": verdict,
            "false_positive": fp, "fp_reason": reason}


BENIGN_RESULTS = [
    br("n01"), br("n02", "CWE-89", True), br("n03", None, None, "no_verdict"),
    br("n04", None, None, "orphan"), br("h01", "CWE-79", True), br("h02"), br("h03"),
]


def test_fp_rate_excludes_no_verdict_and_orphan():
    r = ms.fp_rate(BENIGN_RESULTS)
    assert (r.num, r.den) == (2, 5)
    assert r.excluded == {"no_verdict": ["n03"], "orphan": ["n04"]}


def test_fp_rate_hard_negatives_only():
    r = ms.fp_rate(BENIGN_RESULTS, "hard_negative")
    assert (r.num, r.den) == (1, 3)


def test_benign_no_verdict_rate_excludes_orphans():
    r = ms.benign_no_verdict_rate(BENIGN_RESULTS)
    assert (r.num, r.den) == (1, 6) and r.excluded == {"orphan": ["n04"]}


def test_precision_counts_detected_attacks_against_false_positives():
    # MIXED: 4 detected non-orphan attacks; BENIGN_RESULTS: 2 false positives.
    r = ms.precision(MIXED, BENIGN_RESULTS)
    assert (r.num, r.den) == (4, 6)
    assert ms.traffic_mix(MIXED, BENIGN_RESULTS) == "6 attack : 6 benign"


def test_detection_is_never_printed_without_fp_rate():
    for benign in (BENIGN_RESULTS, None):
        text = ms.format_summary(MIXED, _manifest(), benign=benign)
        [det] = [l for l in text.splitlines() if l.startswith("detection")]
        assert "FP rate" in det, det


def test_summary_with_benign_traffic():
    text = ms.format_summary(MIXED, _manifest(), benign=BENIGN_RESULTS, anomalies=[])
    assert "FP rate 2/5 (40%)" in text
    assert "FP hard neg.   1/3 (33%)" in text
    assert "precision      4/6 (67%)     traffic mix 6 attack : 6 benign" in text
    assert "excludes no_verdict [n03], orphan [n04]" in text
    assert "no-verdict     1/6 (17%)" in text
    assert "anomalies: none" in text
    assert ms.DETECTION_FOOTER not in text  # not an upper bound any more


def test_summary_without_benign_traffic_keeps_the_upper_bound_footer():
    text = ms.format_summary(MIXED, _manifest())
    assert "FP rate n/a (no benign traffic)" in text and ms.DETECTION_FOOTER in text


def test_anomalies_are_always_visible():
    a = {"kind": "benign_solved_challenge", "request_id": "deadbeef-0000",
         "detail": {"benign_id": "n04", "newly_solved": ["Score Board"], "expected_solves": []}}
    text = ms.format_summary(MIXED, _manifest(), benign=BENIGN_RESULTS, anomalies=[a])
    assert "ANOMALY benign_solved_challenge  deadbeef" in text and "Score Board" in text


# ---- Stage 5.5: rule invention ---------------------------------------------------

def _src(row, source):
    return {**row, "verdict_source": source}


def _benign(bid, verdict, source, fp_reason=None):
    return {"benign_id": bid, "request_id": f"b{bid}", "category": "normal",
            "verdict": verdict, "verdict_source": source,
            "false_positive": None if fp_reason else verdict != "benign",
            "fp_reason": fp_reason}


def test_by_source_splits_rule_and_ai_paths():
    rounds = [_src(rr(1), "rule"), _src(rr(2, verdict="CWE-22", type_correct=False), "rule"),
              _src(rr(3, **BENIGN), "ai"), _src(rr(4, **NO_VERDICT), None),
              _src(rr(5, **ORPHAN), None)]
    benign = [_benign("n01", "CWE-89", "rule"), _benign("n02", "benign", "ai"),
              _benign("n03", None, None, fp_reason="instrument_failure")]
    s = ms.by_source(rounds, benign)
    assert "detection" not in s["rule"]  # 100% by construction: never computed
    assert s["rule"]["type_accuracy"].fmt() == "1/2 (50%)"
    assert s["rule"]["fp"].fmt() == "1/1 (100%)"
    assert (s["rule"]["attack_lines"], s["rule"]["benign_lines"]) == (2, 1)
    # the AI path keeps no_verdict as a miss and excludes the orphan
    assert s["ai"]["detection"].fmt() == "0/2 (0%)"
    assert s["ai"]["fp"].fmt() == "0/1 (0%)"
    assert (s["ai"]["attack_lines"], s["ai"]["benign_lines"]) == (2, 2)


def _rule(rid, cwe, seq):
    return {"schema_version": "0.1", "match_id": "m001", "hot_loaded": True,
            "rule": {"rule_id": rid, "cwe": cwe, "created_at_log_seq": seq,
                     "source_request_id": "x", "conditions": [
                         {"field": "query", "op": "contains", "pattern": "p",
                          "case_insensitive": True}]}}


def test_rules_summary_counts_proposals_codes_conflicts_and_saved_calls():
    rules = [_rule("r-001", "CWE-89", 1), _rule("r-002", "CWE-79", 2)]
    rejections = [{"rule_id": "r-003", "created_at_log_seq": 3, "label": "CWE-89",
                   "proposal": {}, "reasons": [{"code": "schema_error", "detail": "a"},
                                               {"code": "schema_error", "detail": "b"}]},
                  {"rule_id": "r-004", "created_at_log_seq": 4, "label": "CWE-89",
                   "proposal": {}, "reasons": [{"code": "rule_cap_reached", "detail": "c"}]}]
    rounds = [rr(5), rr(6)]
    benign = [_benign("n01", "CWE-89", "rule")]
    verdicts = [{"log_seq": 5, "request_id": rounds[0]["request_id"], "source": "rule",
                 "fired_rule_ids": ["r-001", "r-002"]},
                {"log_seq": 6, "request_id": rounds[1]["request_id"], "source": "rule",
                 "fired_rule_ids": ["r-001"]},
                {"log_seq": 7, "request_id": "bn01", "source": "rule",
                 "fired_rule_ids": ["r-001"]},
                {"log_seq": 8, "request_id": "z", "source": "ai", "fired_rule_ids": []}]
    results = [{"rule_id": "r-001", "replay_fires": True, "replay_reason": None,
                "source_label": "CWE-89", "cwe_matches_source": True, "fixture_fires": 2,
                "fixture_benign_ids": ["n01", "h06"]}]
    s = ms.rules_summary(rules, rejections, verdicts, results, rounds, benign)
    assert (s["proposed"], s["stored"], s["rejected"]) == (4, 2, 2)
    assert s["rejection_codes"] == {"schema_error": 1, "rule_cap_reached": 1}
    assert s["cap_hits"] == 1 and s["ai_calls_saved"] == 3 and s["conflicts"] == [5]
    r1, r2 = s["rules"]
    assert (r1["fired_attack_lines"], r1["fired_benign_lines"]) == (2, 1)
    assert (r1["replay_fires"], r1["fixture_fires"]) == (True, 2)
    assert (r2["fired_attack_lines"], r2["replay_fires"]) == (1, None)
    text = "\n".join(ms.format_rules(s, ms.by_source(rounds, benign), "on"))
    assert "proposed 4" in text and "r-003 REJECTED" in text and "query contains/i" in text
    rule_line = next(l for l in text.splitlines() if l.startswith("  rule path"))
    assert "detection" not in rule_line.split("(no detection rate")[0]


def test_summary_block_appears_only_when_rules_mode_is_not_off():
    m = {"match_id": "m001", "status": "completed", "judge_version": "0.6.0",
         "blue_engine": "claude", "git": {"commit": "f" * 40, "dirty": False},
         "blue_params": {"rules": {"mode": "off", "max_rules": 10}}}
    assert "rules mode" not in ms.format_summary([rr(1)], m)
    m["blue_params"]["rules"]["mode"] = "shadow"
    assert "rules mode shadow: proposed 0" in ms.format_summary([rr(1)], m)
