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
                                "snapshot_missing": 1, "not_measurable": 1,
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
