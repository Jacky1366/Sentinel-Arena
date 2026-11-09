"""Judge fact 4a: verdict-level false positives on benign traffic, plus the
benign_solved_challenge / unmatched_verdict anomalies. Pure, no Docker."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from judge import fact4_benign  # noqa: E402

M = "20261109T153012Z-a1b2"
RED = "11111111-1111-4111-8111-111111111111"
B1 = "22222222-2222-4222-8222-222222222222"
B2 = "33333333-3333-4333-8333-333333333333"
B3 = "44444444-4444-4444-8444-444444444444"
B4 = "55555555-5555-4555-8555-555555555555"
STRANGER = "66666666-6666-4666-8666-666666666666"


def _jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def benign(rid, bid, cat="normal", expected=()):
    return {"schema_version": "0.1", "match_id": M, "request_id": rid, "benign_id": bid,
            "category": cat, "expected_solves": sorted(expected),
            "sent_at": "2026-11-09T00:00:00Z"}


def proxy(rid):
    return {"timestamp": "2026-11-09T00:00:00Z", "request_id": rid, "method": "GET",
            "path": "/", "query": "", "body": "", "status": 200}


def verdict(rid, label, seq):
    return {"schema_version": "0.1", "match_id": M, "log_seq": seq, "request_id": rid,
            "verdict": label, "reason": "x"}


def snap(rid, before=(), after=(), traffic="benign"):
    return {"request_id": rid, "traffic": traffic, "before_solved": list(before),
            "after_solved": list(after), "taken_at": "2026-11-09T00:00:01Z"}


def write(d: Path, benigns, proxies, verdicts, snaps, red=()):
    _jsonl(d / "benign_requests.jsonl", benigns)
    _jsonl(d / "proxy.jsonl", proxies)
    _jsonl(d / "verdicts.jsonl", verdicts)
    _jsonl(d / "challenge_snapshots.jsonl", snaps)
    _jsonl(d / "red_attacks.jsonl", [
        {"schema_version": "0.1", "match_id": M, "round": i, "request_id": rid,
         "label": "CWE-89", "payload": "x", "endpoint": "/", "method": "GET",
         "timestamp": "2026-11-09T00:00:00Z"} for i, rid in enumerate(red, start=1)])


# ---- the four result shapes ---------------------------------------------------

def test_attack_verdict_is_fp_benign_is_not_no_verdict_and_orphan_excluded(tmp_path):
    write(tmp_path,
          [benign(B1, "n01"), benign(B2, "h01", "hard_negative"), benign(B3, "n02"),
           benign(B4, "n03")],
          [proxy(B1), proxy(B2), proxy(B3)],  # B4 never logged -> orphan
          [verdict(B1, "CWE-89", 1), verdict(B2, "benign", 2)],  # B3 logged, no verdict
          [snap(B1), snap(B2), snap(B3), snap(B4)])
    results, anomalies = fact4_benign.compute(tmp_path)
    got = {r["benign_id"]: (r["verdict"], r["false_positive"], r["fp_reason"]) for r in results}
    assert got == {"n01": ("CWE-89", True, None), "h01": ("benign", False, None),
                   "n02": (None, None, "no_verdict"), "n03": (None, None, "orphan")}
    assert anomalies == []
    assert [r["category"] for r in results] == ["normal", "hard_negative", "normal", "normal"]


def test_one_result_per_benign_record_in_order(tmp_path):
    bs = [benign(B1, "n01"), benign(B2, "n02")]
    write(tmp_path, bs, [proxy(B1), proxy(B2)], [], [snap(B1), snap(B2)])
    results, _ = fact4_benign.compute(tmp_path)
    assert [r["request_id"] for r in results] == [B1, B2]


# ---- anomalies --------------------------------------------------------------------

def test_expected_solve_exactly_matching_is_not_an_anomaly(tmp_path):
    write(tmp_path, [benign(B1, "h06", "hard_negative", ["Error Handling"])], [proxy(B1)],
          [verdict(B1, "benign", 1)], [snap(B1, ["Login Admin"], ["Error Handling", "Login Admin"])])
    _, anomalies = fact4_benign.compute(tmp_path)
    assert anomalies == []


@pytest.mark.parametrize("expected,after", [
    ((), ["Score Board"]),                                 # solved something unexpected
    (["Error Handling"], []),                              # expected solve did not happen
    (["Error Handling"], ["Error Handling", "Score Board"]),  # superset
])
def test_any_difference_from_expected_solves_trips(tmp_path, expected, after):
    write(tmp_path, [benign(B1, "h06", "hard_negative", expected)], [proxy(B1)],
          [verdict(B1, "benign", 1)], [snap(B1, [], after)])
    results, [a] = fact4_benign.compute(tmp_path)
    assert a["kind"] == "benign_solved_challenge" and a["request_id"] == B1
    assert a["detail"] == {"benign_id": "h06", "newly_solved": sorted(after),
                           "expected_solves": sorted(expected)}
    assert results[0]["false_positive"] is False  # still scored


def test_missing_benign_snapshot_is_an_anomaly_not_a_crash(tmp_path):
    write(tmp_path, [benign(B1, "n01")], [proxy(B1)], [verdict(B1, "CWE-22", 1)],
          [snap(B1, traffic="red")])  # a red-marked row never counts for benign
    results, [a] = fact4_benign.compute(tmp_path)
    assert a["kind"] == "benign_snapshot_missing" and a["detail"] == {"benign_id": "n01"}
    assert results[0]["false_positive"] is True


def test_verdict_matching_neither_red_nor_benign_is_an_anomaly(tmp_path):
    write(tmp_path, [benign(B1, "n01")], [proxy(B1), proxy(RED), proxy(STRANGER)],
          [verdict(RED, "CWE-89", 1), verdict(B1, "benign", 2),
           verdict(STRANGER, "CWE-79", 3)],
          [snap(B1), snap(RED, traffic="red")], red=[RED])
    results, [a] = fact4_benign.compute(tmp_path)
    assert a == {"schema_version": "0.1", "match_id": M, "kind": "unmatched_verdict",
                 "request_id": STRANGER, "detail": {"log_seq": 3, "verdict": "CWE-79"}}
    assert [r["request_id"] for r in results] == [B1]  # Red's verdict is not benign scoring


def test_duplicate_verdict_raises(tmp_path):
    write(tmp_path, [benign(B1, "n01")], [proxy(B1)],
          [verdict(B1, "benign", 1), verdict(B1, "CWE-89", 2)], [snap(B1)])
    with pytest.raises(ValueError, match="duplicate verdict"):
        fact4_benign.compute(tmp_path)


def test_no_benign_traffic_gives_empty_outputs(tmp_path):
    write(tmp_path, [], [proxy(RED)], [verdict(RED, "CWE-89", 1)], [], red=[RED])
    assert fact4_benign.compute(tmp_path) == ([], [])


def test_main_writes_both_files_even_when_empty(tmp_path):
    write(tmp_path, [benign(B1, "n01")], [proxy(B1)], [verdict(B1, "benign", 1)], [snap(B1)])
    assert fact4_benign.main(["--run-dir", str(tmp_path)]) == 0
    assert len((tmp_path / "benign_results.jsonl").read_text().splitlines()) == 1
    assert (tmp_path / "anomalies.jsonl").read_text() == ""


def test_pure_no_network(tmp_path, monkeypatch):
    import socket

    def refuse(*a, **k):
        raise AssertionError("fact 4a opened a socket")
    monkeypatch.setattr(socket, "socket", refuse)
    write(tmp_path, [benign(B1, "n01")], [proxy(B1)], [verdict(B1, "CWE-89", 1)], [snap(B1)])
    fact4_benign.compute(tmp_path)
