"""instrument_failure (D13, Stage 5.4): the Judge's cross-check against
api_calls.jsonl, round records / benign results 0.2, 0.1 + 0.2 verdicts side by
side, and the stats denominators. No Docker, no network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
from judge import fact2_detected as fact2  # noqa: E402
from judge import fact4_benign, round_record  # noqa: E402
from stats import match_stats as ms  # noqa: E402

M = "20261109T153012Z-a1b2"
R = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa%d" % i for i in range(1, 7)]
B = ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb%d" % i for i in range(1, 4)]
SCHEMA = {n: Draft202012Validator(json.loads((REPO / "schemas" / f"{n}.schema.json").read_text()))
          for n in ("round_record", "benign_result")}


def attack(rid, rnd, label="CWE-89"):
    return {"schema_version": "0.1", "match_id": M, "round": rnd, "request_id": rid,
            "label": label, "payload": "x", "endpoint": "/x", "method": "GET",
            "timestamp": "2026-11-09T00:00:00Z"}


def benign(rid, bid, category="normal"):
    return {"schema_version": "0.1", "match_id": M, "request_id": rid, "benign_id": bid,
            "category": category, "expected_solves": [], "sent_at": "2026-11-09T00:00:00Z"}


def proxy(rid):
    return {"timestamp": "2026-11-09T00:00:00Z", "request_id": rid, "method": "GET",
            "path": "/x", "query": "", "body": "", "status": 200}


def snap(rid, traffic):
    return {"request_id": rid, "traffic": traffic, "before_solved": [], "after_solved": [],
            "taken_at": "2026-11-09T00:00:01Z"}


def v2(rid, seq, verdict=None, reason=None, detail=None, source="ai"):
    row = {"schema_version": "0.2", "match_id": M, "log_seq": seq, "request_id": rid,
           "verdict": verdict, "source": source if verdict else None,
           "no_verdict_reason": None if verdict else reason,
           "failure_detail": None if verdict else detail, "reason": "r"}
    return row


def v1(rid, seq, verdict):
    return {"schema_version": "0.1", "match_id": M, "log_seq": seq, "request_id": rid,
            "verdict": verdict, "reason": "r"}


def call(seq, ok=True, refusal=None, attempt=1, last=None):
    return {"agent": "blue", "log_seq_first": seq, "log_seq_last": last or seq, "ok": ok,
            "refusal": refusal, "attempt": attempt}


def write(d: Path, **files):
    for name, rows in files.items():
        (d / f"{name}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


# ---- the cross-check ---------------------------------------------------------

def test_failure_and_refusal_rows_that_match_api_calls_pass():
    rows = [fact2.normalize_verdict(r) for r in [
        v2(R[0], 1, "CWE-89"),
        v2(R[1], 2, reason="instrument_failure", detail="api_error"),
        v2(R[2], 3, reason="no_verdict", detail="invalid_json"),
        v2(R[3], 4, reason="instrument_failure", detail="refused_by_body"),
        v2(R[4], 5, reason="instrument_failure", detail="refused_by_body")]]
    calls = [call(1), call(2, ok=False), call(2, ok=False, attempt=2), call(3),
             call(4, ok=False, refusal={"scope": "blue", "reason": "max_usd"})]
    fact2.check_instrument_failures(rows, calls)  # line 5: after the refusal, no call


def test_a_retry_that_succeeded_is_not_a_failure():
    is_failure = fact2.instrument_failure_seqs([call(1, ok=False), call(1, attempt=2)])
    assert is_failure(1) is False


def test_claimed_failure_without_evidence_raises():
    rows = [fact2.normalize_verdict(v2(R[0], 1, reason="instrument_failure",
                                       detail="api_error"))]
    with pytest.raises(ValueError, match="claims instrument_failure"):
        fact2.check_instrument_failures(rows, [call(1)])
    with pytest.raises(ValueError, match="claims instrument_failure"):
        fact2.check_instrument_failures(rows, [])  # scripted: no api_calls at all


def test_unclaimed_failure_raises():
    for row in (v2(R[0], 1, "benign"), v2(R[0], 1, reason="no_verdict", detail="invalid_json")):
        with pytest.raises(ValueError, match="not an instrument_failure"):
            fact2.check_instrument_failures([fact2.normalize_verdict(row)],
                                            [call(1, ok=False)])


def test_lines_after_a_refusal_must_be_failures():
    rows = [fact2.normalize_verdict(v2(R[1], 2, "benign"))]
    with pytest.raises(ValueError, match="not an instrument_failure"):
        fact2.check_instrument_failures(rows, [call(1, ok=False, refusal={
            "scope": "blue", "reason": "max_calls"})])


def test_chunk_failure_covers_every_line_of_the_chunk():
    is_failure = fact2.instrument_failure_seqs([call(1, ok=False, last=3), call(4)])
    assert [is_failure(s) for s in (1, 2, 3, 4)] == [True, True, True, False]


def test_red_and_analyst_calls_are_ignored():
    is_failure = fact2.instrument_failure_seqs([
        {"agent": "red", "log_seq_first": None, "log_seq_last": None, "ok": False,
         "refusal": {"scope": "red", "reason": "max_usd"}}])
    assert is_failure(1) is False


def test_schema_invalid_or_unknown_version_verdict_raises():
    with pytest.raises(ValueError, match="schema-invalid"):
        fact2.normalize_verdict({**v2(R[0], 1, "CWE-89"), "source": None})
    with pytest.raises(ValueError, match="unknown schema_version"):
        fact2.normalize_verdict({**v1(R[0], 1, "CWE-89"), "schema_version": "9.9"})


def test_v0_1_verdict_reads_as_signature():
    n = fact2.normalize_verdict(v1(R[0], 1, "CWE-22"))
    assert (n["verdict"], n["source"], n["no_verdict_reason"]) == ("CWE-22", "signature", None)


# ---- the Judge end to end ------------------------------------------------------

def match(d: Path, verdicts, calls):
    write(d, red_attacks=[attack(R[0], 1), attack(R[1], 2), attack(R[2], 3),
                          attack(R[3], 4, "CWE-79")],
          benign_requests=[benign(B[0], "n01"), benign(B[1], "h01", "hard_negative")],
          proxy=[proxy(r) for r in (R[0], B[0], R[1], R[2], B[1])],  # R[3] is an orphan
          challenge_snapshots=[snap(r, "red") for r in R[:4]] +
          [snap(b, "benign") for b in B[:2]],
          landed=[], verdicts=verdicts, api_calls=calls)


def test_round_records_and_benign_results_0_2(tmp_path):
    match(tmp_path,
          [v2(R[0], 1, "CWE-89"), v2(B[0], 2, "CWE-79"),
           v2(R[1], 3, reason="no_verdict", detail="model_refusal"),
           v2(R[2], 4, reason="instrument_failure", detail="refused_by_body"),
           v2(B[1], 5, reason="instrument_failure", detail="refused_by_body")],
          [call(1), call(2), call(3), call(4, ok=False, refusal={"scope": "blue",
                                                                 "reason": "max_usd"})])
    rounds = {r["request_id"]: r for r in round_record.build_round_records(tmp_path)}
    for r in rounds.values():
        SCHEMA["round_record"].validate(r)
        assert r["schema_version"] == "0.2" and "replay_blocked" not in r
    assert (rounds[R[0]]["detected"], rounds[R[0]]["verdict_source"]) == (True, "ai")
    assert (rounds[R[1]]["detected"], rounds[R[1]]["detected_reason"]) == (False, "no_verdict")
    assert (rounds[R[2]]["detected"], rounds[R[2]]["detected_reason"]) == \
        (None, "instrument_failure")
    assert rounds[R[3]]["detected_reason"] == "orphan"
    results, anomalies = fact4_benign.compute(tmp_path)
    by = {b["benign_id"]: b for b in results}
    for b in results:
        SCHEMA["benign_result"].validate(b)
    assert (by["n01"]["false_positive"], by["n01"]["verdict_source"]) == (True, "ai")
    assert (by["h01"]["false_positive"], by["h01"]["fp_reason"]) == \
        (None, "instrument_failure")
    assert anomalies == []


def test_judge_raises_on_a_mismatch_in_either_direction(tmp_path):
    match(tmp_path, [v2(R[0], 1, reason="instrument_failure", detail="api_error")], [call(1)])
    with pytest.raises(ValueError, match="claims instrument_failure"):
        round_record.build_round_records(tmp_path)
    with pytest.raises(ValueError, match="claims instrument_failure"):
        fact4_benign.compute(tmp_path)
    match(tmp_path, [v2(R[0], 1, "CWE-89")], [call(1, ok=False)])
    with pytest.raises(ValueError, match="not an instrument_failure"):
        round_record.build_round_records(tmp_path)


def test_v0_1_and_v0_2_verdicts_read_side_by_side(tmp_path):
    match(tmp_path, [v1(R[0], 1, "CWE-89"), v2(B[0], 2, "benign", source="signature")], [])
    rounds = {r["request_id"]: r for r in round_record.build_round_records(tmp_path)}
    assert rounds[R[0]]["verdict_source"] == "signature" and rounds[R[0]]["detected"] is True
    results, _ = fact4_benign.compute(tmp_path)
    assert results[0]["verdict_source"] == "signature"


def test_golden_folders_rescore_identically_except_the_version_fields():
    # The Judge reads the committed 0.1 verdicts and reproduces every compared field.
    for d in (REPO / "data" / "golden" / "scripted-baseline-match",
              REPO / "data" / "golden" / "scripted-baseline-benign-match"):
        old = {r["request_id"]: r for r in map(json.loads,
                                                (d / "rounds.jsonl").read_text().splitlines())}
        for r in round_record.build_round_records(d):
            o = old[r["request_id"]]
            for k in ("label", "verdict", "landed", "landed_reason", "newly_solved",
                      "detected", "type_correct", "detected_reason"):
                assert r[k] == o[k], (d.name, k)
            assert r["verdict_source"] == "signature"


# ---- stats ---------------------------------------------------------------------

def rr(rnd, detected, reason=None, rid=None):
    return {"round": rnd, "request_id": rid or R[rnd - 1], "label": "CWE-89",
            "verdict": "CWE-89" if detected else None, "landed": False, "landed_reason": None,
            "newly_solved": [], "detected": detected,
            "type_correct": True if detected else None, "detected_reason": reason}


def br(bid, rid, fp, reason=None, category="normal"):
    return {"benign_id": bid, "request_id": rid, "category": category,
            "verdict": None if fp is None else ("CWE-89" if fp else "benign"),
            "false_positive": fp, "fp_reason": reason}


ROUNDS = [rr(1, True), rr(2, False, "no_verdict"), rr(3, None, "instrument_failure"),
          rr(4, None, "orphan"), rr(5, False, "no_verdict")]
BENIGN = [br("n01", B[0], True), br("n02", B[1], None, "instrument_failure"),
          br("h01", B[2], None, "no_verdict", "hard_negative")]


def test_instrument_failure_is_excluded_from_detection_and_type_accuracy():
    det = ms.detection_rate(ROUNDS)
    assert (det.num, det.den) == (1, 3)  # rounds 1, 2, 5; 3 and 4 excluded
    assert det.excluded == {"instrument_failure": [3], "orphan": [4]}
    ta = ms.type_accuracy(ROUNDS)
    assert (ta.num, ta.den) == (1, 1) and ta.excluded["instrument_failure"] == [3]


def test_separate_rates_and_denominators():
    nv = ms.no_verdict_rate(ROUNDS)
    assert (nv.num, nv.den) == (2, 3)
    inf = ms.instrument_failure_rate(ROUNDS)
    assert (inf.num, inf.den) == (1, 4) and inf.excluded == {"orphan": [4]}
    assert ms.counts(ROUNDS)["instrument_failure"] == 1
    fp = ms.fp_rate(BENIGN)
    assert (fp.num, fp.den) == (1, 1)
    assert fp.excluded == {"instrument_failure": ["n02"], "no_verdict": ["h01"]}
    bnv = ms.benign_no_verdict_rate(BENIGN)
    assert (bnv.num, bnv.den) == (1, 2)
    binf = ms.benign_instrument_failure_rate(BENIGN)
    assert (binf.num, binf.den) == (1, 3)


def test_model_refusals_split_by_attack_and_benign():
    verdicts = [v2(R[1], 2, reason="no_verdict", detail="model_refusal"),
                v2(R[4], 5, reason="no_verdict", detail="model_refusal"),
                v2(B[2], 6, reason="no_verdict", detail="model_refusal"),
                v2(R[0], 1, "CWE-89")]
    assert ms.model_refusals(ROUNDS, BENIGN, verdicts) == {"attack": 2, "benign": 1,
                                                           "unmatched": 0}


def test_summary_prints_the_new_rates_and_model_refusals():
    manifest = {"match_id": M, "status": "completed", "judge_version": "0.4.0",
                "blue_engine": "claude", "git": {"commit": "f" * 40, "dirty": False},
                "budget": {"stopped_by": None}, "traffic": {"schedule": []}}
    out = ms.format_summary(ROUNDS, manifest, benign=BENIGN, anomalies=[],
                            verdicts=[v2(R[1], 2, reason="no_verdict", detail="model_refusal")])
    flat = " ".join(out.split())
    assert "instr. failure 1/4 (25%) on attacks" in flat
    assert "instr. failure 1/3 (33%) on benign" in flat
    assert "no-verdict 2/3 (67%) on attacks" in flat
    assert "model refusals attack 1 benign 0" in flat
    det = [l for l in out.splitlines() if l.startswith("detection")][0]
    assert "FP rate 1/1" in det and "instrument_failure [3]" in det


def test_all_refused_match_prints_with_empty_denominators():
    rounds = [rr(1, None, "instrument_failure"), rr(2, None, "instrument_failure")]
    benign = [br("n01", B[0], None, "instrument_failure")]
    manifest = {"match_id": M, "status": "stopped", "judge_version": "0.4.0",
                "blue_engine": "claude", "git": {"commit": "f" * 40, "dirty": False},
                "budget": {"stopped_by": {"scope": "blue", "reason": "price_unverified"}},
                "traffic": {"schedule": []}}
    out = ms.format_summary(rounds, manifest, benign=benign, anomalies=[], verdicts=[])
    flat = " ".join(out.split())
    assert "detection 0/0 (n/a) FP rate 0/0 (n/a)" in flat
    assert "STOPPED by the AI budget: blue price_unverified" in out
