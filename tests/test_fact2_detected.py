"""Unit tests for Judge fact 2 (detected) and the round-record join. No Docker."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fact2 = _load("fact2_detected", "judge/fact2_detected.py")
# round_record imports `from judge import fact2_detected`; ensure the package path works.
import sys  # noqa: E402
sys.path.insert(0, str(REPO))
round_record = _load("round_record", "judge/round_record.py")

ROUND_SCHEMA = json.loads((REPO / "schemas" / "round_record.schema.json").read_text())
VALIDATOR = Draft202012Validator(ROUND_SCHEMA)

R1 = "3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"
R2 = "4a5b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"
R3 = "5b6c8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"


# ---- pure branch logic (detected_fields) ---------------------------------

def test_detected_true_type_correct():
    assert fact2.detected_fields("CWE-89", True, "CWE-89") == {
        "verdict": "CWE-89", "detected": True, "type_correct": True, "detected_reason": None}


def test_detected_true_wrong_type():
    assert fact2.detected_fields("CWE-89", True, "CWE-22") == {
        "verdict": "CWE-22", "detected": True, "type_correct": False, "detected_reason": None}


def test_detected_false_benign_verdict():
    assert fact2.detected_fields("CWE-89", True, "benign") == {
        "verdict": "benign", "detected": False, "type_correct": None, "detected_reason": None}


def test_no_verdict():
    assert fact2.detected_fields("CWE-89", True, None) == {
        "verdict": None, "detected": False, "type_correct": None, "detected_reason": "no_verdict"}


def test_orphan_no_proxy_line():
    assert fact2.detected_fields("CWE-89", False, None) == {
        "verdict": None, "detected": None, "type_correct": None, "detected_reason": "orphan"}


# ---- compute_fact2 over artifacts ----------------------------------------

def _attack(rid, label, rnd):
    return {"schema_version": "0.1", "match_id": "m001", "round": rnd, "request_id": rid,
            "label": label, "payload": "x", "endpoint": "/x", "method": "GET",
            "timestamp": "2026-11-05T00:00:00Z"}


def _proxy(rid):
    return {"timestamp": "2026-11-05T00:00:00Z", "request_id": rid, "method": "GET",
            "path": "/x", "query": "", "body": "", "status": 200}


def _verdict(rid, verdict, log_seq):
    return {"schema_version": "0.1", "match_id": "m001", "log_seq": log_seq,
            "request_id": rid, "verdict": verdict, "reason": "r"}


def _write(run, attacks=(), proxy=(), verdicts=(), landed=()):
    for name, rows in [("red_attacks", attacks), ("proxy", proxy),
                       ("verdicts", verdicts), ("landed", landed)]:
        (run / f"{name}.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_compute_fact2_mixed(tmp_path):
    _write(tmp_path,
           attacks=[_attack(R1, "CWE-89", 1), _attack(R2, "CWE-22", 2), _attack(R3, "CWE-79", 3)],
           proxy=[_proxy(R1), _proxy(R2)],          # R3 has no proxy line -> orphan
           verdicts=[_verdict(R1, "CWE-89", 1)])     # R2 logged but no verdict
    out = fact2.compute_fact2(tmp_path)
    assert out[R1]["detected"] is True and out[R1]["type_correct"] is True
    assert out[R2]["detected"] is False and out[R2]["detected_reason"] == "no_verdict"
    assert out[R3]["detected"] is None and out[R3]["detected_reason"] == "orphan"


def test_verdict_with_unknown_request_id_is_ignored(tmp_path):
    unknown = "6c7d8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"
    _write(tmp_path, attacks=[_attack(R1, "CWE-89", 1)], proxy=[_proxy(R1)],
           verdicts=[_verdict(R1, "CWE-89", 1), _verdict(unknown, "CWE-22", 2)])
    out = fact2.compute_fact2(tmp_path)
    assert set(out) == {R1}  # the unknown verdict contributes nothing


def test_duplicate_verdicts_raise(tmp_path):
    _write(tmp_path, attacks=[_attack(R1, "CWE-89", 1)], proxy=[_proxy(R1)],
           verdicts=[_verdict(R1, "CWE-89", 1), _verdict(R1, "CWE-22", 2)])
    with pytest.raises(ValueError, match="duplicate verdict"):
        fact2.compute_fact2(tmp_path)


# ---- round-record join ---------------------------------------------------

def _landed(rid, label, landed, reason, newly):
    return {"schema_version": "0.1", "match_id": "m001", "round": 1, "request_id": rid,
            "label": label, "landed": landed, "landed_reason": reason, "newly_solved": newly}


def test_round_record_join_valid_and_complete(tmp_path):
    _write(tmp_path,
           attacks=[_attack(R1, "CWE-89", 1), _attack(R2, "CWE-22", 2)],
           proxy=[_proxy(R1), _proxy(R2)],
           verdicts=[_verdict(R1, "CWE-89", 1), _verdict(R2, "CWE-89", 2)],
           landed=[_landed(R1, "CWE-89", True, None, ["Login Admin"]),
                   _landed(R2, "CWE-22", True, None, ["Poison Null Byte"])])
    rounds = round_record.build_round_records(tmp_path)
    assert len(rounds) == 2
    for r in rounds:
        VALIDATOR.validate(r)
    # R2: verdict CWE-89 but label CWE-22 -> detected true, type_correct false.
    r2 = next(r for r in rounds if r["request_id"] == R2)
    assert r2["detected"] is True and r2["type_correct"] is False


def test_round_record_orphan_shape(tmp_path):
    # R1 has a landed fact (snapshot taken) but no proxy line -> orphan in the join.
    _write(tmp_path, attacks=[_attack(R1, "CWE-89", 1)], proxy=[],
           verdicts=[], landed=[_landed(R1, "CWE-89", False, None, [])])
    rounds = round_record.build_round_records(tmp_path)
    r = rounds[0]
    VALIDATOR.validate(r)
    assert r["detected"] is None and r["detected_reason"] == "orphan"
    assert r["verdict"] is None and r["type_correct"] is None
    assert r["landed"] is False  # kept for audit; stats layer excludes orphans


def test_round_record_missing_landed_fact_raises(tmp_path):
    _write(tmp_path, attacks=[_attack(R1, "CWE-89", 1)], proxy=[_proxy(R1)],
           verdicts=[_verdict(R1, "CWE-89", 1)], landed=[])
    with pytest.raises(ValueError, match="no landed fact"):
        round_record.build_round_records(tmp_path)


def test_round_record_duplicate_verdict_raises(tmp_path):
    _write(tmp_path, attacks=[_attack(R1, "CWE-89", 1)], proxy=[_proxy(R1)],
           verdicts=[_verdict(R1, "CWE-89", 1), _verdict(R1, "benign", 2)],
           landed=[_landed(R1, "CWE-89", True, None, ["Login Admin"])])
    with pytest.raises(ValueError, match="duplicate verdict"):
        round_record.build_round_records(tmp_path)
