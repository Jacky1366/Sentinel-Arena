"""Unit tests for judge/fact1_landed.py. Pure logic, no Docker, no network.

Covers every branch of the landed rule (contract 6.1), the two-challenges-at-once
case, an unmapped challenge being solved (must NOT count), and orphan handling.
Also checks every emitted landed fact validates against the schema.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("fact1_landed", REPO / "judge" / "fact1_landed.py")
fact1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fact1)

CMAP = {
    "CWE-89": ["Login Admin", "User Credentials"],
    "CWE-79": [],
    "CWE-22": ["Poison Null Byte", "Forgotten Developer Backup"],
}
LANDED_SCHEMA = json.loads((REPO / "schemas" / "landed_fact.schema.json").read_text())
VALIDATOR = Draft202012Validator(LANDED_SCHEMA)
RID = "3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"


# ---- compute_landed: the four branches -----------------------------------

def test_landed_true_when_mapped_challenge_newly_solved():
    r = fact1.compute_landed("CWE-89", ["Login Admin"], ["Login Admin", "User Credentials"], CMAP)
    assert r == {"landed": True, "landed_reason": None, "newly_solved": ["User Credentials"]}


def test_landed_false_when_nothing_mapped_flips():
    r = fact1.compute_landed("CWE-89", [], [], CMAP)
    assert r["landed"] is False and r["landed_reason"] is None and r["newly_solved"] == []


def test_not_measurable_when_mapping_empty():
    # Even if some (unmapped) challenge flips, an empty mapping is not_measurable.
    r = fact1.compute_landed("CWE-79", [], ["Reflected XSS"], CMAP)
    assert r["landed"] is None and r["landed_reason"] == "not_measurable"
    assert r["newly_solved"] == ["Reflected XSS"]


def test_already_solved_when_all_mapped_solved_before():
    before = ["Poison Null Byte", "Forgotten Developer Backup"]
    r = fact1.compute_landed("CWE-22", before, before + ["Forgotten Sales Backup"], CMAP)
    assert r["landed"] is None and r["landed_reason"] == "already_solved"
    # Unmapped flip is still recorded as evidence.
    assert r["newly_solved"] == ["Forgotten Sales Backup"]


# ---- special cases -------------------------------------------------------

def test_two_mapped_challenges_at_once_counts_as_landed():
    r = fact1.compute_landed("CWE-22", [], ["Poison Null Byte", "Forgotten Developer Backup"], CMAP)
    assert r["landed"] is True
    assert r["newly_solved"] == ["Forgotten Developer Backup", "Poison Null Byte"]


def test_unmapped_solve_does_not_count_as_landed():
    # A CWE-89 round that only flips an unmapped challenge (e.g. Error Handling)
    # must be landed=false, not true.
    r = fact1.compute_landed("CWE-89", [], ["Error Handling"], CMAP)
    assert r["landed"] is False and r["landed_reason"] is None
    assert r["newly_solved"] == ["Error Handling"]


def test_partial_mapped_already_solved_still_lands_on_new_one():
    # One of two mapped challenges already solved; the other flips now -> landed.
    r = fact1.compute_landed("CWE-89", ["Login Admin"], ["Login Admin", "User Credentials"], CMAP)
    assert r["landed"] is True and r["newly_solved"] == ["User Credentials"]


# ---- judge_run over artifacts + orphans ----------------------------------

def _write_run(tmp_path, attacks, snapshots):
    (tmp_path / "red_attacks.jsonl").write_text(
        "".join(json.dumps(a) + "\n" for a in attacks), encoding="utf-8")
    (tmp_path / "challenge_snapshots.jsonl").write_text(
        "".join(json.dumps(s) + "\n" for s in snapshots), encoding="utf-8")


def _attack(request_id, label, rnd):
    return {"schema_version": "0.1", "match_id": "m001", "round": rnd,
            "request_id": request_id, "label": label, "payload": "x",
            "endpoint": "/x", "method": "GET", "timestamp": "2026-11-04T00:00:00Z"}


def test_judge_run_emits_schema_valid_facts(tmp_path):
    rid2 = RID.replace("3f2b", "4a5b")
    attacks = [_attack(RID, "CWE-89", 1), _attack(rid2, "CWE-22", 2)]
    snaps = [
        {"request_id": RID, "before_solved": [], "after_solved": ["Login Admin"],
         "taken_at": "2026-11-04T00:00:01Z"},
        {"request_id": rid2, "before_solved": [],
         "after_solved": ["Poison Null Byte", "Forgotten Developer Backup"],
         "taken_at": "2026-11-04T00:00:02Z"},
    ]
    _write_run(tmp_path, attacks, snaps)
    facts, orphans = fact1.judge_run(tmp_path, CMAP)
    assert orphans == []
    assert [f["landed"] for f in facts] == [True, True]
    for f in facts:
        VALIDATOR.validate(f)


def test_orphan_when_no_snapshot(tmp_path):
    rid2 = RID.replace("3f2b", "4a5b")
    attacks = [_attack(RID, "CWE-89", 1), _attack(rid2, "CWE-89", 2)]
    # Only the first attack has a snapshot; the second is an orphan.
    snaps = [{"request_id": RID, "before_solved": [], "after_solved": ["Login Admin"],
              "taken_at": "2026-11-04T00:00:01Z"}]
    _write_run(tmp_path, attacks, snaps)
    facts, orphans = fact1.judge_run(tmp_path, CMAP)
    assert [f["request_id"] for f in facts] == [RID]
    assert [o["request_id"] for o in orphans] == [rid2]


def test_main_writes_landed_jsonl(tmp_path, capsys):
    (REPO / "config" / "challenge_map.json")  # real map exists; use a temp one
    cmap = tmp_path / "cmap.json"
    cmap.write_text(json.dumps(CMAP), encoding="utf-8")
    _write_run(tmp_path, [_attack(RID, "CWE-79", 1)],
               [{"request_id": RID, "before_solved": [], "after_solved": [],
                 "taken_at": "2026-11-04T00:00:01Z"}])
    rc = fact1.main(["--run-dir", str(tmp_path), "--challenge-map", str(cmap)])
    assert rc == 0
    lines = (tmp_path / "landed.jsonl").read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["landed"] is None and rec["landed_reason"] == "not_measurable"
    VALIDATOR.validate(rec)


def test_benign_snapshot_rows_are_skipped_explicitly(tmp_path):
    # Stage 5.2: benign rows share the snapshot file; fact 1 ignores them, even a
    # benign row that solved something (that is fact 4a's anomaly, never a landing).
    benign_rid = RID.replace("3f2b", "9c9c")
    attacks = [_attack(RID, "CWE-89", 1)]
    snaps = [
        {"request_id": benign_rid, "traffic": "benign", "before_solved": [],
         "after_solved": ["Error Handling"], "taken_at": "2026-11-04T00:00:00Z"},
        {"request_id": RID, "traffic": "red", "before_solved": [],
         "after_solved": ["Login Admin"], "taken_at": "2026-11-04T00:00:01Z"},
    ]
    _write_run(tmp_path, attacks, snaps)
    facts, orphans = fact1.judge_run(tmp_path, CMAP)
    assert [f["request_id"] for f in facts] == [RID] and orphans == []
    assert facts[0]["newly_solved"] == ["Login Admin"]


def test_a_red_request_id_on_a_benign_row_is_not_used(tmp_path):
    # Defensive: a snapshot row is used by fact 1 only if it is marked red (or is a
    # pre-5.2 row with no traffic field).
    _write_run(tmp_path, [_attack(RID, "CWE-89", 1)],
               [{"request_id": RID, "traffic": "benign", "before_solved": [],
                 "after_solved": ["Login Admin"], "taken_at": "2026-11-04T00:00:01Z"}])
    facts, orphans = fact1.judge_run(tmp_path, CMAP)
    assert facts == [] and [o["request_id"] for o in orphans] == [RID]
