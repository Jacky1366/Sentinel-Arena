"""tools/export_compare.py (#15; D52, contract 6.18). Synthetic folders only (a dev match and
a replay of it with different verdicts); the committed bundle is checked as a derived file,
never re-exported from the test-set folders here (CLAUDE.md test-set rule 3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_fakes import REPO
from stats import free_play, test_data
from tools import export_compare as ec

MID = "20261124T110000Z-c001"


@pytest.fixture
def registry(tmp_path):
    p = tmp_path / "test_set.json"
    p.write_text(json.dumps({"match_ids": [], "test_purposes": ["eval"], "sealed": []}))
    return test_data.load_registry(p)


def jl(p: Path, rows):
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))


SPEC = [  # round, label, technique, attempt, solved, detected original, detected other arm
    (1, "other", "recon", "no", [], False, False),
    (2, "CWE-89", "SQL injection", "yes", ["Login Admin"], True, True),
    (3, "other", "sensitive file", "yes", ["Confidential Document"], False, True),
    (4, "other", "enumeration", "yes", [], False, False),
]


def make(root: Path, purpose="dev"):
    match = root / "match"
    match.mkdir(parents=True)
    (match / "match.json").write_text(json.dumps({
        "match_id": MID, "purpose": purpose,
        "models": {"red": {"model": "deepseek-v4-pro"}, "blue": {"model": "claude-haiku-5-5"}}}))
    jl(match / "red_attacks.jsonl", [
        {"round": r, "request_id": f"rid-{r}", "label": lab, "technique": t, "method": "GET",
         "endpoint": f"/p{r}", "payload": f"/p{r}?q=x", "headers": {"Cookie": "SECRET"} if r == 3 else {}}
        for r, lab, t, *_ in SPEC])
    (match / "challenge_catalog.json").write_text(json.dumps(
        {"Login Admin": "Injection", "Confidential Document": "Sensitive Data Exposure"}))
    audits = root / "audits"
    audits.mkdir()
    jl(audits / f"{MID}.freeplay.jsonl", [{"round": r, "attack_attempt": a} for r, _, _, a, *_ in SPEC])

    def rounds(i):
        return [{"round": r, "request_id": f"rid-{r}", "label": lab, "newly_solved": s,
                 "detected": d[i], "verdict": ("other" if lab == "other" else lab) if d[i] else "benign",
                 "verdict_source": "ai", "detected_reason": None, "type_correct": None}
                for r, lab, _, _, s, *d in SPEC]
    jl(match / "rounds.jsonl", rounds(0))
    jl(match / "benign_results.jsonl", [
        {"request_id": f"b{i}", "category": "normal", "false_positive": False, "fp_reason": None,
         "verdict": "benign"} for i in range(3)])
    rep = root / "replay"
    rep.mkdir()
    (rep / "replay.json").write_text(json.dumps({"replay_id": "r1", "source": {"match_id": MID}}))
    for name in ("red_attacks.jsonl", "challenge_catalog.json"):
        (rep / name).write_bytes((match / name).read_bytes())
    jl(rep / "rounds.jsonl", rounds(1))
    jl(rep / "benign_results.jsonl", [
        {"request_id": f"b{i}", "category": "normal", "false_positive": i == 0, "fp_reason": None,
         "verdict": "other" if i == 0 else "benign"} for i in range(3)])
    return match, rep, audits


def arms(match, rep):
    return [{"id": "original", "label": "Original", "blue": "original", "folders": [match]},
            {"id": "open", "label": "Open", "blue": "open", "folders": [rep]}]


def test_rows_join_by_request_id_and_flag_divergence(tmp_path):
    match, rep, audits = make(tmp_path)
    doc = ec.build("t", "T", arms(match, rep), audits)
    assert [r["round"] for r in doc["rows"]] == [1, 2, 3, 4]
    r3 = doc["rows"][2]
    assert r3["divergent"] and r3["landed"] and r3["attack_attempt"] == "yes"
    assert r3["verdicts"]["original"]["detected"] is False and r3["verdicts"]["open"]["verdict"] == "other"
    assert r3["headers_set"] == ["Cookie"] and "SECRET" not in json.dumps(doc)  # names only
    assert [r["round"] for r in doc["rows"] if r["divergent"]] == [3]


def test_aggregates_equal_free_play_summary_and_fp_rate(tmp_path):
    match, rep, audits = make(tmp_path)
    doc = ec.build("t", "T", arms(match, rep), audits)
    ap = audits / f"{MID}.freeplay.jsonl"
    for aid, d in (("original", match), ("open", rep)):
        s = free_play.summary(d, ap)["detection"]
        assert (doc["aggregate"][aid]["detected"], doc["aggregate"][aid]["attempts"]) == (s["num"], s["den"])
    assert doc["aggregate"]["original"]["detected"] == 1 and doc["aggregate"]["open"]["detected"] == 2
    assert doc["aggregate"]["open"]["landed_detected"] == 2 and doc["aggregate"]["original"]["landed_detected"] == 1
    assert (doc["aggregate"]["open"]["benign_fp"], doc["aggregate"]["open"]["benign"]) == (1, 3)


def test_arms_must_be_the_same_traffic(tmp_path):
    match, rep, audits = make(tmp_path)
    (rep / "replay.json").write_text(json.dumps({"replay_id": "r1", "source": {"match_id": "other"}}))
    with pytest.raises(ValueError, match="same traffic"):
        ec.build("t", "T", arms(match, rep), audits)
    with pytest.raises(ValueError, match="two arms"):
        ec.build("t", "T", arms(match, rep)[:1], audits)


def test_gate_refuses_test_data_without_go(tmp_path, registry):
    match, rep, _ = make(tmp_path, purpose="eval")
    assert "REFUSED" in ec.gate([match, rep], env={}, registry=registry)
    assert ec.gate([match, rep], env={"ARENA_GO": "manual-freeplay-export"}, registry=registry) is None
    dev, drep, _ = make(tmp_path / "dev")
    assert ec.gate([dev], env={}, registry=registry) is None


def test_export_writes_bundle_and_compare_js_never_into_a_source(tmp_path):
    match, rep, audits = make(tmp_path)
    doc = ec.build("free.t", "T", arms(match, rep), audits)
    out = tmp_path / "out"
    p = ec.export(doc, [match, rep], out)
    js = (out / "compare.js").read_text()
    assert p.name == "free.t.json" and 'window.ARENA_COMPARE["free.t"]' in js
    with pytest.raises(ValueError, match="source folder"):
        ec.export(doc, [match, rep], match / "x")
    assert not (match / "x").exists()


def test_committed_compare_bundles_are_valid_and_match_the_committed_stats():
    out = REPO / "dashboard" / "public" / "compare"
    docs = {p.stem: json.loads(p.read_text()) for p in out.glob("*.json")}
    assert "freeplay" in docs
    for doc in docs.values():
        assert not [e.message for e in ec.SCHEMA.iter_errors(doc)]
    agg = docs["freeplay"]["aggregate"]
    assert (agg["original"]["detected"], agg["original"]["attempts"]) == (12, 19)  # progress.md
    assert (agg["open"]["detected"], agg["open"]["attempts"]) == (14, 19)
    assert docs["freeplay"]["fp_check"] is None  # the 2c holdout panel needs its own GO
    js = (out / "compare.js").read_text()
    for name in docs:
        assert f'window.ARENA_COMPARE["{name}"]' in js
