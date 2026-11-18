"""tools/stage6_1_check.py offline (Stage 6.1): the refusals (no --real-calls, unsealed
offline files, missing --library), the zero-token prediction, and Gates 1 and 2 driven
end to end on FakeOps + the fake provider (no network, no Docker, no money)."""

from __future__ import annotations

import json

import pytest

from llm_fakes import REPO
from test_blue_rules import cond, verdict
from test_promote_rules import TrainOps
from test_rule_library import make_library, rule
from test_run_match_ai_vs_ai import RED_REPLY, ai_config
from test_run_match_rules import RulesOps, dirs  # noqa: F401 (fixture)
from llm_fakes import PRICES, FakeAdapter, lc
from rules import library as rule_library  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from tools import stage6_1_check as gate  # noqa: E402


def run(argv, capsys):
    code = gate.main(argv)
    return code, capsys.readouterr().out


def test_gate1_refuses_before_the_seal(capsys):
    code, out = run(["--gate", "1", "--real-calls"], capsys)
    assert code == 2 and "not sealed (D27)" in out


def test_gates_refuse_without_real_calls(capsys, monkeypatch):
    monkeypatch.setattr(gate, "sealed_ok", lambda: [])
    code, out = run(["--gate", "1"], capsys)
    assert code == 2 and "Nothing was called" in out
    code, out = run(["--gate", "2", "--library", str(gate.EMPTY)], capsys)
    assert code == 2 and "Nothing was called" in out
    code, out = run(["--gate", "2"], capsys)
    assert code == 2 and "--library" in out


def test_prediction_is_zero_token_and_reads_only_frozen_files(tmp_path, capsys):
    lib_path = make_library(tmp_path, ("20261120T010000Z-aaaa", [
        rule(1, cwe="CWE-22", pattern="../", field="path", ci=False),
        rule(2, cwe="CWE-89", pattern="or 1=1", field="query")]))[-1]
    lib = rule_library.load(lib_path)
    pred = gate.predict(lib)
    assert set(pred) == set(gate.SOURCES)
    assert all(h["rule_ids"][0].startswith("lib-") for hits in pred.values() for h in hits)
    code, out = run(["--predict", "--library", str(lib_path)], capsys)
    assert code == 0 and "answered by the library" in out


def good_brain(view):
    if "OR 1=1" in view["body"]:
        return verdict("CWE-89", {"conditions": [cond(field="body", pattern="or 1=1")]})
    return verdict("benign")


class GateOps(TrainOps):
    """A train match as Gate 1 runs it: AI Red (fake provider) + rule-writing AI Blue."""

    def __init__(self, live, answer):
        super().__init__(live, answer=answer, cfg=ai_config())

    def red_client(self, config, prices):
        return lc.LLMClient(config=config, prices=prices,
                            adapters={"fake": FakeAdapter(text=RED_REPLY)}, env={},
                            sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")

    def traffic(self, match_id, match_dir, attacks, benign_entries, schedule, settle,
                red_driver=None):
        assert red_driver is not None
        red_driver.red.propose(None, 1)
        super().traffic(match_id, match_dir, attacks, benign_entries, schedule, settle)


def test_gate1_offline_runs_train_matches_and_scaffolds_scoped_audits(dirs, tmp_path,
                                                                     monkeypatch):
    live, runs = dirs
    ids = iter(f"20261120T0200{i:02d}Z-bbbb" for i in range(10))
    monkeypatch.setattr(gate.run_match, "new_match_id", lambda: next(ids))
    sheets, audits = tmp_path / "sheets", tmp_path / "audits"
    sheets.mkdir()
    code = gate.gate1(cost_stats.load_prices(), k=2, sheet_dir=sheets, audits=audits,
                      ops=GateOps(live, answer=good_brain), live_dir=live, runs_dir=runs)
    assert code == 0
    ms = [json.loads((d / "match.json").read_text()) for d in sorted(runs.glob("2026*"))]
    assert [m["purpose"] for m in ms] == ["train", "train"]
    assert [m["traffic"]["seed"] for m in ms] == list(gate.SEEDS[:2])
    assert all(m["blue_params"]["library"] is None for m in ms)  # D28: no library
    assert len(list(audits.glob("*.jsonl"))) == 2
    assert "candidate source rounds only" in next(sheets.glob("*.md")).read_text()


def test_gate2_offline_compares_empty_and_library(tmp_path, monkeypatch, capsys):
    lib_path = make_library(tmp_path / "lib", ("20261120T010000Z-aaaa", [
        rule(1, cwe="CWE-22", pattern="../", field="path", ci=False)]))[-1]
    monkeypatch.setattr(gate, "holdout_hits", lambda lib: {e.library_id: []
                                                           for e in lib.entries})
    live = tmp_path / "live"
    live.mkdir()
    code = gate.gate2(cost_stats.load_prices(), lib_path, root=tmp_path / "out",
                      ops=RulesOps(live, answer=lambda v: verdict("benign")))
    out = capsys.readouterr().out
    assert code == 0, out
    reps = sorted(p.name for p in (tmp_path / "out").iterdir())
    assert reps == sorted(f"{s}-{a}" for s in gate.SOURCES for a in ("empty", "library"))
    for s in gate.SOURCES:
        e = json.loads((tmp_path / "out" / f"{s}-empty" / "replay.json").read_text())
        l_ = json.loads((tmp_path / "out" / f"{s}-library" / "replay.json").read_text())
        assert e["blue_params"]["library"]["entries"] == 0
        edir = tmp_path / "out" / f"{s}-empty"  # v0000 is LOADED, not absent (regression)
        assert (edir / "library.json").is_file()
        assert {json.loads(x)["schema_version"]
                for x in (edir / "verdicts.jsonl").read_text().splitlines()} == {"0.4"}
        assert l_["blue_params"]["library"]["entries"] == 1
        drop = ("library",)
        assert {k: v for k, v in e["blue_params"].items() if k not in drop} == \
               {k: v for k, v in l_["blue_params"].items() if k not in drop}  # all else equal
    assert "M5 summary" in out and "RESULT: PASS" in out
