"""tools/replay_blue.py (Stage 5.5, D17): a replay of a frozen match equals the live
run given identical verdicts, never writes into the source folder, refuses bad
sources and output folders, and the source's D16 audit applies to it. Fake Ops and
the fake provider only; the golden folders are replayed with scripted Blue."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
from test_run_match_rules import RulesOps, broad, dirs, go  # noqa: F401 (fixture)
from test_blue_rules import union_brain
from test_run_match_failure import FakeOps
from tools import audit_match, replay_blue  # noqa: E402

GOLDEN = sorted(p.parent for p in (REPO / "data" / "golden").glob("*/match.json"))
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "replay_manifest.schema.json")
                                         .read_text()))
JUDGED = ("landed.jsonl", "verdicts.jsonl", "rules.jsonl", "rule_rejections.jsonl",
          "rounds.jsonl", "benign_results.jsonl", "rule_results.jsonl", "anomalies.jsonl")


def tree(d: Path) -> dict[str, str]:
    return {p.relative_to(d).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.rglob("*")) if p.is_file()}


def read_only(d: Path):
    """chmod a folder tree read-only; returns a function that restores it."""
    modes = {p: p.stat().st_mode for p in [d, *d.rglob("*")]}
    for p in modes:
        p.chmod(modes[p] & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

    def restore():
        for p, m in modes.items():
            p.chmod(m)
    return restore


def do_replay(src, out, ops, **kw):
    lines: list[str] = []
    code, rdir = replay_blue.replay(src, out, ops=ops, out_fn=lines.append, **kw)
    return code, rdir, "\n".join(lines)


@pytest.mark.parametrize("mode,answer", [("on", broad), ("shadow", broad), ("on", union_brain),
                                         ("off", broad)])
def test_replay_equals_the_live_run_given_identical_verdicts(dirs, tmp_path, mode, answer):
    code, live_dir, out = go(RulesOps(dirs[0], answer=answer), dirs, mode)
    assert code == 0, out
    before = tree(live_dir)
    restore = read_only(live_dir)
    try:
        code, rdir, rout = do_replay(live_dir, tmp_path / "replay",
                                     RulesOps(dirs[0], answer=answer), engine="claude",
                                     rules_mode=mode)
    finally:
        restore()
    assert code == 0, rout
    assert tree(live_dir) == before  # the source is untouched
    for name in JUDGED:
        a, b = live_dir / name, rdir / name
        assert a.exists() == b.exists(), name
        if a.exists():
            assert a.read_bytes() == b.read_bytes(), name  # byte-identical
    live_calls = (live_dir / "api_calls.jsonl").read_text().splitlines()
    replay_calls = (rdir / "api_calls.jsonl").read_text().splitlines()
    assert len(live_calls) == len(replay_calls)
    m = json.loads((rdir / "replay.json").read_text())
    assert SCHEMA.is_valid(m) and m["status"] == "completed"
    assert m["blue_params"] == json.loads((live_dir / "match.json").read_text())["blue_params"]


def test_replay_manifest_records_the_source_and_copies_only_inputs(dirs, tmp_path):
    code, live_dir, _ = go(RulesOps(dirs[0]), dirs, "on")
    src = json.loads((live_dir / "match.json").read_text())
    code, rdir, _ = do_replay(live_dir, tmp_path / "r", RulesOps(dirs[0]), engine="scripted")
    assert code == 0
    m = json.loads((rdir / "replay.json").read_text())
    assert m["source"]["match_id"] == src["match_id"]
    assert m["source"]["artifacts"] == src["artifacts"]
    assert m["source"]["copied"] == ["benign_requests.jsonl", "challenge_snapshots.jsonl",
                                     "proxy.jsonl", "red_attacks.jsonl"]
    assert m["source"]["match_json_sha256"] == \
        hashlib.sha256((live_dir / "match.json").read_bytes()).hexdigest()
    assert m["blue_engine"] == "scripted" and m["blue_params"] is None
    assert m["cost"]["attempts"] == 0 and not (rdir / "api_calls.jsonl").exists()
    assert not (rdir / "match.json").exists()
    assert set(m["artifacts"]) == set(tree(rdir)) - {"replay.json"}
    for v in map(json.loads, (rdir / "verdicts.jsonl").read_text().splitlines()):
        assert v["match_id"] == src["match_id"]  # the source id: the join and audits work


@pytest.mark.parametrize("golden", GOLDEN, ids=[g.name for g in GOLDEN])
def test_scripted_replay_of_every_golden_folder_leaves_it_untouched(golden, tmp_path):
    before = tree(golden)
    code, rdir, out = do_replay(golden, tmp_path / "r", FakeOps(tmp_path), engine="scripted")
    assert code == 0, out
    assert tree(golden) == before
    src = json.loads((golden / "match.json").read_text())
    for name in json.loads((rdir / "replay.json").read_text())["source"]["copied"]:
        assert hashlib.sha256((rdir / name).read_bytes()).hexdigest() == \
            src["artifacts"][name]["sha256"]
    assert (rdir / "landed.jsonl").read_bytes() == (golden / "landed.jsonl").read_bytes()
    if src["blue_engine"] == "scripted":  # same engine: same verdicts as the source
        def key(p):
            return [(r["request_id"], r["verdict"]) for r in
                    map(json.loads, p.read_text().splitlines())]
        assert key(rdir / "verdicts.jsonl") == key(golden / "verdicts.jsonl")


def test_the_source_audit_applies_to_a_replay(tmp_path):
    golden = REPO / "data" / "golden" / "ai-red-luna-gate2-match3"
    code, rdir, _ = do_replay(golden, tmp_path / "r", FakeOps(tmp_path), engine="scripted")
    assert code == 0
    s = audit_match.summary(rdir)
    assert s["match_id"] == "20261113T053039Z-4645"
    assert s["audit_file"] == "data/golden/audits/20261113T053039Z-4645.jsonl"
    assert s["audited_excludes_label_invalid"] == [9] and s["audited"] is not None
    assert s["audited"]["detection"]["den"] == s["raw"]["detection"]["den"] - 1


# ---- refusals: nothing is written ------------------------------------------------

def refused(src, out, ops=None, **kw):
    code, rdir, text = do_replay(src, out, ops or FakeOps(out.parent), **kw)
    assert (code, rdir) == (2, None), text
    return text


def test_refuses_to_write_inside_the_source_or_another_replay(tmp_path):
    golden = REPO / "data" / "golden" / "scripted-baseline-benign-match"
    before = tree(golden)
    assert "holds a match.json" in refused(golden, golden / "replay")
    assert tree(golden) == before and not (golden / "replay").exists()
    code, rdir, _ = do_replay(golden, tmp_path / "r1", FakeOps(tmp_path), engine="scripted")
    assert code == 0
    assert "holds a replay.json" in refused(golden, rdir / "nested")


def test_refuses_a_non_empty_output_folder(tmp_path):
    out = tmp_path / "busy"
    out.mkdir()
    (out / "x").write_text("x")
    assert "not empty" in refused(REPO / "data" / "golden" / "scripted-baseline-match", out)


def copy_match(src: Path, dst: Path) -> Path:
    dst.mkdir(parents=True)
    for p in src.iterdir():
        if p.is_file():
            (dst / p.name).write_bytes(p.read_bytes())
    return dst


def test_refuses_a_tampered_source(tmp_path):
    d = copy_match(REPO / "data" / "golden" / "ai-red-luna-gate2-match1", tmp_path / "m")
    with (d / "proxy.jsonl").open("a") as fh:
        fh.write("\n")
    assert "was changed" in refused(d, tmp_path / "out")


def test_refuses_a_failed_source(tmp_path):
    d = copy_match(REPO / "data" / "golden" / "ai-red-luna-gate2-match1", tmp_path / "m")
    m = json.loads((d / "match.json").read_text())
    m.update(status="failed", failed_step="blue", error="x")
    (d / "match.json").write_text(json.dumps(m))
    assert "only a completed or stopped" in refused(d, tmp_path / "out")


def test_refuses_a_folder_that_is_not_a_match(tmp_path):
    (tmp_path / "m").mkdir()
    assert "not a frozen match" in refused(tmp_path / "m", tmp_path / "out")


def test_refuses_a_rules_mode_for_scripted_blue(tmp_path):
    text = refused(REPO / "data" / "golden" / "scripted-baseline-match", tmp_path / "out",
                   engine="scripted", rules_mode="on")
    assert "needs --engine claude" in text


def test_default_output_is_data_replays(monkeypatch, tmp_path):
    monkeypatch.setattr(replay_blue, "REPLAYS", tmp_path / "replays")
    code, rdir, _ = do_replay(REPO / "data" / "golden" / "scripted-baseline-match", None,
                              FakeOps(tmp_path), engine="scripted")
    assert code == 0 and rdir.parent == tmp_path / "replays"
    assert rdir.name == json.loads((rdir / "replay.json").read_text())["replay_id"]


def test_replays_dir_is_git_ignored():
    ignore = (REPO / ".gitignore").read_text()
    assert "data/replays/*" in ignore
    assert os.path.isfile(REPO / "data" / "replays" / ".gitkeep")


# ---- the Part F gate tool, offline paths only -----------------------------------

def test_gate_refuses_without_real_calls_and_calls_nothing(capsys, monkeypatch):
    from tools import stage5_5_check as gate
    monkeypatch.setattr(gate.replay_blue, "replay",
                        lambda *a, **k: pytest.fail("the gate called replay"))
    assert gate.main([]) == 2
    out = capsys.readouterr().out
    assert "12 replays" in out and "REFUSED" in out


def test_gate_report_prints_numbers_and_every_rule(dirs, tmp_path, capsys):
    from tools import stage5_5_check as gate

    def brain(view):  # one valid broad rule, then an invalid proposal on the benign line
        from test_blue_rules import cond, verdict
        if view["query"] == "q=apple":
            return verdict("CWE-89", {"conditions": [cond(op="regex", pattern="(?=x)")]})
        return broad(view)
    code, live_dir, _ = go(RulesOps(dirs[0], answer=union_brain), dirs, "off")
    code, rdir, _ = do_replay(live_dir, tmp_path / "r", RulesOps(dirs[0], answer=brain),
                              engine="claude", rules_mode="shadow")
    assert code == 0
    row = gate.report(rdir)
    out = capsys.readouterr().out
    assert row["mode"] == "shadow" and row["proposed"] >= 2
    assert "rules mode shadow" in out and "REJECTED" in out and "regex_unsupported_feature" in out
    assert "rule path" in out and "AI path" in out and "raw" in out and "audited" in out
