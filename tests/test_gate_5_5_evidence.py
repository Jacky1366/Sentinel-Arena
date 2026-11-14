"""The committed Stage 5.5 gate evidence (data/golden/replays/gate-5.5/): 12 Blue
replays with real Haiku 5.5 calls. AI output is not reproducible, so the run is
preserved: every file matches its recorded hash, every input matches its golden
source, and the Judge re-scores every folder offline to byte-identical outputs."""

from __future__ import annotations

import json
import shutil
import sys

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO

sys.path.insert(0, str(REPO))
import run_match  # noqa: E402

GATE = REPO / "data" / "golden" / "replays" / "gate-5.5"
SOURCES = ["ai-red-luna-gate2-match1", "ai-red-luna-gate2-match2", "ai-red-luna-gate2-match3",
           "scripted-baseline-benign-match"]
MODES = ("off", "shadow", "on")
FOLDERS = [f"{s}-{m}" for s in SOURCES for m in MODES]
COMMIT = "072e9d72daa836ab936574aab3ac0d3af456fd76"
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "replay_manifest_v0_1.schema.json")
                                         .read_text()))
# Written by the Judge (offline steps); re-derived from the inputs + Blue's verdicts.
JUDGED = ("landed.jsonl", "rounds.jsonl", "benign_results.jsonl", "anomalies.jsonl",
          "rule_results.jsonl")


def manifest(name: str) -> dict:
    return json.loads((GATE / name / "replay.json").read_text())


def test_exactly_the_12_replays_and_a_readme():
    assert sorted(p.name for p in GATE.iterdir()) == sorted(FOLDERS + ["README.md"])


@pytest.mark.parametrize("name", FOLDERS)
def test_files_match_their_recorded_hashes_and_sources(name):
    d, m = GATE / name, manifest(name)
    assert SCHEMA.is_valid(m)
    assert m["status"] == "completed" and m["git"] == {"commit": COMMIT, "dirty": False}
    assert m["blue_engine"] == "claude" and m["blue_params"]["model"] == "claude-haiku-5-5"
    mode = name.rsplit("-", 1)[1]
    assert m["blue_params"]["rules"] == {"mode": mode, "max_rules": 10}
    assert m["blue_params"]["request"]["max_output_tokens"] == 512
    hashes = run_match.artifact_hashes(d)
    hashes.pop("replay.json")
    assert hashes == m["artifacts"]  # nothing changed since the run
    src = REPO / "data" / "golden" / name.rsplit("-", 1)[0]
    assert m["source"]["path"] == src.relative_to(REPO).as_posix()
    assert m["source"]["match_json_sha256"] == run_match.sha256_file(src / "match.json")
    for f in m["source"]["copied"]:  # inputs are the golden source's, byte for byte
        assert run_match.sha256_file(d / f) == m["source"]["artifacts"][f]["sha256"]
    has_rules = (d / "rules.jsonl").exists()
    assert has_rules == (mode != "off")


@pytest.mark.parametrize("name", FOLDERS)
def test_the_judge_rescores_identically(name, tmp_path):
    d = GATE / name
    work = tmp_path / name
    shutil.copytree(d, work)
    for f in JUDGED:
        (work / f).unlink(missing_ok=True)
    ops = run_match.Ops()  # only the pure file steps are used: no network
    ops.judge_fact1(work)
    for step in ("judge_rounds", "judge_benign", "judge_red", "judge_rules"):
        getattr(ops, step)(work)
    for f in JUDGED:
        assert (work / f).exists() == (d / f).exists(), f
        if (d / f).exists():
            assert (work / f).read_bytes() == (d / f).read_bytes(), f


def test_headline_numbers():
    """The numbers reported in docs/progress.md (Stage 5.5 gate results)."""
    calls = {n: manifest(n)["cost"]["attempts"] for n in FOLDERS}
    assert sum(calls[f"{s}-off"] for s in SOURCES) == 104
    assert sum(calls[f"{s}-on"] for s in SOURCES) == 90
    assert sum(calls.values()) == 298
    rules = {n: len((GATE / n / "rules.jsonl").read_text().splitlines())
             for n in FOLDERS if not n.endswith("-off")}
    assert sum(rules.values()) == 56
    for n in rules:
        assert (GATE / n / "rule_rejections.jsonl").read_text() == ""
        for r in map(json.loads, (GATE / n / "rule_results.jsonl").read_text().splitlines()):
            assert r["replay_fires"] and r["cwe_matches_source"] and r["fixture_fires"] == 0
    total = sum(manifest(n)["cost"]["total_usd"] for n in FOLDERS)
    assert round(total, 4) == 0.0569
