"""The committed Stage 5.7 Gate 2 / 2b evidence (data/golden/replays/gate-5.7/): 8 cached
Blue replays (rules on / off, caching on) with real Haiku 5.5 calls. AI output is not
reproducible, so the runs are preserved: every file matches its recorded hash, every
input matches its golden source, every verdict equals the committed gate-5.5 replay of the
same rules mode, and the Judge re-scores every folder offline to byte-identical outputs."""

from __future__ import annotations

import json
import shutil
import sys

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO

sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from stats import cost  # noqa: E402

GATE = REPO / "data" / "golden" / "replays" / "gate-5.7"
GATE55 = REPO / "data" / "golden" / "replays" / "gate-5.5"
SOURCES = ["ai-red-luna-gate2-match1", "ai-red-luna-gate2-match2", "ai-red-luna-gate2-match3",
           "scripted-baseline-benign-match"]
FOLDERS = [f"{s}-{m}-cached" for m in ("on", "off") for s in SOURCES]
COMMIT = {"on": "5d6013d964a65bfa961741e5ecd851b8b4eda6a3",     # Gate 2
          "off": "bb4eeeb2c84f9fc44ba512980c3cde1e74a74380"}    # Gate 2b
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "replay_manifest.schema.json")
                                         .read_text()))
JUDGED = ("landed.jsonl", "rounds.jsonl", "benign_results.jsonl", "anomalies.jsonl",
          "rule_results.jsonl")


def manifest(name: str) -> dict:
    return json.loads((GATE / name / "replay.json").read_text())


def mode_of(name: str) -> str:
    return name.rsplit("-", 2)[1]


def source_of(name: str) -> str:
    return name.rsplit("-", 2)[0]


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def test_exactly_the_8_replays_and_a_readme():
    assert sorted(p.name for p in GATE.iterdir()) == sorted(FOLDERS + ["README.md"])


@pytest.mark.parametrize("name", FOLDERS)
def test_files_match_their_recorded_hashes_and_sources(name):
    d, m, mode = GATE / name, manifest(name), mode_of(name)
    assert SCHEMA.is_valid(m) and m["schema_version"] == "0.2"
    assert m["status"] == "completed" and m["git"] == {"commit": COMMIT[mode], "dirty": False}
    p = m["blue_params"]
    assert m["blue_engine"] == "claude" and p["model"] == "claude-haiku-5-5"
    assert p["rules"] == {"mode": mode, "max_rules": 10}
    assert p["caching"] == {"mode": "on", "ttl": "5m"}
    assert p["prompt_version"] == ("2" if mode == "on" else "1")
    assert p["request"]["max_output_tokens"] == 512
    hashes = run_match.artifact_hashes(d)
    hashes.pop("replay.json")
    assert hashes == m["artifacts"]
    src = REPO / "data" / "golden" / source_of(name)
    assert m["source"]["path"] == src.relative_to(REPO).as_posix()
    assert m["source"]["match_json_sha256"] == run_match.sha256_file(src / "match.json")
    for f in m["source"]["copied"]:
        assert run_match.sha256_file(d / f) == m["source"]["artifacts"][f]["sha256"]
    assert (d / "rules.jsonl").exists() == (mode == "on")


@pytest.mark.parametrize("name", FOLDERS)
def test_verdicts_equal_the_uncached_gate_5_5_replay(name):
    """Caching is a cost setting: the same traffic got the same verdicts."""
    twin = GATE55 / f"{source_of(name)}-{mode_of(name)}"
    key = lambda d: [(v["request_id"], v["verdict"], v.get("source"))  # noqa: E731
                     for v in rows(d / "verdicts.jsonl")]
    assert key(GATE / name) == key(twin)


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


def test_headline_numbers_and_the_2x2():
    """The numbers reported in docs/progress.md (Stage 5.7, Gates 2 / 2b)."""
    prices = cost.load_prices()

    def total(folder_of):
        s = cost.summarize([c for src in SOURCES for c in rows(folder_of(src) / "api_calls.jsonl")],
                           prices)
        return round(s["total_usd"], 6), s["attempts"], round(s["cache_savings_usd"], 6)
    off = total(lambda s: GATE55 / f"{s}-off")
    on = total(lambda s: GATE55 / f"{s}-on")
    off_c = total(lambda s: GATE / f"{s}-off-cached")
    on_c = total(lambda s: GATE / f"{s}-on-cached")
    approx = lambda x: pytest.approx(x, abs=2e-6)  # noqa: E731 (per-source rounding)
    assert (off[0], off[1], on[0], on[1]) == (approx(0.012388), 104, approx(0.020478), 90)
    assert (off_c[0], off_c[1], off_c[2]) == (approx(0.005201), 104, approx(0.007211))
    assert (on_c[0], on_c[1], on_c[2]) == (approx(0.006092), 90, approx(0.014341))
    assert on_c[0] > off_c[0]  # rules still cost more than no rules once both are cached
    for name in FOLDERS:
        assert manifest(name)["cost"]["unpriced_usage"] is False
        assert all(c["unpriced_cache_write_tokens"] == 0
                   for c in rows(GATE / name / "api_calls.jsonl"))
