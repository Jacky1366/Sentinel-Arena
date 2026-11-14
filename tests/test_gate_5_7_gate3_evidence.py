"""The committed Stage 5.7 Gate 3 evidence (data/golden/ai-vs-ai-gate3-match{1,2,3}/): the
first three AI-vs-AI matches (AI Red gpt-6-luna vs AI Blue Haiku 5.5, rules on, caching on
for both), with the designer's D16 label audits (data/golden/audits/). AI output is not
reproducible, so the matches are preserved: every file matches the hash its match.json
recorded, the Judge re-scores every folder offline to byte-identical outputs, every match
reaches four facts PASS, and the audited numbers are the ones reported in docs/progress.md."""

from __future__ import annotations

import json
import shutil
import sys

import pytest

from llm_fakes import REPO

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import audit_match as am  # noqa: E402
import run_match  # noqa: E402
from stats import cost  # noqa: E402
from tools import four_facts as ff  # noqa: E402

GOLDEN = REPO / "data" / "golden"
COMMIT = "be635929d0aaad7af1bb2946632ca59a136efa38"
# name -> (match_id, raw detection, audited detection, label-invalid rounds, landed rounds,
#          (sent, unsent), (red usd, blue usd))
MATCHES = {
    "ai-vs-ai-gate3-match1": ("20261114T072114Z-1a3a", (9, 9), (9, 9), [], [], (9, 1),
                              (0.001548, 0.001942)),
    "ai-vs-ai-gate3-match2": ("20261114T072400Z-a58a", (8, 9), (8, 8), [8], [3], (9, 1),
                              (0.001002, 0.001499)),
    "ai-vs-ai-gate3-match3": ("20261114T072621Z-a41b", (10, 10), (10, 10), [], [], (10, 0),
                              (0.001247, 0.001615)),
}
JUDGED = ("landed.jsonl", "rounds.jsonl", "benign_results.jsonl", "anomalies.jsonl",
          "rule_results.jsonl")


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def match(name: str) -> dict:
    return json.loads((GOLDEN / name / "match.json").read_text())


def test_the_three_matches_are_committed():
    assert sorted(p.name for p in GOLDEN.glob("ai-vs-ai-gate3-match*")) == sorted(MATCHES)


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_files_match_their_recorded_hashes_and_configuration(name):
    d, m = GOLDEN / name, match(name)
    mid, *_ = MATCHES[name]
    assert m["schema_version"] == "0.7" and m["match_id"] == mid
    assert m["status"] == "completed" and m["git"] == {"commit": COMMIT, "dirty": False}
    assert m["judge_version"] == "0.6.0" and m["traffic"]["seed"] == 5202
    assert m["red_engine"] == "ai" and m["blue_engine"] == "claude"
    assert m["red_params"]["model"] == "gpt-6-luna" and m["blue_params"]["model"] == "claude-haiku-5-5"
    assert m["red_params"]["caching"] == {"mode": "on", "ttl": "30m"}
    assert m["blue_params"]["caching"] == {"mode": "on", "ttl": "5m"}
    assert m["blue_params"]["rules"] == {"mode": "on", "max_rules": 10}
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]  # nothing changed since the match froze


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_the_judge_rescores_identically(name, tmp_path):
    d = GOLDEN / name
    work = tmp_path / name
    shutil.copytree(d, work)
    for f in JUDGED:
        (work / f).unlink()
    ops = run_match.Ops()  # only the pure file steps are used: no network
    ops.judge_fact1(work)
    for step in ("judge_rounds", "judge_benign", "judge_red", "judge_rules"):
        getattr(ops, step)(work)
    for f in JUDGED:
        assert (work / f).read_bytes() == (d / f).read_bytes(), f


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_four_facts_pass(name):
    """The Stage 5 done-when (contract 6.11, C7)."""
    r = ff.check(GOLDEN / name)
    assert r["status"] == ff.PASS and r["rules_mode"] == "on", r["reasons"]


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_audited_numbers(name):
    d = GOLDEN / name
    mid, raw, audited, invalid, landed, (sent, unsent), _ = MATCHES[name]
    audit = GOLDEN / "audits" / f"{mid}.jsonl"
    assert am.audit_path(mid) == audit and audit.is_file()
    s = am.summary(d)  # validates the audit file against the schema and the rounds
    assert s["unaudited"] == [] and s["audited_excludes_label_invalid"] == invalid
    det = s["raw"]["detection"], s["audited"]["detection"]
    assert ((det[0]["num"], det[0]["den"]), (det[1]["num"], det[1]["den"])) == (raw, audited)
    assert (s["raw"]["fp"]["num"], s["raw"]["fp"]["den"]) == (0, 17)
    assert len(rows(d / "red_attacks.jsonl")) == sent and len(rows(d / "red_unsent.jsonl")) == unsent
    assert [r["round"] for r in rows(d / "rounds.jsonl") if r["landed"]] == landed


def test_audit_totals_27_valid_1_invalid():
    verdicts = [r["verdict"] for name in MATCHES
                for r in rows(GOLDEN / "audits" / f"{MATCHES[name][0]}.jsonl")]
    assert (verdicts.count("valid"), verdicts.count("invalid"), len(verdicts)) == (27, 1, 28)


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_cost_per_agent(name):
    """The per-agent costs reported in docs/progress.md; both agents saved money net."""
    d, m = GOLDEN / name, match(name)
    red_usd, blue_usd = MATCHES[name][-1]
    s = cost.summarize(rows(d / "api_calls.jsonl"), cost.load_prices())
    assert round(s["total_usd"], 6) == m["cost"]["total_usd"]
    for agent, usd in (("red", red_usd), ("blue", blue_usd)):
        b = m["cost"]["by_agent"][agent]
        assert b["usd"] == usd and b["cache_savings_usd"] > 0 and b["failed_attempts"] == 0
    assert all(c["stop_reason"] != "max_tokens" and c["unpriced_cache_write_tokens"] == 0
               for c in rows(d / "api_calls.jsonl"))
