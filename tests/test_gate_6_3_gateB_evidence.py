"""The committed Stage 6.3 Gate B evidence (flagship gate, M7): the 3 eval matches
(data/golden/eval-6.3-gateB-match{1,2,3}/) and their FULL D16 audit files
(data/golden/audits/). These are TEST data (D35): this read-only integrity check is the
designer's GO'd evidence test. AI output is not reproducible, so it is preserved and checked:
every file matches its match.json hash, the configuration is the D38 Red treatment against
Haiku + library v5, the match ids are registered in config/test_set.json, and the audit
scaffold covers every Red round (D36)."""

from __future__ import annotations

import hashlib
import json

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402

GOLDEN = REPO / "data" / "golden"
COMMIT = "28b30434e8eb42845e61914ffb27e367efbdfeb2"
LIB_V5_SHA = "324a1eceace9499606284230f4997cb961da39af6ec67ab2a6d7c4e70a168bc7"
MATCHES = {  # folder -> (match_id, seed, total usd)
    "eval-6.3-gateB-match1": ("20261119T061057Z-6177", 6301, 0.004685),
    "eval-6.3-gateB-match2": ("20261119T061403Z-789a", 6302, 0.004679),
    "eval-6.3-gateB-match3": ("20261119T061702Z-18d1", 6303, 0.005179),
}


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_the_three_eval_matches_are_committed():
    assert sorted(p.name for p in GOLDEN.glob("eval-6.3-gateB-match*")) == sorted(MATCHES)
    assert abs(sum(v[2] for v in MATCHES.values()) - 0.014543) < 1e-6  # Gate B total


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_files_match_their_hashes_and_the_d38_protocol(name):
    d = GOLDEN / name
    mid, seed, usd = MATCHES[name]
    m = json.loads((d / "match.json").read_text())
    assert run_match.validate_manifest(m) == []
    assert m["match_id"] == mid and m["purpose"] == "eval" and m["status"] == "completed"
    assert m["git"] == {"commit": COMMIT, "dirty": False} and m["traffic"]["seed"] == seed
    assert abs(m["cost"]["total_usd"] - usd) < 1e-9
    red, blue = m["red_params"], m["blue_params"]
    assert red["model"] == "gpt-6-luna" and red["provider"] == "openai"  # D38
    assert red["request"]["reasoning_effort"] == "high"
    assert red["request"]["max_output_tokens"] == 8192
    assert red["caching"]["mode"] == "on" and red["prompt_version"] == "1"
    assert blue["model"] == "claude-haiku-5-5" and blue["rules"]["mode"] == "on"
    assert blue["caching"]["mode"] == "on" and blue["library"]["sha256"] == LIB_V5_SHA
    assert hashlib.sha256((d / "library.json").read_bytes()).hexdigest() == LIB_V5_SHA
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]  # nothing changed since the match froze
    assert set(p.name for p in d.iterdir()) == set(m["artifacts"]) | {"README.md", "match.json"}
    calls = rows(d / "api_calls.jsonl")
    assert not any(c["agent"] == "red" and c.get("stop_reason") == "max_tokens" for c in calls)


def test_the_matches_are_registered_test_data():
    ts = json.loads((REPO / "config" / "test_set.json").read_text())
    assert {v[0] for v in MATCHES.values()} <= set(ts["match_ids"])
    assert "eval" in ts["test_purposes"]


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_the_audit_covers_every_red_round(name):
    mid = MATCHES[name][0]
    reds = rows(GOLDEN / name / "red_attacks.jsonl")
    audit = rows(GOLDEN / "audits" / f"{mid}.jsonl")
    assert sorted(a["round"] for a in audit) == sorted(r["round"] for r in reds)  # D36: FULL
    assert all(a["match_id"] == mid for a in audit)
    # D16 verdicts (designer, 2026-11-19): invalid only where the payload sat in the URL
    # fragment and never reached the server (match1 r10, match2 r5); everything else valid.
    inv = {r["round"] for r in audit if r["verdict"] == "invalid"}
    expect = {"eval-6.3-gateB-match1": {10}, "eval-6.3-gateB-match2": {5},
              "eval-6.3-gateB-match3": set()}[name]
    assert inv == expect and all(a["auditor"] == "designer" for a in audit)
