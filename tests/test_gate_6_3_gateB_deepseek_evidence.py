"""The committed Stage 6.3 Gate B-deepseek evidence: 3 eval matches
(data/golden/eval-6.3-gateB-deepseek-match{1,2,3}/), a DeepSeek Red treatment arm against
Haiku + library v5, and their FULL D16 audit files (data/golden/audits/). TEST data (D35);
this read-only integrity check is the designer's GO'd evidence test: every file matches its
match.json hash, the configuration is deepseek-v4-pro at effort max (8192) against Haiku +
v5, every Red call carries its D39 rate window, the ids are registered as test data, and the
audit scaffold covers every Red round (D36)."""

from __future__ import annotations

import hashlib
import json

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402

GOLDEN = REPO / "data" / "golden"
COMMIT = "c4e7922"
LIB_V5_SHA = "324a1eceace9499606284230f4997cb961da39af6ec67ab2a6d7c4e70a168bc7"
MATCHES = {  # folder -> (match_id, seed, total usd)
    "eval-6.3-gateB-deepseek-match1": ("20261119T071647Z-3ffc", 6311, 0.081741),
    "eval-6.3-gateB-deepseek-match2": ("20261119T073045Z-de63", 6312, 0.088465),
    "eval-6.3-gateB-deepseek-match3": ("20261119T074153Z-5288", 6313, 0.075698),
}


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_the_three_eval_matches_are_committed():
    assert sorted(p.name for p in GOLDEN.glob("eval-6.3-gateB-deepseek-match*")) == \
        sorted(MATCHES)
    assert round(sum(v[2] for v in MATCHES.values()), 6) == 0.245904  # gate total


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_files_match_their_hashes_and_the_protocol(name):
    d = GOLDEN / name
    mid, seed, usd = MATCHES[name]
    m = json.loads((d / "match.json").read_text())
    assert run_match.validate_manifest(m) == []
    assert m["match_id"] == mid and m["purpose"] == "eval" and m["status"] == "completed"
    assert m["git"]["commit"].startswith(COMMIT) and m["git"]["dirty"] is False
    assert m["traffic"]["seed"] == seed and abs(m["cost"]["total_usd"] - usd) < 1e-9
    red, blue = m["red_params"], m["blue_params"]
    assert red["provider"] == "deepseek" and red["model"] == "deepseek-v4-pro"
    assert red["request"]["reasoning_effort"] == "max"
    assert red["request"]["max_output_tokens"] == 8192
    assert red["caching"] == {"mode": "on", "ttl": "auto"} and red["prompt_version"] == "1"
    assert blue["model"] == "claude-haiku-5-5" and blue["rules"]["mode"] == "on"
    assert blue["library"]["sha256"] == LIB_V5_SHA
    assert hashlib.sha256((d / "library.json").read_bytes()).hexdigest() == LIB_V5_SHA
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]  # nothing changed since the match froze
    assert set(p.name for p in d.iterdir()) == set(m["artifacts"]) | {"README.md", "match.json"}
    red_calls = [c for c in rows(d / "api_calls.jsonl") if c["agent"] == "red"]
    assert all(c["rate_window"] in ("peak", "off_peak") for c in red_calls)  # D39
    assert not any(c.get("stop_reason") == "max_tokens" for c in red_calls)


def test_the_matches_are_registered_test_data():
    ts = json.loads((REPO / "config" / "test_set.json").read_text())
    assert {v[0] for v in MATCHES.values()} <= set(ts["match_ids"])


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_the_audit_covers_every_red_round(name):
    mid = MATCHES[name][0]
    reds = rows(GOLDEN / name / "red_attacks.jsonl")
    audit = rows(GOLDEN / "audits" / f"{mid}.jsonl")
    assert sorted(a["round"] for a in audit) == sorted(r["round"] for r in reds)  # D36: FULL
