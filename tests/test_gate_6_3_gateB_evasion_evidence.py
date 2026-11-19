"""The committed Stage 6.3 Gate B-evasion evidence (D40, the final experiment): 3 eval matches
(data/golden/eval-6.3-gateB-evasion-match{1,2,3}/), a DeepSeek Red treatment arm against
Haiku + library v5, and their FULL D16 audit files (data/golden/audits/). TEST data (D35);
this read-only integrity check is the designer's GO'd evidence test: every file matches its
match.json hash, the configuration is Gate B-deepseek + Red prompt v2 (the pre-registered
evasion directive) with a 180 s Red timeout, every Red call carries its D39 rate window, the ids are registered as test data, and the
audit scaffold covers every Red round (D36)."""

from __future__ import annotations

import hashlib
import json

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402

GOLDEN = REPO / "data" / "golden"
COMMIT = "8e64792"
V2_SHA = "a826b6f40b203a6d6e93225b834460d64d6dc576e84963f6b9e74c1f7cbaa66b"
LIB_V5_SHA = "324a1eceace9499606284230f4997cb961da39af6ec67ab2a6d7c4e70a168bc7"
MATCHES = {  # folder -> (match_id, seed, total usd)
    "eval-6.3-gateB-evasion-match1": ("20261119T082130Z-da57", 6321, 0.109897),
    "eval-6.3-gateB-evasion-match2": ("20261119T083408Z-2665", 6322, 0.137117),
    "eval-6.3-gateB-evasion-match3": ("20261119T084926Z-a819", 6323, 0.108983),
}


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_the_three_eval_matches_are_committed():
    assert sorted(p.name for p in GOLDEN.glob("eval-6.3-gateB-evasion-match*")) == \
        sorted(MATCHES)
    assert round(sum(v[2] for v in MATCHES.values()), 6) == 0.355997  # gate total


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
    assert red["caching"] == {"mode": "on", "ttl": "auto"}
    assert red["prompt_version"] == "2" and red["system_prompt_sha256"] == V2_SHA  # D40
    assert red["request"]["timeout_s"] == 180
    assert blue["model"] == "claude-haiku-5-5" and blue["rules"]["mode"] == "on"
    assert blue["library"]["sha256"] == LIB_V5_SHA
    assert hashlib.sha256((d / "library.json").read_bytes()).hexdigest() == LIB_V5_SHA
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]  # nothing changed since the match froze
    assert set(p.name for p in d.iterdir()) == set(m["artifacts"]) | {"README.md", "match.json"}
    red_calls = [c for c in rows(d / "api_calls.jsonl") if c["agent"] == "red"]
    assert all(c["rate_window"] in ("peak", "off_peak") for c in red_calls)  # D39
    cut = sum(c.get("stop_reason") == "max_tokens" for c in red_calls)
    assert cut == (1 if name.endswith("match2") else 0)  # one reply hit 8192 (match 2, r5)
    assert not any(c.get("stop_reason") == "refusal" for c in red_calls)  # not refused


def test_prompt_v2_is_the_committed_directive():
    from red import ai_red
    assert ai_red.RED_PROMPT_SHA256["2"] == V2_SHA


def test_the_matches_are_registered_test_data():
    ts = json.loads((REPO / "config" / "test_set.json").read_text())
    assert {v[0] for v in MATCHES.values()} <= set(ts["match_ids"])


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_the_audit_covers_every_red_round(name):
    mid = MATCHES[name][0]
    reds = rows(GOLDEN / name / "red_attacks.jsonl")
    audit = rows(GOLDEN / "audits" / f"{mid}.jsonl")
    assert sorted(a["round"] for a in audit) == sorted(r["round"] for r in reds)  # D36: FULL
