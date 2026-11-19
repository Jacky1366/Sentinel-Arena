"""The committed Stage 6.3 Gate B-freeplay evidence (D41, exploratory arm): 3 eval matches
(data/golden/eval-6.3-gateB-freeplay-match{1,2,3}/), their captured challenge catalogs and
their binary audit scaffolds (data/golden/audits/<id>.freeplay.jsonl). TEST data (D35);
this read-only integrity check is the designer's GO'd evidence test: every file matches its
match.json hash, the config is deepseek-v4-pro prompt-v3 (free-play) at effort max / 16384 /
300 s with a $0.40 per-match cap against Haiku + v5, the ids are registered as test data, the
challenge catalog is captured, and the binary audit covers every Red round."""

from __future__ import annotations

import json

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402

GOLDEN = REPO / "data" / "golden"
COMMIT = "fc198fe"
LIB_V5_SHA = "324a1eceace9499606284230f4997cb961da39af6ec67ab2a6d7c4e70a168bc7"
MATCHES = {  # folder -> (match_id, seed, total usd)
    "eval-6.3-gateB-freeplay-match1": ("20261119T180616Z-a388", 6331, 0.025913),
    "eval-6.3-gateB-freeplay-match2": ("20261119T181023Z-2336", 6332, 0.024710),
    "eval-6.3-gateB-freeplay-match3": ("20261119T181410Z-4eb5", 6333, 0.043844),
}


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_the_three_eval_matches_are_committed():
    assert sorted(p.name for p in GOLDEN.glob("eval-6.3-gateB-freeplay-match*")) == sorted(MATCHES)
    assert round(sum(v[2] for v in MATCHES.values()), 6) == 0.094467


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_files_match_their_hashes_and_the_freeplay_protocol(name):
    d = GOLDEN / name
    mid, seed, usd = MATCHES[name]
    m = json.loads((d / "match.json").read_text())
    assert run_match.validate_manifest(m) == []
    assert m["match_id"] == mid and m["purpose"] == "eval" and m["status"] == "completed"
    assert m["git"]["commit"].startswith(COMMIT) and m["git"]["dirty"] is False
    assert m["traffic"]["seed"] == seed and abs(m["cost"]["total_usd"] - usd) < 1e-9
    red = m["red_params"]
    assert red["provider"] == "deepseek" and red["model"] == "deepseek-v4-pro"
    assert red["prompt_version"] == "3" and red["request"]["reasoning_effort"] == "max"
    assert red["request"]["max_output_tokens"] == 16384 and red["request"]["timeout_s"] == 300
    assert m["budget"]["limits"]["red"]["max_usd"] == 0.40
    assert m["budget"]["limits"]["match"]["max_usd"] == 0.40
    assert m["blue_params"]["model"] == "claude-haiku-5-5"
    assert m["blue_params"]["library"]["sha256"] == LIB_V5_SHA
    assert m["blue_params"]["prompt_version"] == "2"  # Blue prompt unchanged (rules on)
    cat = json.loads((d / "challenge_catalog.json").read_text())
    assert cat and all(isinstance(v, str) for v in cat.values())
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]
    assert set(p.name for p in d.iterdir()) == set(m["artifacts"]) | {"README.md", "match.json"}


def test_the_matches_are_registered_test_data():
    ts = json.loads((REPO / "config" / "test_set.json").read_text())
    assert {v[0] for v in MATCHES.values()} <= set(ts["match_ids"])


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_the_binary_audit_covers_every_red_round(name):
    mid = MATCHES[name][0]
    reds = rows(GOLDEN / name / "red_attacks.jsonl")
    audit = rows(GOLDEN / "audits" / f"{mid}.freeplay.jsonl")
    assert sorted(a["round"] for a in audit) == sorted(r["round"] for r in reds)  # D36 full
    assert all(a["attack_attempt"] == "unaudited" for a in audit)
