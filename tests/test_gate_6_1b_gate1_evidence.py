"""The committed Stage 6.1b Gate 1 evidence: the 5 train matches
(data/golden/train-6.1b-gate1-match{1..5}/), their D30 audits (data/audits/), the rule
library versions v0000..v0005 and the retention evidence (data/library/). AI output is not
reproducible, so it is preserved and checked: every match file matches its match.json hash,
the configuration is the D28 train protocol, every audited source round is valid, every
retention file matches the hash its retention.json recorded, and the committed library v5
has the sha256 recorded in docs/progress.md before the Gate 2 GO."""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402
from rules import library as rule_library  # noqa: E402

GOLDEN = REPO / "data" / "golden"
LIB = REPO / "data" / "library"
COMMIT = "a8d7969505edb32ef7e432d6e3a8c2c80f46f37b"
MATCHES = {  # folder -> (match_id, seed, total usd, rules stored, retained, rejected)
    "train-6.1b-gate1-match1": ("20261119T005133Z-0b84", 6101, 0.004369, 4, 4, 0),
    "train-6.1b-gate1-match2": ("20261119T005410Z-4ed0", 6102, 0.002463, 4, 3, 1),
    "train-6.1b-gate1-match3": ("20261119T005624Z-dc00", 6103, 0.002751, 5, 5, 0),
    "train-6.1b-gate1-match4": ("20261119T005846Z-37ca", 6104, 0.003171, 8, 5, 3),
    "train-6.1b-gate1-match5": ("20261119T010114Z-500b", 6105, 0.002534, 5, 2, 3),
}


def sha(p) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_the_five_train_matches_are_committed():
    assert sorted(p.name for p in GOLDEN.glob("train-6.1b-gate1-match*")) == sorted(MATCHES)
    assert abs(sum(v[2] for v in MATCHES.values()) - 0.015288) < 1e-6  # Gate 1 total


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_files_match_their_hashes_and_the_train_protocol(name):
    d = GOLDEN / name
    mid, seed, usd, n_rules, _, _ = MATCHES[name]
    m = json.loads((d / "match.json").read_text())
    assert run_match.validate_manifest(m) == []
    assert m["schema_version"] == "0.8" and m["match_id"] == mid and m["purpose"] == "train"
    assert m["status"] == "completed" and m["git"] == {"commit": COMMIT, "dirty": False}
    assert m["traffic"]["seed"] == seed and m["judge_version"] == "0.7.0"
    assert m["red_engine"] == "ai" and m["blue_engine"] == "claude"
    assert m["blue_params"]["rules"]["mode"] == "on" and m["blue_params"]["library"] is None
    assert abs(m["cost"]["total_usd"] - usd) < 1e-9
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]  # nothing changed since the match froze
    assert set(p.name for p in d.iterdir()) == set(m["artifacts"]) | {"README.md", "match.json"}
    assert len(rows(d / "rules.jsonl")) == n_rules
    test_ids = json.loads((REPO / "config" / "test_set.json").read_text())["match_ids"]
    assert mid not in test_ids  # TRAIN data (S6-1)


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_every_candidate_source_round_is_audited_valid(name):
    mid = MATCHES[name][0]
    d = GOLDEN / name
    red = {a["request_id"]: a["round"] for a in rows(d / "red_attacks.jsonl")}
    sources = sorted(red[r["rule"]["source_request_id"]] for r in rows(d / "rules.jsonl"))
    audit = rows(REPO / "data" / "audits" / f"{mid}.jsonl")
    assert sorted(a["round"] for a in audit) == sources  # D30 scope, exactly
    assert all(a["verdict"] == "valid" and a["auditor"] == "designer" for a in audit)


@pytest.mark.parametrize("name", sorted(MATCHES))
def test_retention_evidence_matches_its_manifest(name):
    mid, _, _, n_rules, kept, rejected = MATCHES[name]
    d = LIB / "retention" / mid
    man = json.loads((d / "retention.json").read_text())
    ret = rows(d / "retention.jsonl")
    assert len(ret) == n_rules
    assert sum(r["decision"] == "retained" for r in ret) == kept
    assert sum(r["decision"] == "rejected" for r in ret) == rejected
    blob = json.dumps(man)
    for f in ("retention.jsonl", "variants.jsonl"):
        assert sha(d / f) in blob, f  # the manifest records each output's hash


def test_the_library_chain_v0000_to_v0005_is_committed_and_loads():
    files = sorted(LIB.glob("rule_library_v*.json"))
    assert [p.name for p in files] == [f"rule_library_v{v:04d}.json" for v in range(6)]
    sizes = [len(rule_library.load(p)) for p in files]
    assert sizes == [0, 4, 7, 12, 17, 19]


def test_committed_v5_matches_the_sha256_pre_registered_in_progress():
    text = (REPO / "docs" / "progress.md").read_text(encoding="utf-8")
    m = re.search(r"Library v5 sha256:\s*`([0-9a-f]{64})`", text)
    assert m, "progress.md must record the full v5 sha256"
    assert sha(LIB / "rule_library_v0005.json") == m.group(1)
