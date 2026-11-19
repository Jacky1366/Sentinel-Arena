"""tools/promote_rules.py (Stage 6.1, M1/M2, S6-3, D26, D27, D30): a train match's rules are
promoted into a NEW library version with full retention evidence; every refusal in D26
holds (nothing written); the holdout is never parsed. FakeOps train matches + the fake
provider; every location (library, retention, audits, test set, fixture v2) is in tmp."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
from test_blue_rules import cond, verdict
from test_run_match_rules import RulesOps, dirs  # noqa: F401 (fixture)
from library import writer  # noqa: E402
from rules import library as rule_library  # noqa: E402
from tools import audit_match, promote_rules  # noqa: E402
import run_match  # noqa: E402

MANIFEST = Draft202012Validator(json.loads(
    (REPO / "schemas" / "retention_manifest.schema.json").read_text()))
GOLDEN_IDS = json.loads((REPO / "config" / "test_set.json").read_text())["match_ids"]


def good_brain(view):
    """A rule per attack (SQLi in the login body, XSS in the search query); benign else."""
    if "OR 1=1" in view["body"]:
        return verdict("CWE-89", {"conditions": [cond(field="body", pattern="or 1=1")]})
    if "<script>" in view["query"]:
        return verdict("CWE-79", {"conditions": [cond(field="query", pattern="<script>")]})
    return verdict("benign")


class TrainOps(RulesOps):
    """FakeOps traffic with AI-Red records (0.2, source "ai"), as in a real train match:
    AI labels are what the D30 audit covers."""

    def traffic(self, match_id, match_dir, *a, **kw):
        super().traffic(match_id, match_dir, *a, **kw)
        p = match_dir / "red_attacks.jsonl"
        rows = [json.loads(l) for l in p.read_text().splitlines()]
        p.write_text("".join(json.dumps({**r, "schema_version": "0.2", "source": "ai",
                                         "rationale": "test"}) + "\n" for r in rows))


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class Env:
    def __init__(self, tmp_path, dirs, monkeypatch):
        self.tmp, self.dirs = tmp_path, dirs
        self.lib_dir = tmp_path / "library"
        self.v0 = writer.write(writer.empty_doc("2026-11-20T00:00:00.000Z"), self.lib_dir)
        self.audits = tmp_path / "audits"
        self.golden_audits = tmp_path / "golden_audits"
        self.holdout = tmp_path / "holdout_v1.jsonl"
        self.holdout.write_bytes(b"\x00 not json: selection must never parse the holdout\n")
        self.fx2 = tmp_path / "fixture_v2_offline.jsonl"
        self.fx2.write_text(json.dumps({"benign_id": "yh01", "category": "hard_negative",
                                        "look_alike": "CWE-22", "method": "GET",
                                        "path": "/ftp/minutes..2026.md", "query": "",
                                        "body": ""}) + "\n")
        self.test_set = tmp_path / "test_set.json"
        self.write_test_set()
        monkeypatch.setattr(promote_rules, "FIXTURE_V2", self.fx2)
        ids = iter(f"20261120T0100{i:02d}Z-aaaa" for i in range(100))
        monkeypatch.setattr(run_match, "new_match_id", lambda: next(ids))  # ascending ids
        self.committed = {str(self.holdout): sha(self.holdout), str(self.fx2): sha(self.fx2)}
        monkeypatch.setattr(promote_rules, "git_show_sha256",
                            lambda commit, path: self.committed.get(path))

    def write_test_set(self, match_ids=None, holdout_sha="auto"):
        self.test_set.write_text(json.dumps({
            "schema_version": "0.1", "_comment": "test",
            "match_ids": match_ids or GOLDEN_IDS,
            "sealed": [{"path": str(self.holdout), "role": "test",
                        "sha256": sha(self.holdout) if holdout_sha == "auto" else holdout_sha},
                       {"path": str(self.fx2), "role": "train", "sha256": sha(self.fx2)}]}))

    def train_match(self, answer=good_brain, purpose="train"):
        live, runs = self.dirs
        out: list[str] = []
        code, d = run_match.run_match(ops=TrainOps(live, answer=answer), live_dir=live,
                                      runs_dir=runs, engine="claude", blue_rules_mode="on",
                                      purpose=purpose, out=out.append)
        assert code == 0, out
        return d

    def audit(self, d, verdict_="valid"):
        p = audit_match.scaffold(d, audits=self.audits, golden_dir=self.golden_audits)
        rows = [json.loads(l) for l in p.read_text().splitlines()]
        for r in rows:
            r.update(verdict=verdict_, reason="test", auditor="designer", date="2026-11-20")
        p.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return p

    def promote(self, d, library=None):
        out: list[str] = []
        code = promote_rules.promote(d, library or self.latest(), 0, library_dir=self.lib_dir,
                                     test_set_path=self.test_set, audits=self.audits,
                                     golden_audits=self.golden_audits, out=out.append)
        return code, "\n".join(out)

    def latest(self) -> Path:
        return sorted(self.lib_dir.glob("rule_library_v*.json"))[-1]


@pytest.fixture
def env(tmp_path, dirs, monkeypatch):
    return Env(tmp_path, dirs, monkeypatch)


def test_promotion_writes_a_new_version_with_its_evidence(env):
    d = env.train_match()
    env.audit(d)
    v0_bytes = env.v0.read_bytes()
    code, out = env.promote(d)
    assert code == 0, out
    mid = json.loads((d / "match.json").read_text())["match_id"]
    lib = rule_library.load(env.lib_dir / "rule_library_v0001.json")
    assert [e.library_id for e in lib.entries] == ["lib-0001", "lib-0002"]
    assert env.v0.read_bytes() == v0_bytes  # the parent is never touched
    rdir = env.lib_dir / "retention" / mid
    rows = [json.loads(l) for l in (rdir / "retention.jsonl").read_text().splitlines()]
    assert [r["decision"] for r in rows] == ["retained", "retained"]
    assert all(r["variants_blocked"] for r in rows)
    m = json.loads((rdir / "retention.json").read_text())
    MANIFEST.validate(m)
    assert m["summary"]["retained"] == 2 and m["match"]["purpose"] == "train"
    assert m["outputs"]["library"]["library_version"] == 1
    assert (rdir / "variants.jsonl").read_text()
    doc = json.loads((env.lib_dir / "rule_library_v0001.json").read_text())
    assert doc["promoted_matches"] == [mid]
    assert {f["sha256"] for f in doc["fixtures"]} >= {sha(env.fx2)}
    assert "lib-0001" in out


def test_a_second_train_match_dedups_against_the_library(env):
    d1 = env.train_match()
    env.audit(d1)
    assert env.promote(d1)[0] == 0
    d2 = env.train_match()
    env.audit(d2)
    code, out = env.promote(d2)
    assert code == 0, out
    lib = rule_library.load(env.lib_dir / "rule_library_v0002.json")
    assert len(lib) == 2  # nothing new: exact duplicates
    mid2 = json.loads((d2 / "match.json").read_text())["match_id"]
    rows = [json.loads(l) for l in (env.lib_dir / "retention" / mid2 / "retention.jsonl")
            .read_text().splitlines()]
    assert [r["duplicate_of"] for r in rows] == ["lib-0001", "lib-0002"]
    assert env.promote(d2)[0] == 2  # already promoted / retention dir exists


def test_rejections_are_recorded_never_deleted(env):
    def broad(view):
        return verdict("CWE-89", {"conditions": [cond(field="path", pattern="/rest")]})
    d = env.train_match(answer=broad)
    env.audit(d)
    code, out = env.promote(d)
    assert code == 0, out
    mid = json.loads((d / "match.json").read_text())["match_id"]
    rows = [json.loads(l) for l in (env.lib_dir / "retention" / mid / "retention.jsonl")
            .read_text().splitlines()]
    assert rows and all(r["decision"] == "rejected" for r in rows)
    assert any(x["code"] == "fixture_hit" for r in rows for x in r["reasons"])
    assert len(rule_library.load(env.latest())) == 0
    assert (d / "rules.jsonl").read_text()  # the match's own evidence is untouched


def test_an_invalid_source_label_is_rejected(env):
    d = env.train_match()
    env.audit(d, "invalid")
    assert env.promote(d)[0] == 0
    assert len(rule_library.load(env.latest())) == 0


# ---- refusals (exit 2, nothing written) -------------------------------------------

def _nothing_written(env):
    assert sorted(p.name for p in env.lib_dir.iterdir()) == ["rule_library_v0000.json"]


def test_refuses_a_dev_match(env):
    d = env.train_match(purpose="dev")
    code, out = env.promote(d)
    assert code == 2 and "purpose 'dev'" in out
    _nothing_written(env)


@pytest.mark.parametrize("name", ["scripted-baseline-match", "claude-blue-haiku-first-match",
                                  "scripted-baseline-benign-match"])  # non-test folders
def test_refuses_every_golden_match(env, name):
    code, out = env.promote(REPO / "data" / "golden" / name)
    assert code == 2 and "data/golden" in out
    _nothing_written(env)


def test_refuses_a_replay_folder(env, tmp_path):
    (tmp_path / "rep").mkdir()
    (tmp_path / "rep" / "replay.json").write_text("{}")
    code, out = env.promote(tmp_path / "rep")
    assert code == 2 and "replay" in out


def test_refuses_a_test_set_match_id(env):
    d = env.train_match()
    env.audit(d)
    env.write_test_set(match_ids=[json.loads((d / "match.json").read_text())["match_id"]])
    code, out = env.promote(d)
    assert code == 2 and "test data" in out
    _nothing_written(env)


def test_refuses_before_the_seal_and_a_match_older_than_it(env):
    d = env.train_match()
    env.audit(d)
    env.write_test_set(holdout_sha=None)
    code, out = env.promote(d)
    assert code == 2 and "not sealed yet" in out
    env.write_test_set()
    env.committed.clear()  # the sealed files are not in the match's commit
    code, out = env.promote(d)
    assert code == 2 and "predates the seal" in out
    _nothing_written(env)


def test_refuses_a_dirty_or_changed_match(env):
    d = env.train_match()
    env.audit(d)
    m = json.loads((d / "match.json").read_text())
    (d / "rules.jsonl").write_text((d / "rules.jsonl").read_text() + "\n")
    code, out = env.promote(d)
    assert code == 2 and "rules.jsonl" in out
    m["git"]["dirty"] = True
    (d / "match.json").write_text(json.dumps(m))
    code, out = env.promote(d)
    assert code == 2 and "dirty" in out
    _nothing_written(env)


def test_refuses_without_a_complete_audit(env):
    d = env.train_match()
    code, out = env.promote(d)
    assert code == 2 and "no audit" in out
    audit_match.scaffold(d, audits=env.audits, golden_dir=env.golden_audits)  # unaudited
    code, out = env.promote(d)
    assert code == 2 and "unaudited" in out
    _nothing_written(env)


def test_refuses_an_older_parent(env):
    d1 = env.train_match()
    env.audit(d1)
    assert env.promote(d1)[0] == 0
    d2 = env.train_match()
    env.audit(d2)
    code, out = env.promote(d2, library=env.v0)
    assert code == 2 and "already exists" in out


def test_audit_scope_of_a_train_match_is_the_candidate_source_rounds(env):
    d = env.train_match()
    assert audit_match.audit_scope(d) == {1, 2}
    p = env.audit(d)
    assert [json.loads(l)["round"] for l in p.read_text().splitlines()] == [1, 2]
    sheet = audit_match.sheet([d], audits=env.audits, golden=env.golden_audits)
    assert "candidate source rounds only [1, 2] (D30)" in sheet
    dev = env.train_match(answer=lambda v: verdict("benign"), purpose="dev")
    assert audit_match.audit_scope(dev) is None
