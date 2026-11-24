"""stats/test_data.py (D59): folders are classified by manifest, never by name. Synthetic
folders and a synthetic registry only; no real test-set folder is opened."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from llm_fakes import REPO  # noqa: F401  (puts the repo on sys.path)
from stats import test_data as td

TEST_ID = "20261119T180616Z-a388"
OTHER_ID = "20261124T010101Z-0001"


@pytest.fixture
def registry(tmp_path) -> td.Registry:
    p = tmp_path / "test_set.json"
    p.write_text(json.dumps({"match_ids": [TEST_ID], "test_purposes": ["eval"],
                             "sealed": [{"path": "benign/holdout_v1.jsonl"}]}))
    return td.load_registry(p)


def match(root: Path, name: str, match_id: str | None, purpose: str = "dev") -> Path:
    d = root / name
    d.mkdir(parents=True)
    m = {"purpose": purpose}
    if match_id is not None:
        m["match_id"] = match_id
    (d / "match.json").write_text(json.dumps(m))
    return d


def replay(root: Path, name: str, source_id: str) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "replay.json").write_text(json.dumps({"replay_id": name,
                                               "source": {"match_id": source_id}}))
    return d


def test_slip_reproduced_golden_name_with_registered_id_is_test(tmp_path, registry):
    d = match(tmp_path, "eval-6.3-gateB-freeplay-match1", TEST_ID)
    v = td.classify(d, registry)
    assert v.kind == td.TEST and v.match_id == TEST_ID


def test_match_id_shaped_name_is_not_trusted(tmp_path, registry):
    # named like the registered id, but the manifest says otherwise -> manifest wins
    d = match(tmp_path, TEST_ID, OTHER_ID)
    assert td.classify(d, registry).kind == td.NOT_TEST


def test_eval_purpose_is_test_even_if_unregistered(tmp_path, registry):
    d = match(tmp_path, "incident", OTHER_ID, purpose="eval")
    v = td.classify(d, registry)
    assert v.kind == td.TEST and "D35" in v.reason


def test_replays_follow_their_source(tmp_path, registry):
    assert td.classify(replay(tmp_path, "r1", TEST_ID), registry).kind == td.TEST
    assert td.classify(replay(tmp_path, "r2", OTHER_ID), registry).kind == td.NOT_TEST


@pytest.mark.parametrize("content", [None, "{not json", "[]", json.dumps({"purpose": "dev"})])
def test_missing_or_bad_manifest_is_unknown(tmp_path, registry, content):
    d = tmp_path / "f"
    d.mkdir()
    if content is not None:
        (d / "match.json").write_text(content)
    assert td.classify(d, registry).kind == td.UNKNOWN


def test_bad_replay_manifest_is_unknown(tmp_path, registry):
    d = tmp_path / "r"
    d.mkdir()
    (d / "replay.json").write_text(json.dumps({"source": {}}))
    assert td.classify(d, registry).kind == td.UNKNOWN


def test_scannable_skips_test_and_unknown_by_default(tmp_path, registry):
    ok = match(tmp_path, "a", OTHER_ID)
    folders = [ok, match(tmp_path, "b", TEST_ID), match(tmp_path, "c", "x", purpose="eval"),
               tmp_path / "probe"]
    (tmp_path / "probe").mkdir()
    plan = td.scannable(folders, registry)
    assert plan.folders == [ok]
    assert plan.skipped == {td.TEST: 2, td.UNKNOWN: 1}
    plan = td.scannable(folders, registry, allow_unknown=True)
    assert plan.folders == [ok, tmp_path / "probe"]
    assert plan.skipped == {td.TEST: 2, td.UNKNOWN: 0}


def test_only_manifests_are_opened(tmp_path, registry, monkeypatch):
    d = match(tmp_path, "eval-folder", TEST_ID)
    (d / "api_calls.jsonl").write_text("{}\n")
    real_open = builtins.open
    opened = []

    def spy(file, *a, **k):
        opened.append(Path(file).name)
        return real_open(file, *a, **k)
    monkeypatch.setattr(builtins, "open", spy)
    monkeypatch.setattr(Path, "open", lambda self, *a, **k: spy(self, *a, **k))
    td.scannable([d], registry)
    assert opened and set(opened) <= {"match.json", "replay.json"}


def test_is_sealed(registry):
    assert td.is_sealed("benign/holdout_v1.jsonl", registry)
    assert td.is_sealed(td.REPO / "benign" / "holdout_v1.jsonl", registry)
    assert not td.is_sealed("benign/benign_set.json", registry)


def test_real_registry_loads():
    reg = td.load_registry()
    assert reg.match_ids and "eval" in reg.test_purposes
