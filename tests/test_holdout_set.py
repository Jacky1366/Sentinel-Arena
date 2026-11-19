"""The offline benign data (Stage 6.1, M4, D27, D31): the drafts are valid, sized and
composed as planned, disjoint from each other and from everything sent in a match;
tools/build_holdout.py captures VERBATIM from the logged lines and seals with exclusive
creates (mocked sender + log: no Docker, no network); --check detects drift; nothing that
sends match traffic references the offline files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_fakes import REPO
from red.scripted_red import request_target  # noqa: E402
from tools import build_holdout as bh  # noqa: E402


def entries(name):
    return bh.load_draft(name)["entries"]


def test_holdout_size_and_composition():
    e = entries("holdout_v1")
    assert len(e) == 40
    by = {}
    for x in e:
        k = x["look_alike"] or "normal"
        by[k] = by.get(k, 0) + 1
    assert by == {"normal": 12, "CWE-89": 9, "CWE-79": 9, "CWE-22": 10}


def test_fixture_v2_is_cwe22_look_alikes_only():
    e = entries("fixture_v2_offline")
    assert len(e) == 6
    assert {x["look_alike"] for x in e} == {"CWE-22"}
    assert all(x["category"] == "hard_negative" and x["benign_id"].startswith("yh") for x in e)


def _sent_requests():
    sent = set()
    for e in json.loads((REPO / "benign" / "benign_set.json").read_text())["entries"]:
        sent.add((e["method"], request_target(e)))
    for line in (REPO / "benign" / "fixture_v1.jsonl").read_text().splitlines():
        f = json.loads(line)
        sent.add((f["method"], f["path"] + (f"?{f['query']}" if f["query"] else "")))
    return sent


def test_offline_sets_are_disjoint_from_each_other_and_from_sent_traffic():
    bh.check_drafts()  # holdout vs fixture v2
    sent = _sent_requests()
    for name in bh.SETS:
        for e in entries(name):
            if e.get("json_body") is None:
                assert (e["method"], request_target(e)) not in sent, e["benign_id"]
    bodies = {json.loads(l)["body"] for l in (REPO / "benign" / "fixture_v1.jsonl")
              .read_text().splitlines()}
    for name in bh.SETS:
        for e in entries(name):
            if e.get("json_body") is not None:
                assert json.dumps(e["json_body"]) not in bodies


def test_no_match_traffic_code_references_the_offline_files():
    for rel in ("benign/send_benign.py", "runner/match_ops.py", "runner/arena_client.py",
                "run_match.py", "blue/run_blue.py", "blue/claude_engine.py"):
        src = (REPO / rel).read_text()
        assert "holdout" not in src and "fixture_v2" not in src, rel


def test_check_passes_before_sealing():
    assert bh.check_sealed() == []


class FakeResp:
    status, body_incomplete = 200, False


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """build_holdout pointed at tmp: benign dir, test_set, live log; sender and Target
    mocked. The sender appends the line nginx would log."""
    benign = tmp_path / "benign"
    benign.mkdir()
    for n in bh.SETS:
        (benign / f"{n}.draft.json").write_bytes(bh.draft_path(n).read_bytes())
    ts = tmp_path / "test_set.json"
    ts.write_bytes(bh.TEST_SET.read_bytes())
    live = tmp_path / "live"
    live.mkdir()
    (live / "proxy.jsonl").write_text("")
    monkeypatch.setattr(bh, "BENIGN", benign)
    monkeypatch.setattr(bh, "TEST_SET", ts)
    monkeypatch.setattr(bh.match_ops, "LIVE", live)
    calls = []
    monkeypatch.setattr(bh.match_ops, "running_images", lambda: {"juice_shop": {}, "nginx": {}})
    monkeypatch.setattr(bh.match_ops, "check_live_clean", lambda d: None)
    monkeypatch.setattr(bh.match_ops, "acquire_lock", lambda d, m: calls.append("lock"))
    monkeypatch.setattr(bh.match_ops, "release_lock", lambda d: calls.append("unlock"))
    monkeypatch.setattr(bh.match_ops, "reset_target", lambda: calls.append("reset") or 0)
    monkeypatch.setattr(bh.match_ops, "rotate_proxy_log", lambda d: calls.append("rotate"))
    monkeypatch.setattr(bh.time, "sleep", lambda s: None)

    def send(method, target, rid, body=None):
        path, _, query = target.partition("?")
        with (live / "proxy.jsonl").open("a") as fh:
            fh.write(json.dumps({"request_id": rid, "method": method, "path": path,
                                 "query": query, "body": body or "", "status": 200}) + "\n")
        return FakeResp()
    monkeypatch.setattr(bh.arena_client, "send", send)
    monkeypatch.setattr(bh, "REPO", tmp_path)
    return tmp_path, benign, ts, calls


def test_capture_seals_verbatim_and_resets_the_target(sandbox):
    tmp_path, benign, ts, calls = sandbox
    assert bh.capture(out=lambda *_: None) == 0
    assert calls[:2] == ["lock", "reset"] and calls[-2:] == ["reset", "unlock"]
    rows = [json.loads(l) for l in (benign / "holdout_v1.jsonl").read_text().splitlines()]
    assert len(rows) == 40 and rows[0]["query"] == "q=orange+juice"
    xh04 = next(r for r in rows if r["benign_id"] == "xh04")
    assert json.loads(xh04["body"])["email"] == "d.o'neil@example.com"
    meta = json.loads((benign / "holdout_v1.meta.json").read_text())
    sealed = {s["path"]: s["sha256"] for s in json.loads(ts.read_text())["sealed"]}
    assert sealed["benign/holdout_v1.jsonl"] == meta["sha256"]
    assert sealed["benign/fixture_v2_offline.jsonl"] is not None
    assert bh.check_sealed() == []
    with pytest.raises(FileExistsError):  # a sealed file is never overwritten
        bh.capture(out=lambda *_: None)


def test_check_detects_drift_after_sealing(sandbox):
    tmp_path, benign, ts, calls = sandbox
    bh.capture(out=lambda *_: None)
    p = benign / "fixture_v2_offline.jsonl"
    p.write_text(p.read_text().replace("minutes", "agenda"))
    assert any("differs" in x for x in bh.check_sealed())


def test_capture_writes_nothing_if_a_line_was_not_logged(sandbox, monkeypatch):
    tmp_path, benign, ts, calls = sandbox
    monkeypatch.setattr(bh.arena_client, "send", lambda *a, **k: FakeResp())  # nothing logged
    with pytest.raises(RuntimeError, match="not logged"):
        bh.capture(out=lambda *_: None)
    assert not (benign / "holdout_v1.jsonl").exists()
    assert calls[-2:] == ["reset", "unlock"]
