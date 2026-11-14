"""run_match / run_traffic with AI Red (Stage 5.6). The driver loop (guard, send,
feedback, red_unsent.jsonl) with stubbed network; the orchestrator wiring (match.json
red_params / models.red, judge_red label_mismatch, cap mid-match). No Docker."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from llm_fakes import CONFIG, PRICES, FakeAdapter, config, lc, make_client
import run_match
from runner import arena_client, match_ops
from runner.schedule import Schedule
from red import ai_red

M = "20261109T153012Z-a1b2"


def attack_json(method="GET", path="/rest/products/search?q=1", body="", label="CWE-89",
                rationale="probe"):
    return json.dumps({"method": method, "path": path, "body": body, "label": label,
                       "rationale": rationale})


def result(text, stop="completed"):
    return lc.Result(ok=True, text=text, usage=lc.Usage(50, 0, 0, 20), attempts=1,
                     stop_reason=stop)


class ScriptClient:
    """A stub body: returns scripted Results; writes no api_calls.jsonl."""

    def __init__(self, results):
        self.results = list(results)

    def complete(self, agent, model, system, messages, **kw):
        return self.results.pop(0) if self.results else result(attack_json())


@pytest.fixture
def no_target(monkeypatch):
    """No Docker: challenge snapshots return empty, and the arena sender is a stub
    that records every request and returns a canned 200."""
    sent: list[dict] = []
    monkeypatch.setattr(match_ops, "solved_now", lambda *a, **k: [])
    monkeypatch.setattr(match_ops, "snapshot_after", lambda before, settle, **k: [])

    def fake_send(method, target, request_id, body=None, timeout=None, **k):
        sent.append({"method": method, "target": target, "request_id": request_id,
                     "body": body})
        return arena_client.Response(200, body_text="OK")
    monkeypatch.setattr(arena_client, "send", fake_send)
    return sent


# ---- the driver loop --------------------------------------------------------

def test_driver_sends_guards_brain_and_feeds_back(no_target, tmp_path):
    client = ScriptClient([
        result(attack_json(label="CWE-89")),                       # 1 sent
        result(attack_json(path="http://evil/x", label="CWE-22")),  # 2 guard: scope
        result("not json"),                                        # 3 brain: invalid_json
        result(attack_json(path="/rest/x", label="CWE-79")),        # 4 sent
    ])
    red = ai_red.AIRed(client, "gpt-6-luna", tmp_path, M, round_cap=4)
    driver = match_ops.AIDriver(red)
    schedule = Schedule(4, [], 1)
    results = match_ops.run_traffic(M, tmp_path, [], [], schedule, settle=0,
                                    log=lambda *a: None, red_driver=driver)

    attacks = [json.loads(l) for l in (tmp_path / "red_attacks.jsonl").read_text().splitlines()]
    assert [a["label"] for a in attacks] == ["CWE-89", "CWE-79"]
    assert all(a["schema_version"] == "0.2" and a["source"] == "ai" and a["rationale"]
               for a in attacks)
    assert [s["target"] for s in no_target] == ["/rest/products/search?q=1", "/rest/x"]
    assert all("X-Arena-Request-Id" not in str(s) for s in no_target)  # header added by client

    guard = [json.loads(l) for l in (tmp_path / "red_unsent.jsonl").read_text().splitlines()]
    assert [(g["kind"], g["reason"]) for g in guard] == [
        ("guard_block", "scope_violation"), ("brain_failure", "invalid_json")]
    assert guard[0]["proposed"]["label"] == "CWE-22" and guard[0]["round"] == 2
    assert guard[1]["proposed"] is None
    # Every slot consumed a round; sent ones are rounds 1 and 4.
    assert [a["round"] for a in attacks] == [1, 4]
    kinds = [r["kind"] for r in results]
    assert kinds.count("red") == 2 and kinds.count("red_no_send") == 2


def test_cap_reached_midmatch_then_instrument_failures_and_benign_continues(no_target, tmp_path):
    cfg = config(red={"max_calls": 1})
    cfg["agents"]["red"].update(provider="fake", model="fake-small")
    client, _ = make_client(FakeAdapter(text=attack_json()), cfg=cfg)
    red = ai_red.AIRed(client, "fake-small", tmp_path, M, round_cap=3)
    driver = match_ops.AIDriver(red)
    benign = [{"benign_id": "n01", "category": "normal", "method": "GET",
               "endpoint": "/rest/products/search", "query_params": {"q": "apple"},
               "expected_solves": [], "note": "x"}]
    # Interleave is seeded; whatever the order, benign must all be sent and red capped.
    schedule = Schedule(3, ["n01"], 7)
    match_ops.run_traffic(M, tmp_path, [], benign, schedule, settle=0,
                          log=lambda *a: None, red_driver=driver)
    guard = [json.loads(l) for l in (tmp_path / "red_unsent.jsonl").read_text().splitlines()]
    # First red call succeeds (cap 1), the rest are refused -> instrument failures.
    insts = [g for g in guard if g["kind"] == "instrument_failure"]
    assert insts and all(g["reason"] == "refused_by_body" for g in insts)
    benign_rows = (tmp_path / "benign_requests.jsonl").read_text().splitlines()
    assert len(benign_rows) == 1  # benign still sent despite the Red cap
    calls = [json.loads(l) for l in (tmp_path / lc.API_CALLS).read_text().splitlines()]
    assert sum(c["refusal"] is not None for c in calls) == len(insts)


# ---- orchestrator wiring (simulated traffic) --------------------------------

def fake_config():
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["red"].update(provider="fake", model="fake-small", round_cap=2,
                                request={"effort": "low"})
    return cfg


SIM_RED = [  # (request_id, round, label, path, newly_solved)
    ("11111111-1111-4111-8111-111111111111", 1, "CWE-89", "/rest/user/login", ["Login Admin"]),
    # round 2 labeled CWE-79 but solves a CWE-22 challenge -> label_mismatch
    ("22222222-2222-4222-8222-222222222222", 2, "CWE-79", "/ftp/x", ["Poison Null Byte"]),
]
SIM_GUARD = [{"kind": "guard_block", "reason": "above_root", "detail": "climbs out",
              "proposed": {"method": "GET", "path": "/../x", "body": "", "label": "CWE-22",
                           "rationale": "t"}}]


class AIRedSimOps(run_match.Ops):
    """Fake Ops: AI config + simulated AI-Red traffic (no real loop, no Docker)."""

    def __init__(self, live):
        self.live = live
        self.calls: list[str] = []

    def preflight(self):
        return {"juice_shop": {"image": "x:1", "image_id": "sha256:" + "b" * 64,
                               "repo_digest": None},
                "nginx": {"image": "x:1", "image_id": "sha256:" + "b" * 64,
                          "repo_digest": None}}

    def git_info(self):
        return {"commit": "f" * 40, "dirty": False}

    def llm_setup(self):
        from stats import cost as cost_stats
        return fake_config(), PRICES, cost_stats.price_table_ref()

    def red_client(self, config, prices):
        self.calls.append("red_client")
        return make_client(FakeAdapter(text=attack_json()), cfg=config)[0]

    def reset(self):
        return 0

    def rotate(self, live_dir):
        return match_ops.rotate_proxy_log(live_dir, reopen=self._reopen(live_dir),
                                          poll_timeout=0.1)

    def _reopen(self, live_dir):
        return lambda: (live_dir / "proxy.jsonl").touch()

    def traffic(self, match_id, match_dir, attacks, benign_entries, schedule, settle,
                red_driver=None):
        self.calls.append("traffic")
        for name in ("benign_requests.jsonl",):
            (match_dir / name).write_text("", encoding="utf-8")
        with (match_dir / "red_attacks.jsonl").open("w") as ra, \
                (match_dir / "challenge_snapshots.jsonl").open("w") as snap, \
                (match_dir / match_ops.RED_UNSENT).open("w") as guard, \
                (self.live / "proxy.jsonl").open("a") as proxy:
            for rid, rnd, label, path, newly in SIM_RED:
                ra.write(json.dumps(ai_red.red_record(
                    {"method": "GET", "path": path, "body": "", "label": label,
                     "rationale": "r"}, rid, match_id, rnd)) + "\n")
                proxy.write(json.dumps({"timestamp": "2026-11-09T00:00:00Z", "request_id": rid,
                                        "method": "GET", "path": path, "query": "", "body": "",
                                        "status": 200}) + "\n")
                snap.write(json.dumps({"request_id": rid, "traffic": "red",
                                       "before_solved": [], "after_solved": newly,
                                       "taken_at": "2026-11-09T00:00:01Z"}) + "\n")
            for g in SIM_GUARD:
                guard.write(json.dumps({"schema_version": "0.1", "match_id": match_id,
                                        "round": 3, "timestamp": "2026-11-09T00:00:02Z",
                                        **g}) + "\n")

    def freeze(self, live_dir, match_dir):
        match_ops.freeze_proxy_log(live_dir, match_dir, reopen=self._reopen(live_dir),
                                   poll_timeout=0.1)

    def reopen(self, live_dir):
        match_ops.reopen_and_confirm(live_dir, reopen=self._reopen(live_dir), poll_timeout=0.1)


@pytest.fixture
def dirs(tmp_path):
    live = tmp_path / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text("")
    return live, tmp_path / "runs"


def test_ai_red_match_records_red_params_and_label_mismatch(dirs):
    live, runs = dirs
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=AIRedSimOps(live), live_dir=live, runs_dir=runs,
                                          red_engine="ai", out=out.append)
    assert code == 0, "\n".join(out)
    m = json.loads((match_dir / "match.json").read_text())
    assert m["schema_version"] == "0.7" and run_match.validate_manifest(m) == []
    assert m["red_engine"] == "ai" and m["red_source"] is None
    assert m["models"]["red"] == {"provider": "fake", "model": "fake-small"}
    assert m["red_params"]["model"] == "fake-small" and m["red_params"]["round_cap"] == 2
    assert m["red_params"]["request"]["reasoning_effort"] == "low"
    anomalies = [json.loads(l) for l in (match_dir / "anomalies.jsonl").read_text().splitlines()]
    mism = [a for a in anomalies if a["kind"] == "label_mismatch"]
    assert len(mism) == 1 and mism[0]["detail"]["round"] == 2
    assert mism[0]["detail"]["conflicts"][0]["mapped_cwe"] == "CWE-22"
    flat = " ".join(" ".join(out).split())
    assert "red=ai" in flat and "attacks sent 2" in flat and "guard blocks 1" in flat
    assert "red_unsent.jsonl" in m["artifacts"]


def test_no_red_model_is_refused_at_preflight(dirs):
    live, runs = dirs

    class NoModel(AIRedSimOps):
        def llm_setup(self):
            cfg, prices, ref = super().llm_setup()
            cfg["agents"]["red"]["model"] = None
            return cfg, prices, ref
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=NoModel(live), live_dir=live, runs_dir=runs,
                                          red_engine="ai", out=out.append)
    assert (code, match_dir) == (2, None) and "no Red model" in "\n".join(out)


def test_cli_flags_red(monkeypatch):
    seen = {}
    monkeypatch.setattr(run_match, "run_match", lambda **kw: (seen.update(kw), (0, None))[1])
    assert run_match.main(["--red", "ai", "--red-model", "gpt-6-luna"]) == 0
    assert seen["red_engine"] == "ai" and seen["red_model"] == "gpt-6-luna"
