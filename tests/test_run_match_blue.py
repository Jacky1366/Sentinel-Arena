"""run_match.py --blue claude (Stage 5.4): wiring, match.json 0.4 blue_params,
stops and refusals. FakeOps (no Docker) + the fake provider only: no real adapter
is ever reachable (FakeOps.blue_client registers only the fake adapter)."""

from __future__ import annotations

import copy
import json

import pytest

from llm_fakes import CONFIG, PRICES, lc
from test_run_match_failure import (ATTACKS, BENIGN, PREVIOUS, FakeOps, assert_finalized,
                                    manifest_of, run_match)
from blue import claude_engine  # noqa: E402
from stats import cost as cost_stats  # noqa: E402

VERDICTS = '{"verdicts": [{"index": 1, "label": "CWE-89", "rationale": "tautology"}]}'


@pytest.fixture
def dirs(tmp_path):
    live = tmp_path / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text(PREVIOUS)
    return live, tmp_path / "runs"


def fake_config(**blue):
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["blue"].update(blue.pop("agent", {}))
    cfg["caps"]["blue"].update(blue)
    return cfg


class ClaudeOps(FakeOps):
    """Fake provider config + prices; replies scripted per call."""

    def __init__(self, live, cfg=None, replies=None, **kw):
        super().__init__(live, benign=BENIGN, **kw)
        self.cfg = cfg or fake_config()
        self.replies = list(replies or [])

    def llm_setup(self):
        return self.cfg, PRICES, cost_stats.price_table_ref()

    def blue_client(self, config, prices):
        ops = self

        class Scripted:
            provider, needs_key = "fake", False

            def call(self, **kw):
                text, stop = ops.replies.pop(0) if ops.replies else (VERDICTS, "end_turn")
                return lc.Reply(text=text, usage=lc.Usage(100, 0, 0, 10), stop_reason=stop)
        self.calls.append("blue_client")
        return lc.LLMClient(config=config, prices=prices, adapters={"fake": Scripted()},
                            env={}, sleep=lambda s: None)


def go(ops, dirs, **kw):
    live, runs = dirs
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=ops, live_dir=live, runs_dir=runs,
                                          engine="claude", out=out.append, **kw)
    return code, match_dir, "\n".join(out)


def rows(match_dir, name):
    return [json.loads(l) for l in (match_dir / name).read_text().splitlines()]


def test_claude_match_completes_and_records_blue_params(dirs):
    code, match_dir, out = go(ClaudeOps(dirs[0]), dirs)
    assert code == 0, out
    m = assert_finalized(dirs[0], match_dir)
    assert m["schema_version"] == "0.4" and m["blue_engine"] == "claude"
    assert m["models"]["blue"] == {"provider": "fake", "model": "fake-small"}
    assert m["blue_params"] == claude_engine.blue_params(CONFIG, "fake-small", 1)
    assert m["blue_params"]["sdk"] is None and m["blue_params"]["chunk_size"] == 1
    v = rows(match_dir, "verdicts.jsonl")
    assert len(v) == 4 and {r["source"] for r in v} == {"ai"}
    calls = rows(match_dir, "api_calls.jsonl")
    assert [c["log_seq_first"] for c in calls] == [1, 2, 3, 4]
    assert m["cost"]["attempts"] == 4 and "api_calls.jsonl" in m["artifacts"]
    rounds = rows(match_dir, "rounds.jsonl")
    assert all(r["verdict_source"] == "ai" and r["detected"] is True for r in rounds)
    flat = " ".join(out.split())
    assert "blue=claude" in flat and "model refusals attack 0 benign 0" in flat


def test_every_call_refused_is_stopped_exit_4_with_stats(dirs):
    code, match_dir, out = go(ClaudeOps(dirs[0], cfg=fake_config(max_calls=0)), dirs)
    assert code == 4, out
    m = manifest_of(match_dir)
    assert m["status"] == "stopped"
    assert m["budget"]["stopped_by"] == {"scope": "blue", "reason": "max_calls"}
    v = rows(match_dir, "verdicts.jsonl")
    assert {(r["no_verdict_reason"], r["failure_detail"]) for r in v} == \
        {("instrument_failure", "refused_by_body")}
    assert len(rows(match_dir, "api_calls.jsonl")) == 1  # Blue stopped after the first
    assert {r["detected_reason"] for r in rows(match_dir, "rounds.jsonl")} == \
        {"instrument_failure"}
    flat = " ".join(out.split())
    assert "detection 0/0 (n/a) FP rate 0/0 (n/a)" in flat
    assert "STOPPED by the AI budget: blue max_calls" in flat


def test_refusal_mid_match_scores_earlier_lines(dirs):
    code, match_dir, out = go(ClaudeOps(dirs[0], cfg=fake_config(max_calls=2)), dirs)
    assert code == 4
    v = rows(match_dir, "verdicts.jsonl")
    assert [r["verdict"] for r in v] == ["CWE-89", "CWE-89", None, None]
    assert "instr. failure" in out


def test_model_refusals_are_counted_by_traffic(dirs):
    # Schedule order is seeded; refuse every call and count by traffic kind.
    replies = [("", "refusal")] * 4
    code, match_dir, out = go(ClaudeOps(dirs[0], replies=replies), dirs)
    assert code == 0  # a model refusal is a brain failure, not a body stop
    v = rows(match_dir, "verdicts.jsonl")
    assert {r["failure_detail"] for r in v} == {"model_refusal"}
    assert "model refusals attack 2 benign 2" in " ".join(out.split())
    assert {r["detected_reason"] for r in rows(match_dir, "rounds.jsonl")} == {"no_verdict"}


def test_chunk_size_above_one_is_refused_at_preflight(dirs):
    code, match_dir, out = go(ClaudeOps(dirs[0], cfg=fake_config(agent={"chunk_size": 2})),
                              dirs)
    assert (code, match_dir) == (2, None) and "D4" in out


def test_no_blue_model_is_refused_at_preflight(dirs):
    code, match_dir, out = go(ClaudeOps(dirs[0], cfg=fake_config(agent={"model": None})),
                              dirs)
    assert (code, match_dir) == (2, None) and "no Blue model" in out


def test_blue_model_override_reaches_the_calls_and_manifest(dirs):
    prices = copy.deepcopy(PRICES)
    prices["models"]["fake-other"] = copy.deepcopy(prices["models"]["fake-small"])

    class Ops(ClaudeOps):
        def llm_setup(self):
            return self.cfg, prices, cost_stats.price_table_ref()
    code, match_dir, out = go(Ops(dirs[0]), dirs, blue_model="fake-other")
    assert code == 0, out
    m = manifest_of(match_dir)
    assert m["models"]["blue"]["model"] == m["blue_params"]["model"] == "fake-other"
    assert {c["model"] for c in rows(match_dir, "api_calls.jsonl")} == {"fake-other"}


def test_fake_ops_with_the_real_config_can_never_reach_a_provider(dirs):
    # Real config names anthropic; FakeOps.blue_client has only the fake adapter,
    # so the Blue step fails instead of making a real call.
    live, runs = dirs
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=FakeOps(live), live_dir=live, runs_dir=runs,
                                          engine="claude", out=out.append)
    m = manifest_of(match_dir)
    assert code == 1 and m["failed_step"] == "blue" and "no adapter" in m["error"]
    assert not (match_dir / "api_calls.jsonl").exists()


def test_cli_flag_is_blue(monkeypatch):
    seen = {}
    monkeypatch.setattr(run_match, "run_match", lambda **kw: (seen.update(kw), (0, None))[1])
    assert run_match.main(["--blue", "claude", "--blue-model", "m"]) == 0
    assert seen["engine"] == "claude" and seen["blue_model"] == "m"
    with pytest.raises(SystemExit):
        run_match.main(["--engine", "scripted"])
