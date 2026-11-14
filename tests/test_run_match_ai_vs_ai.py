"""run_match.py --red ai --blue claude (Stage 5.7): AI vs AI with Blue rules mode on and
prompt caching selectable for both agents. FakeOps (no Docker) + the fake provider only:
no real adapter is reachable. Also: the four-facts check in the summary, and the
Stage 5.7 gate tools' offline paths (they refuse without --real-calls)."""

from __future__ import annotations

import copy
import json

import pytest

from llm_fakes import CONFIG, PRICES, REPO, FakeAdapter, lc
from test_blue_rules import Brain
from test_run_match_failure import BENIGN, PREVIOUS, FakeOps, manifest_of, run_match
from test_run_match_rules import broad
from stats import cost as cost_stats  # noqa: E402

RED_REPLY = json.dumps({"method": "GET", "path": "/rest/products/search?q=1", "body": "",
                        "label": "CWE-89", "rationale": "probe"})


def ai_config():
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["red"].update(provider="fake", model="fake-small", round_cap=2,
                                request={"effort": "low"})
    return cfg


class AIvAIOps(FakeOps):
    """FakeOps traffic (2 attacks + 2 benign lines), a fake-provider Red client that is
    really called once by the driver, and a rule-proposing Blue Brain."""

    def __init__(self, live, cfg=None):
        super().__init__(live, benign=BENIGN)
        self.cfg = cfg or ai_config()
        self.brain = Brain(broad)
        self.blue_cache: list[bool] = []
        self.red_adapter = FakeAdapter(text=RED_REPLY)
        self.configs: dict[str, dict] = {}
        inner = self.brain.call

        def spy(**kw):
            self.blue_cache.append(kw["cache"])
            return inner(**kw)
        self.brain.call = spy

    def llm_setup(self):
        return self.cfg, PRICES, cost_stats.price_table_ref()

    def red_client(self, config, prices):
        self.calls.append("red_client")
        self.configs["red"] = config
        return lc.LLMClient(config=config, prices=prices, adapters={"fake": self.red_adapter},
                            env={}, sleep=lambda s: None,
                            dotenv_path=REPO / "nonexistent" / "no.env")

    def blue_client(self, config, prices):
        self.calls.append("blue_client")
        self.configs["blue"] = config
        return lc.LLMClient(config=config, prices=prices, adapters={"fake": self.brain},
                            env={}, sleep=lambda s: None,
                            dotenv_path=REPO / "nonexistent" / "no.env")

    def traffic(self, match_id, match_dir, attacks, benign_entries, schedule, settle,
                red_driver=None):
        assert red_driver is not None  # --red ai builds the AI driver
        red_driver.red.propose(None, 1)  # one real AI-Red call through the body
        super().traffic(match_id, match_dir, attacks, benign_entries, schedule, settle)


@pytest.fixture
def dirs(tmp_path):
    live = tmp_path / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text(PREVIOUS)
    return live, tmp_path / "runs"


def go(ops, dirs, **kw):
    live, runs = dirs
    out: list[str] = []
    code, d = run_match.run_match(ops=ops, live_dir=live, runs_dir=runs, red_engine="ai",
                                  engine="claude", blue_rules_mode="on", out=out.append, **kw)
    return code, d, "\n".join(out)


def test_ai_vs_ai_with_caching_on_for_both(dirs):
    ops = AIvAIOps(dirs[0])
    code, d, out = go(ops, dirs, blue_caching="on", red_caching="on")
    assert code == 0, out
    m = manifest_of(d)
    assert m["schema_version"] == "0.7" and run_match.validate_manifest(m) == []
    assert m["red_engine"] == "ai" and m["blue_engine"] == "claude"
    assert m["blue_params"]["caching"] == {"mode": "on", "ttl": "5m"}  # fake = Anthropic-like
    assert m["red_params"]["caching"] == {"mode": "on", "ttl": "5m"}
    assert m["blue_params"]["rules"]["mode"] == "on"
    # the flags reached both clients and both adapters
    assert lc.agent_caching(ops.configs["red"], "red") == "on"
    assert lc.agent_caching(ops.configs["blue"], "blue") == "on"
    assert [c["cache"] for c in ops.red_adapter.calls] == [True]
    assert ops.blue_cache and set(ops.blue_cache) == {True}
    # every api_calls line is 0.2; per-agent cost lines print
    calls = cost_stats.read_calls(d / lc.API_CALLS)
    assert {c["schema_version"] for c in calls} == {"0.2"}
    assert {c["agent"] for c in calls} == {"red", "blue"}
    assert "  red " in out and "  blue " in out and "net savings" in out
    # the Stage 5 done-when: all four facts computed
    assert "four facts: PASS" in out
    assert "2 Red + 17 benign slots" in out  # AI Red's round_cap, not the payload file's 7


def test_caching_defaults_to_config_and_can_differ_per_agent(dirs):
    cfg = ai_config()
    cfg["agents"]["blue"]["caching"] = "on"  # config default for Blue
    ops = AIvAIOps(dirs[0], cfg)
    code, d, out = go(ops, dirs)  # no flags: config defaults
    assert code == 0, out
    m = manifest_of(d)
    assert m["blue_params"]["caching"]["mode"] == "on"
    assert m["red_params"]["caching"] == {"mode": "off", "ttl": None}
    assert [c["cache"] for c in ops.red_adapter.calls] == [False]
    assert set(ops.blue_cache) == {True}


def test_flags_override_the_config(dirs):
    cfg = ai_config()
    cfg["agents"]["blue"]["caching"] = "on"
    ops = AIvAIOps(dirs[0], cfg)
    code, d, out = go(ops, dirs, blue_caching="off", red_caching="on")
    assert code == 0, out
    m = manifest_of(d)
    assert m["blue_params"]["caching"] == {"mode": "off", "ttl": None}
    assert m["red_params"]["caching"]["mode"] == "on"
    assert set(ops.blue_cache) == {False}


@pytest.mark.parametrize("kw,msg", [
    ({"engine": "scripted", "blue_caching": "on"}, "--blue-caching needs --blue claude"),
    ({"red_engine": "scripted", "red_caching": "on"}, "--red-caching needs --red ai"),
])
def test_caching_for_a_scripted_agent_is_refused_at_preflight(dirs, kw, msg):
    live, runs = dirs
    out: list[str] = []
    args = {"red_engine": "ai", "engine": "claude", **kw}
    code, d = run_match.run_match(ops=AIvAIOps(live), live_dir=live, runs_dir=runs,
                                  out=out.append, **args)
    assert (code, d) == (2, None) and msg in "\n".join(out)


def test_cli_flags_reach_run_match(monkeypatch):
    seen = {}
    monkeypatch.setattr(run_match, "run_match", lambda **kw: (seen.update(kw), (0, None))[1])
    assert run_match.main(["--red", "ai", "--blue", "claude", "--blue-rules-mode", "on",
                           "--blue-caching", "on", "--red-caching", "on"]) == 0
    assert (seen["blue_caching"], seen["red_caching"]) == ("on", "on")
    with pytest.raises(SystemExit):
        run_match.main(["--blue-caching", "sometimes"])


def test_replay_caching_flag(tmp_path):
    from tools import replay_blue
    from test_run_match_failure import FakeOps as F
    code, rdir = replay_blue.replay(REPO / "data" / "golden" / "scripted-baseline-match",
                                    tmp_path / "r", ops=F(tmp_path), engine="scripted",
                                    caching="on", out_fn=lambda *_: None)
    assert (code, rdir) == (2, None)  # caching is an AI-call setting


# ---- the gate tools refuse without --real-calls and call nothing --------------

@pytest.mark.parametrize("argv", [["--gate", "2"], ["--gate", "3"]])
def test_gate_2_and_3_refuse_without_real_calls(argv, monkeypatch, capsys):
    from tools import stage5_7_check as g
    monkeypatch.setattr(g.replay_blue, "replay", lambda *a, **k: pytest.fail("replayed"))
    monkeypatch.setattr(g.run_match, "run_match", lambda *a, **k: pytest.fail("ran a match"))
    assert g.main(argv) == 2
    assert "REFUSED" in capsys.readouterr().out


def test_gate_1_refuses_without_real_calls(monkeypatch, capsys):
    from tools import stage5_7_gate1 as g
    monkeypatch.setattr(g, "run_blue", lambda *a, **k: pytest.fail("called Blue"))
    monkeypatch.setattr(g, "run_red", lambda *a, **k: pytest.fail("called Red"))
    assert g.main([]) == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and "dry run 5 turns" in out


def test_gate_1_blue_and_red_paths_on_the_fake_provider(tmp_path, monkeypatch, capsys):
    """The Gate 1 code paths with the fake provider standing in for both real ones."""
    from tools import stage5_7_gate1 as g
    Client = lc.LLMClient  # the real class, captured before the module attribute is patched
    cfg = lc.with_caching(lc.with_caching(ai_config(), "blue", "on"), "red", "on")
    cfg["agents"]["blue"]["model"] = "fake-small"
    reads = iter([lc.Usage(60, 0, 900, 10), lc.Usage(60, 900, 0, 10), lc.Usage(400, 0, 0, 10)])

    def fake_client(config):
        a = FakeAdapter(text='{"verdicts": []}')
        a.call = lambda **kw: lc.Reply(text='{"verdicts": []}', usage=next(reads))
        return Client(config=config, prices=PRICES, adapters={"fake": a}, env={},
                      sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")
    monkeypatch.setattr(g.lc, "LLMClient", lambda config: fake_client(config))
    assert g.run_blue(cfg, tmp_path / "blue", "m001") == 0
    out = capsys.readouterr().out
    assert "Blue call 2: prompt v2, line 2 (expect read)" in out
    assert "C1 (prompt v1): NOT cached" in out

    growth = iter([lc.Usage(400 + 150 * i, 0 if i < 5 else 1000 + 150 * (i - 5), 0, 20)
                   for i in range(8)])

    def red_client(config):
        a = FakeAdapter(text=RED_REPLY)
        a.call = lambda **kw: lc.Reply(text=RED_REPLY, usage=next(growth))
        return Client(config=config, prices=PRICES, adapters={"fake": a}, env={},
                      sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")
    monkeypatch.setattr(g.lc, "LLMClient", lambda config: red_client(config))
    assert g.run_red(cfg, tmp_path / "red", "m001", 8) == 0
    out = capsys.readouterr().out
    assert "reads growing turn by turn: YES (non-zero reads on 3 turn(s))" in out
