"""Stage 6.3 (flagship gate) offline: --red-effort and purpose eval wiring, the test-set
registration by purpose (D35), promotion refusing eval matches, the zero-token estimate,
and Gates B and C driven end to end on FakeOps + the fake provider (no network, no Docker,
no money; the real tool's refusals are in tests/test_go_token.py)."""

from __future__ import annotations

import json

import pytest

from llm_fakes import PRICES, REPO
from test_promote_rules import Env, TrainOps  # noqa: F401
from test_run_match_ai_vs_ai import ai_config
from test_run_match_rules import RulesOps, dirs  # noqa: F401 (fixture)
from test_stage6_1_gates_offline import GateOps, good_brain
import run_match  # noqa: E402
from agents import llm_client as lc  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from tools import audit_match  # noqa: E402
from tools import stage6_3_check as g  # noqa: E402


@pytest.fixture(autouse=True)
def no_real_ops(monkeypatch):
    class _NoRealOps:
        def __init__(self, *a, **kw):
            raise AssertionError("real run_match.Ops in a test")
    monkeypatch.setattr(g.run_match, "Ops", _NoRealOps)


# ---- configuration ---------------------------------------------------------------

def test_red_strength_is_model_plus_effort_and_nothing_else():
    base = lc.load_config()
    cfg = g.gate_config(base)
    assert cfg["agents"]["red"]["model"] == "gpt-6.1-sol"
    assert cfg["agents"]["red"]["request"]["effort"] == "medium"
    assert cfg["agents"]["red"]["caching"] == "on"  # Gate 3 configuration
    for k in ("max_output_tokens", "round_cap", "provider"):
        assert cfg["agents"]["red"][k] == base["agents"]["red"][k]
    assert cfg["agents"]["blue"] == base["agents"]["blue"]
    assert base["agents"]["red"]["request"]["effort"] == "low"  # not mutated


def test_with_effort_validates_and_copies():
    base = lc.load_config()
    assert lc.with_effort(base, "red", None) is base
    with pytest.raises(lc.ConfigError):
        lc.with_effort(base, "red", "ultra")


def go_match(dirs_, ops, **kw):
    live, runs = dirs_
    out: list[str] = []
    code, d = run_match.run_match(ops=ops, live_dir=live, runs_dir=runs, out=out.append, **kw)
    return code, d, "\n".join(out)


def test_red_effort_is_recorded_and_needs_ai_red(dirs):
    code, d, out = go_match(dirs, GateOps(dirs[0], answer=good_brain), red_engine="ai",
                            engine="claude", blue_rules_mode="on", red_effort="medium")
    assert code == 0, out
    m = json.loads((d / "match.json").read_text())
    assert m["red_params"]["request"]["reasoning_effort"] == "medium"
    code, d, out = go_match(dirs, RulesOps(dirs[0]), engine="claude", red_effort="medium")
    assert code == 2 and d is None and "--red-effort needs --red ai" in out


def test_eval_purpose_is_recorded_and_needs_a_clean_tree(dirs, monkeypatch):
    ops = GateOps(dirs[0], answer=good_brain)
    code, d, out = go_match(dirs, ops, red_engine="ai", engine="claude",
                            blue_rules_mode="on", purpose="eval")
    assert code == 0, out
    m = json.loads((d / "match.json").read_text())
    assert m["purpose"] == "eval" and run_match.validate_manifest(m) == []
    assert audit_match.audit_scope(d) is None  # D36: eval matches get a FULL audit
    monkeypatch.setattr(type(ops), "git_info", lambda self: {"commit": "x" * 40, "dirty": True})
    code, d, out = go_match(dirs, ops, red_engine="ai", engine="claude",
                            blue_rules_mode="on", purpose="eval")
    assert code == 2 and "eval needs a clean committed tree" in out


def test_the_committed_registry_marks_eval_as_test_data():
    ts = json.loads((REPO / "config" / "test_set.json").read_text())
    assert ts["test_purposes"] == ["eval"]


def test_promotion_refuses_an_eval_match(tmp_path, dirs, monkeypatch):
    env = Env(tmp_path, dirs, monkeypatch)
    d = env.train_match(purpose="eval")
    env.audit(d)
    code, out = env.promote(d)
    assert code == 2 and "purpose 'eval'" in out
    doc = json.loads(env.test_set.read_text())
    doc["test_purposes"] = ["eval"]
    env.test_set.write_text(json.dumps(doc))
    code, out = env.promote(d)
    assert code == 2 and "TEST data by purpose" in out


def test_register_test_ids_appends_once(tmp_path):
    p = tmp_path / "ts.json"
    p.write_text((REPO / "config" / "test_set.json").read_text())
    g.register_test_ids(["20261120T000000Z-eeee"], p)
    g.register_test_ids(["20261120T000000Z-eeee"], p)
    ids = json.loads(p.read_text())["match_ids"]
    assert ids.count("20261120T000000Z-eeee") == 1 and len(ids) == 7


# ---- Gate A: estimate (zero token) ------------------------------------------------------

def test_estimate_reprices_the_train_profile():
    prices = cost_stats.load_prices()
    e = g.estimate(prices, lc.load_config())
    # repricing Haiku Blue at Haiku prices gives back what the train matches paid
    paid = sum(json.loads((d / "match.json").read_text())["cost"]["by_agent"]["blue"]["usd"]
               for d in g.PROFILE) / len(g.PROFILE)
    assert e["per_match"]["blue_haiku"] == pytest.approx(paid, abs=2e-6)
    assert e["per_match"]["red_sol_x3"] > e["per_match"]["red_sol_x1"] > 0
    assert e["per_match"]["blue_sonnet"] > e["per_match"]["blue_haiku"]
    assert e["gate_b_worst"] == 1.5 and e["gate_c_worst"] == 1.5
    assert all("train-6.1b-gate1" in n for n in e["profile"])  # never test-set data


def test_price_problems_flags_unverified():
    prices = json.loads(json.dumps(cost_stats.load_prices()))
    prices["models"]["gpt-6.1-sol"]["verified"] = False
    assert any("gpt-6.1-sol" in p for p in g.price_problems(prices))
    prices["models"]["gpt-6.1-sol"]["verified"] = True
    assert g.price_problems(prices) == []


# ---- Gates B and C offline ---------------------------------------------------------------

def test_gates_b_and_c_offline(dirs, tmp_path, monkeypatch, capsys):
    live, runs = dirs
    monkeypatch.setattr(g, "RED_MODEL", "fake-small")
    monkeypatch.setattr(g, "BLUE_LIVE", "fake-small")
    monkeypatch.setattr(g, "BLUE_STRONG", "fake-small")
    monkeypatch.setattr(g, "ARMS_C", (("sonnet-v5", "fake-small", "v5"),
                                      ("haiku-empty", "fake-small", "empty")))
    monkeypatch.setattr(g, "SEEDS", (6301, 6302))
    ids = iter(f"20261120T0300{i:02d}Z-cccc" for i in range(20))
    monkeypatch.setattr(g.run_match, "new_match_id", lambda: next(ids))
    ts = tmp_path / "test_set.json"
    ts.write_text((REPO / "config" / "test_set.json").read_text())
    sheets, audits = tmp_path / "sheets", tmp_path / "audits"
    sheets.mkdir()
    code = g.gate_b(PRICES, sheet_dir=sheets, audits=audits, test_set=ts,
                    ops=GateOps(live, answer=good_brain), live_dir=live, runs_dir=runs)
    out = capsys.readouterr().out
    assert code == 0, out
    ds = sorted(p for p in runs.glob("2026*") if (p / "match.json").is_file())
    ms_ = [json.loads((d / "match.json").read_text()) for d in ds]
    assert [m["purpose"] for m in ms_] == ["eval", "eval"]
    assert [m["traffic"]["seed"] for m in ms_] == [6301, 6302]
    assert all(m["blue_params"]["library"]["sha256"] == g.LIB_V5_SHA for m in ms_)
    assert all(m["red_params"]["request"]["reasoning_effort"] == "medium" for m in ms_)
    assert set(json.loads(ts.read_text())["match_ids"]) >= {m["match_id"] for m in ms_}
    for d, m in zip(ds, ms_):  # FULL audit: every Red round scaffolded
        rows = [json.loads(l) for l in (audits / f"{m['match_id']}.jsonl").read_text().splitlines()]
        reds = [json.loads(l) for l in (d / "red_attacks.jsonl").read_text().splitlines()]
        assert sorted(r["round"] for r in rows) == sorted(r["round"] for r in reds)
    assert next(sheets.glob("stage6_3_gateB_*.md")).is_file()

    assert g.check_sources(ds) == []
    code = g.gate_c(PRICES, ds, root=tmp_path / "c", ops=RulesOps(live, answer=good_brain))
    out = capsys.readouterr().out
    assert code == 0, out
    reps = sorted(p.name for p in (tmp_path / "c").iterdir())
    assert reps == sorted(f"{d.name}-{a}" for d in ds for a in ("sonnet-v5", "haiku-empty"))
    for d in ds:
        v5 = json.loads((tmp_path / "c" / f"{d.name}-sonnet-v5" / "replay.json").read_text())
        e = json.loads((tmp_path / "c" / f"{d.name}-haiku-empty" / "replay.json").read_text())
        assert v5["blue_params"]["library"]["sha256"] == g.LIB_V5_SHA
        assert e["blue_params"]["library"]["entries"] == 0
    assert "RESULT: PASS" in out


def test_gate_c_refuses_non_eval_sources():
    probs = g.check_sources([REPO / "data" / "golden" / "train-6.1b-gate1-match1"])
    assert probs and "purpose 'train'" in probs[0]


# ---- Gate A: probe (fake provider) -------------------------------------------------------

def _probe_factory(script, env):
    from llm_fakes import FakeAdapter, FakeError  # noqa: F401
    from test_run_match_ai_vs_ai import RED_REPLY
    oa = FakeAdapter(script=list(script.get("openai", ())), provider="openai", text=RED_REPLY)
    an = FakeAdapter(script=list(script.get("anthropic", ())), provider="anthropic")
    return lambda cfg: lc.LLMClient(config=cfg, prices=cost_stats.load_prices(),
                                    adapters={"openai": oa, "anthropic": an}, env=env,
                                    sleep=lambda s: None,
                                    dotenv_path=REPO / "nonexistent" / "no.env")


def test_probe_prints_redacted_provider_errors(tmp_path, capsys):
    from llm_fakes import FakeError
    secret = "probe" + "secret" + "value" + "123456"  # built at runtime (key hygiene)
    env = {"ARENA_OPENAI_API_KEY": secret, "ARENA_ANTHROPIC_API_KEY": secret}
    fac = _probe_factory({"openai": [FakeError(f"Unsupported parameter 'x' ({secret})", 400)],
                          "anthropic": [FakeError("thinking.type: 'disabled' not allowed", 400)]},
                         env)
    assert g.probe(out_root=tmp_path / "p", client_factory=fac) == 1
    out = capsys.readouterr().out
    assert "error red: " in out and "Unsupported parameter 'x'" in out
    assert "error blue: " in out and "thinking.type" in out
    assert secret not in out
    for f in (tmp_path / "p").rglob("*"):  # error text never reaches disk
        if f.is_file():
            assert "Unsupported" not in f.read_text() and secret not in f.read_text()


def test_probe_passes_on_clean_replies(tmp_path, capsys):
    assert g.probe(out_root=tmp_path / "p", client_factory=_probe_factory({}, {})) == 0
    out = capsys.readouterr().out
    assert "RESULT: PASS" in out and "error " not in out
    red = [json.loads(l) for l in (tmp_path / "p" / "red" / lc.API_CALLS).read_text().splitlines()]
    assert red[0]["model"] == "gpt-6.1-sol" and red[0]["ok"] is True


def test_effort_values_are_the_api_values():
    # a second EFFORTS once narrowed config validation to minimal..high (Nov 18 fix)
    assert lc.EFFORTS == ("low", "medium", "high", "xhigh", "max")
    base = lc.load_config()
    assert lc.with_effort(base, "red", "xhigh")["agents"]["red"]["request"]["effort"] == "xhigh"
    with pytest.raises(lc.ConfigError):
        lc.with_effort(base, "red", "minimal")


def test_sonnet_arm_turns_thinking_off_with_between_tools():
    cfg = g.sonnet_config(lc.load_config())
    assert cfg["agents"]["blue"]["request"] == {"thinking": "between_tools", "effort": "low"}
    assert cfg["agents"]["blue"]["caching"] == "on"
    kw = lc.anthropic_request_kwargs(lc.agent_request(cfg, "blue"), None)
    assert kw["thinking"] == {"type": "between_tools"}  # no other field alongside it
    assert lc.load_config()["agents"]["blue"]["request"]["thinking"] == "disabled"  # Haiku


def _adapters_factory(oa, an):
    return lambda cfg: lc.LLMClient(config=cfg, prices=cost_stats.load_prices(),
                                    adapters={"openai": oa, "anthropic": an}, env={},
                                    sleep=lambda s: None,
                                    dotenv_path=REPO / "nonexistent" / "no.env")


@pytest.mark.parametrize("model", ["gpt-6.1-terra", "gpt-5.6-sol", "gpt-6-luna"])
def test_probe_one_red_candidate_only(tmp_path, capsys, model):
    from llm_fakes import FakeAdapter
    from test_run_match_ai_vs_ai import RED_REPLY
    oa, an = FakeAdapter(provider="openai", text=RED_REPLY), FakeAdapter(provider="anthropic")
    assert g.probe(out_root=tmp_path / "p", client_factory=_adapters_factory(oa, an),
                   red_model=model, blue=False) == 0
    assert len(oa.calls) == 1 and an.calls == [] and not (tmp_path / "p" / "blue").exists()
    assert oa.calls[0]["model"] == model
    assert oa.calls[0]["request"]["effort"] == g.PROBE_CANDIDATES[model]
    assert f"effort {g.PROBE_CANDIDATES[model]}" in capsys.readouterr().out


def test_probe_blue_only_sends_between_tools(tmp_path, capsys):
    from llm_fakes import FakeAdapter
    oa, an = FakeAdapter(provider="openai"), FakeAdapter(provider="anthropic")
    assert g.probe(out_root=tmp_path / "p", client_factory=_adapters_factory(oa, an),
                   red_model=None) == 0
    assert oa.calls == [] and len(an.calls) == 1
    assert an.calls[0]["model"] == "claude-sonnet-5-5"
    assert an.calls[0]["request"]["thinking"] == "between_tools"
    assert "Red proposal" not in capsys.readouterr().out


def test_probe_prints_a_safety_refusal_and_never_retries(tmp_path, capsys):
    from llm_fakes import FakeAdapter

    class Refusing(FakeAdapter):
        def call(self, **kw):
            self.calls.append(kw)
            return lc.Reply(text="I can't help with that.", usage=self.usage,
                            stop_reason="refusal")
    oa, an = Refusing(provider="openai"), FakeAdapter(provider="anthropic")
    assert g.probe(out_root=tmp_path / "p", client_factory=_adapters_factory(oa, an),
                   red_model="gpt-6.1-terra", blue=False) == 1
    out = capsys.readouterr().out
    assert len(oa.calls) == 1 and "refusal red: I can't help with that." in out
    assert "RESULT: CHECK" in out


def test_probe_cli_accepts_only_the_named_candidates():
    with pytest.raises(SystemExit):
        g.main(["--gate", "A", "--probe", "--probe-red", "gpt-6.2-astra"])
