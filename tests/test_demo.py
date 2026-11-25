"""#18: the demo launcher (scripts/demo.sh), its D46 config as code (tools/demo_match.py) and
the golden-run export (tools/export_golden.py). Zero cost: the fake provider, stubbed
network, a copied non-test golden folder; demo.sh only on its refusal paths."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from llm_fakes import REPO, lc
import live_fakes
from live_fakes import lab, tee  # noqa: F401 (fixture)
import run_match
from red import ai_red
from stats import cost as cost_stats
from stats import test_data
from test_blue_rules import Brain
from test_run_match_rules import broad
from tools import demo_match, export_dashboard, export_golden
from tools import stage6_3_check as s63

DEMO_SH = REPO / "scripts" / "demo.sh"
TRAIN = REPO / "data" / "golden" / "train-6.1b-gate1-match1"   # not test data (D59, checked below)


# ---- the D46 config ------------------------------------------------------------------

def test_deepseek_is_the_gate_b_freeplay_red_and_d44_blue():
    kw = demo_match.demo_kwargs()
    arm = s63.FREEPLAY_ARM
    assert (kw["red_model"], kw["red_provider"], kw["red_effort"]) == (
        arm["model"], arm["provider"], arm["effort"])
    assert kw["red_prompt_version"] == arm["prompt_version"] == ai_red.FREEPLAY_PROMPT_VERSION
    assert kw["red_max_output_tokens"] == arm["max_output_tokens"] and kw["caps"] == arm["caps"]
    assert (kw["engine"], kw["blue_model"], kw["blue_rules_mode"], kw["blue_caching"],
            kw["red_caching"]) == ("claude", s63.BLUE_LIVE, "on", "on", "on")
    assert kw["library"] == s63.LIB_V5 and kw["purpose"] == "dev" and kw["seed"] is None
    assert kw["red_timeout_s"] == demo_match.DEMO_RED_TIMEOUT_S


def test_luna_is_the_d38_strength():
    kw = demo_match.demo_kwargs("luna")
    assert (kw["red_model"], kw["red_effort"], kw["red_max_output_tokens"]) == (
        s63.RED_MODEL, s63.RED_EFFORT, s63.RED_MAX_OUTPUT)
    assert kw["red_prompt_version"] in ai_red.RED_PROMPTS
    assert {k: v for k, v in kw.items() if not k.startswith("red_")} == {
        k: v for k, v in demo_match.demo_kwargs().items() if not k.startswith("red_")}


def test_red_config_applies_every_override():
    cfg = demo_match.red_config(demo_match.demo_kwargs(red_timeout_s=77))
    red = cfg["agents"]["red"]
    assert red["provider"] == "deepseek" and red["max_output_tokens"] == 16384
    assert red["request"]["effort"] == "max" and red["caching"] == "on"
    assert lc.agent_timeout(cfg, "red") == 77 and cfg["caps"]["match"]["max_usd"] == 0.40


def test_paid_modes_refuse_without_go(monkeypatch, capsys):
    monkeypatch.delenv("ARENA_GO", raising=False)
    assert demo_match.main([]) == 2 and demo_match.main(["--one-turn", "--red", "luna"]) == 2
    assert "REFUSED" in capsys.readouterr().err
    assert demo_match.main(["--print-config"]) == 0


def test_nothing_sets_or_defaults_the_go_token():
    for p in (DEMO_SH, REPO / "tools" / "demo_match.py", REPO / "tools" / "export_golden.py"):
        text = p.read_text()   # usage lines may show the placeholder manual-<what>, nothing more
        assert not re.search(r"ARENA_GO(=|:-|:=)[\"']?(manual|gate)-[a-z0-9]", text), p
        assert not re.search(r"export\s+ARENA_GO|environ\[.ARENA_GO.\]\s*=|setenv", text), p


# ---- the demo config through the REAL orchestrator (fake adapters, real names) --------

class DemoOps(live_fakes.LiveOps):
    """LiveOps with the demo's real provider names served by fake adapters, real prices."""

    def llm_setup(self):
        cfg, _, ref = run_match.Ops().llm_setup()
        return cfg, cost_stats.load_prices(), ref

    def _c(self, cfg, prices, adapters):
        return lc.LLMClient(config=cfg, prices=prices, adapters=adapters, env={},
                            sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")

    def red_client(self, config, prices):
        bad = json.dumps({"method": "GET", "path": "/x", "label": "other", "notes": {}})
        texts = [live_fakes.RED_TEXTS[0], bad] + live_fakes.RED_TEXTS[2:]
        return self._c(config, prices, {"deepseek": live_fakes.SeqAdapter(texts)})

    def blue_client(self, config, prices):
        return self._c(config, prices, {"anthropic": Brain(broad)})


def test_demo_kwargs_run_a_full_match_and_print_the_diagnosis(lab):  # noqa: F811
    live, runs, transcript = lab
    out = tee(transcript)
    kw = demo_match.demo_kwargs(seed=live_fakes.SEED)
    code, d = run_match.run_match(ops=DemoOps(live, out), live_dir=live, runs_dir=runs,
                                  settle=0, out=out, **kw)
    assert code == 0, transcript.read_text()
    m = json.loads((d / "match.json").read_text())
    assert m["purpose"] == "dev" and m["models"]["red"]["model"] == "deepseek-v4-pro"
    assert m["red_params"]["prompt_version"] == "3"
    tx = transcript.read_text()
    assert "red diagnosis: round 2 invalid_shape: stop=completed" in tx and "notes:dict" in tx
    assert "notes" not in (d / "red_unsent.jsonl").read_text()
    # and it qualifies as the golden run, except for being under tmp (fine) — the checks:
    assert export_golden.problems(d) == []


# ---- golden-run export ----------------------------------------------------------------

def _dev_copy(tmp_path, **patch) -> Path:
    assert test_data.classify(TRAIN, test_data.load_registry()).kind == test_data.NOT_TEST
    d = tmp_path / "m"
    shutil.copytree(TRAIN, d)
    m = json.loads((d / "match.json").read_text())
    m.update({"purpose": "dev", **patch})
    (d / "match.json").write_text(json.dumps(m))
    return d


def test_golden_accepts_a_clean_dev_demo_match_and_exports(tmp_path):
    d = _dev_copy(tmp_path)  # Luna Red + Haiku Blue rules on = the --luna demo config
    assert export_golden.problems(d) == []
    out = tmp_path / "public"
    p = export_dashboard.export(d, export_golden.NAME, out)
    assert p.name == "golden-run.json" and (out / "bundles.js").exists()
    dist = tmp_path / "dist"
    export_golden.sync_dist(out, dist)
    assert (dist / "golden-run.json").read_bytes() == p.read_bytes()


@pytest.mark.parametrize("patch,why", [
    ({"purpose": "train"}, "not dev"),
    ({"status": "failed", "failed_step": "blue"}, "status 'failed'"),
    ({"models": {"red": {"provider": "openai", "model": "gpt-6.1-sol"},
                 "blue": {"provider": "anthropic", "model": "claude-haiku-5-5"}}}, "not a demo Red"),
    ({"blue_engine": "scripted"}, "not the demo Blue"),
])
def test_golden_refusals(tmp_path, patch, why):
    d = _dev_copy(tmp_path, **patch)
    assert any(why in p for p in export_golden.problems(d)), export_golden.problems(d)


def test_golden_refuses_test_data_by_manifest_without_reading_more(tmp_path):
    d = _dev_copy(tmp_path, purpose="eval")
    (d / "rounds.jsonl").unlink()  # would fail loudly if anything past the manifest were read
    assert export_golden.problems(d)[0].startswith("not exportable: test")


def test_golden_refuses_four_facts_fail(tmp_path):
    d = _dev_copy(tmp_path)
    (d / "rounds.jsonl").write_text("")
    assert any("four facts FAIL" in p for p in export_golden.problems(d))


def test_golden_cli_check_writes_nothing(tmp_path, capsys):
    d = _dev_copy(tmp_path)
    before = sorted(p.name for p in export_golden.PUBLIC.iterdir())
    assert export_golden.main([str(d), "--check"]) == 0
    assert sorted(p.name for p in export_golden.PUBLIC.iterdir()) == before
    assert export_golden.main([str(tmp_path / "nope")]) == 2


# ---- demo.sh (refusal paths only: no Docker, no browser, no server, no call) ----------

def _sh(*args, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != "ARENA_GO"}
    env.update({"DEMO_NO_OPEN": "1", **(env_extra or {})})
    return subprocess.run(["bash", str(DEMO_SH), *args], capture_output=True, text=True,
                          env=env, timeout=30)


def test_demo_sh_syntax_and_executable():
    assert os.access(DEMO_SH, os.X_OK)
    assert subprocess.run(["bash", "-n", str(DEMO_SH)]).returncode == 0


@pytest.mark.parametrize("args", [[], ["--luna"]])
def test_demo_sh_live_modes_refuse_without_go(args):
    r = _sh(*args)
    assert r.returncode != 0 and "ARENA_GO is not set" in r.stderr
    assert "caffeinate" not in r.stdout and "live server" not in r.stdout  # stopped first


def test_demo_sh_rejects_unknown_and_extra_options():
    assert "unknown option" in _sh("--fast").stderr
    assert "one option at most" in _sh("--luna", "--replay").stderr


def test_demo_sh_replay_needs_no_go_and_points_at_the_golden_bundle():
    text = DEMO_SH.read_text()
    assert "#src=bundle:golden-run&tab=battle" in text
    replay = text.split('if [ "$mode" = replay ]; then')[1].split("\nfi\n")[0]
    assert "ARENA_GO" not in replay and "demo_match" not in replay and "curl" not in replay


# ---- --one-turn (the Luna free-play check; also a demo-day probe) ----------------------

class _One:
    def __init__(self, res):
        self.res, self.calls = res, 0

    def complete(self, agent, model, system, messages, **kw):
        self.calls += 1
        assert agent == "red" and system == ai_red.RED_PROMPTS["3"]
        return self.res


def _res(text, stop="completed"):
    return lc.Result(ok=True, text=text, usage=lc.Usage(50, 0, 0, 20), attempts=1, stop_reason=stop)


def test_one_turn_accepted_is_one_call_and_nothing_sent(tmp_path):
    a = json.dumps({"method": "GET", "path": "/rest/user/whoami", "body": "", "label": "other",
                    "rationale": "probe", "technique": "recon"})
    c = _One(_res(a))
    lines: list[str] = []
    rc = demo_match.one_turn(demo_match.demo_kwargs("luna"), client_factory=lambda cfg: c,
                             out_root=tmp_path / "chk", out=lines.append)
    assert rc == 0 and c.calls == 1 and any(l.startswith("ACCEPTED") for l in lines)
    assert "guard allow" in "\n".join(lines) and "prompt v3" in lines[0]


def test_one_turn_refusal_reports_not_accepted_with_diagnosis(tmp_path):
    c = _One(_res("I can't help with attacking systems.", stop="refusal"))
    lines: list[str] = []
    rc = demo_match.one_turn(demo_match.demo_kwargs("luna"), client_factory=lambda cfg: c,
                             out_root=tmp_path / "chk", out=lines.append)
    assert rc == 1 and "NOT ACCEPTED: brain_failure refusal (the model refused)" in lines
    assert any(l.startswith("red diagnosis: round 1 refusal: stop=refusal") for l in lines)
