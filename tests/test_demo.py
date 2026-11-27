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
    # and it qualifies as the matchup-2 golden run
    assert export_golden.classify_run(d) == ("freeplay", [])


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
    d = _dev_copy(tmp_path)  # Luna prompt v1 + Haiku rules on = the --taxonomy --luna config
    assert export_golden.classify_run(d) == ("taxonomy", [])
    out = tmp_path / "public"
    p = export_dashboard.export(d, export_golden.bundle_name("taxonomy"), out)
    assert p.name == "golden-taxonomy.json" and (out / "bundles.js").exists()
    dist = tmp_path / "dist"
    export_golden.sync_dist(out, dist)
    assert (dist / "golden-taxonomy.json").read_bytes() == p.read_bytes()


@pytest.mark.parametrize("patch,why", [
    ({"purpose": "train"}, "not dev"),
    ({"status": "failed", "failed_step": "blue"}, "status 'failed'"),
    ({"models": {"red": {"provider": "openai", "model": "gpt-6.1-sol"},
                 "blue": {"provider": "anthropic", "model": "claude-haiku-5-5"}}},
     "not the taxonomy demo configuration"),
    ({"blue_engine": "scripted"}, "not the taxonomy demo configuration"),
    ({"red_params": {"prompt_version": "2"}}, "not a demo matchup"),
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
    env.update({"DEMO_DRY": "1", **(env_extra or {})})
    return subprocess.run(["bash", str(DEMO_SH), *args], capture_output=True, text=True,
                          env=env, timeout=30)


def test_demo_sh_syntax_and_executable():
    assert os.access(DEMO_SH, os.X_OK)
    assert subprocess.run(["bash", "-n", str(DEMO_SH)]).returncode == 0


@pytest.mark.parametrize("args", [[], ["--luna"], ["--taxonomy"], ["--taxonomy", "--luna"],
                                  ["--open-replay"]])
def test_demo_sh_live_modes_refuse_without_go(args):
    r = _sh(*args)
    assert r.returncode != 0 and "ARENA_GO is not set" in r.stderr
    assert "caffeinate" not in r.stdout and "live server" not in r.stdout  # stopped first


def test_demo_sh_rejects_unknown_and_extra_options():
    assert "unknown option" in _sh("--fast").stderr
    assert "--replay needs one of" in _sh("--replay").stderr
    assert "--replay needs one of" in _sh("--replay", "live").stderr
    assert "takes no other option" in _sh("--luna", "--replay", "open").stderr
    assert "matchup 3 has no Red" in _sh("--open-replay", "--luna").stderr


@pytest.mark.parametrize("kind", ["taxonomy", "freeplay", "open"])
def test_demo_sh_replay_needs_no_go_and_names_the_golden_bundle(kind):
    r = _sh("--replay", kind)
    if (REPO / "dashboard" / "dist" / "data" / f"golden-{kind}.json").exists():
        assert r.returncode == 0 and f"#src=bundle:golden-{kind}&tab=battle" in r.stdout
    else:
        assert r.returncode != 0 and f"no golden-{kind} run yet" in r.stderr
    text = DEMO_SH.read_text()
    replay = text.split('if [ -n "$replay" ]; then\n  echo')[1].split("\nfi\n")[0]
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


# ---- D61: matchup 1 (taxonomy) and matchup 3 (open Blue replay) ------------------------

def test_taxonomy_is_gate_b_deepseek_and_its_backup_gate_b():
    kw = demo_match.demo_kwargs(matchup="taxonomy")
    arm = s63.DEEPSEEK_ARM
    assert (kw["red_model"], kw["red_provider"], kw["red_effort"]) == (
        arm["model"], arm["provider"], arm["effort"])
    assert kw["red_prompt_version"] == "1" == ai_red.RED_PROMPT_VERSION
    assert "prompt_version" not in arm and "caps" not in arm and "max_output_tokens" not in arm
    assert kw["red_max_output_tokens"] == s63.RED_MAX_OUTPUT and kw["caps"] is None
    luna = demo_match.demo_kwargs("luna", matchup="taxonomy")
    assert (luna["red_model"], luna["red_effort"], luna["red_max_output_tokens"],
            luna["red_prompt_version"]) == (s63.RED_MODEL, s63.RED_EFFORT, s63.RED_MAX_OUTPUT, "1")
    blue_keys = ("engine", "blue_model", "blue_rules_mode", "blue_caching", "library", "purpose")
    assert all(kw[k] == demo_match.demo_kwargs()[k] for k in blue_keys)  # same original Blue


def test_open_replay_settings_are_gate_c_open():
    import inspect
    src = inspect.getsource(s63.gate_c_open)
    assert demo_match.OPEN_REPLAY == {"engine": "claude", "model": s63.BLUE_LIVE,
                                      "rules_mode": "on", "caching": "on", "blue_prompt": "open"}
    for part in ('engine="claude"', "model=BLUE_LIVE", 'rules_mode="on"', 'caching="on"',
                 "library=library", 'blue_prompt="open"'):
        assert part in src, part
    assert "thinking" not in src.split("replay_blue.replay(")[1].split(")")[0]


def _demo_match(lab, matchup="freeplay"):
    live, runs, transcript = lab
    out = tee(transcript)
    kw = demo_match.demo_kwargs(seed=live_fakes.SEED, matchup=matchup)
    code, d = run_match.run_match(ops=DemoOps(live, out), live_dir=live, runs_dir=runs,
                                  settle=0, out=out, **kw)
    assert code == 0
    return d


def test_matchup_3_rejudges_the_latest_freeplay_match_end_to_end(lab, tmp_path):  # noqa: F811
    live, runs, transcript = lab
    assert demo_match.latest_freeplay(runs) is None
    lines: list[str] = []
    sess = tmp_path / "sessions.jsonl"
    assert demo_match.open_replay(runs, out_fn=lines.append, sessions=sess) == 2
    assert lines[0].startswith("WARNING: no demo session") and lines[1].startswith("REFUSED")
    src = _demo_match(lab)
    _demo_match(lab, "taxonomy")                 # newer, but not free-play
    ev = tmp_path / "ev"                          # newer free-play copy marked eval: test data
    shutil.copytree(src, runs / "zz-eval")
    m = json.loads((runs / "zz-eval" / "match.json").read_text())
    m.update(purpose="eval", started_at="2099-01-01T00:00:00Z")
    (runs / "zz-eval" / "match.json").write_text(json.dumps(m))
    assert demo_match.latest_freeplay(runs) == src
    lines = []
    code = demo_match.open_replay(runs, out_fn=lines.append, ops=DemoOps(live, tee(transcript)),
                                  out=tmp_path / "r", sessions=sess)
    assert code == 0, "\n".join(lines)
    assert f"matchup 3: open Blue re-judges free-play match {src.name} (same traffic)" in lines
    r = json.loads((tmp_path / "r" / "replay.json").read_text())
    assert r["source"]["match_id"] == src.name and r["blue_params"]["prompt_version"] == "3-open"
    assert r["blue_params"]["rules"]["mode"] == "on" and r["models"]["blue"]["model"] == demo_match.BLUE
    assert (tmp_path / "r" / "proxy.jsonl").read_bytes() == (src / "proxy.jsonl").read_bytes()
    assert export_golden.classify_run(tmp_path / "r") == ("open", [])
    assert not ev.exists()


# ---- demo sessions (designer 2026-11-26): rehearsal runs never reach the stage ----------

def test_sessions_are_append_only_and_the_last_is_current(tmp_path):
    p = tmp_path / "demo" / "sessions.jsonl"
    assert demo_match.current_session(p) is None
    a = demo_match.new_session(p)
    b = demo_match.new_session(p)
    assert demo_match.current_session(p) == b and a["session_id"] != b["session_id"]
    assert len(p.read_text().splitlines()) == 2                  # never overwritten
    assert b["started_at"].endswith("Z") and b["started_at"] >= a["started_at"]


def test_open_replay_ignores_freeplay_matches_from_before_the_session(lab, tmp_path):  # noqa: F811
    live, runs, transcript = lab
    rehearsal = _demo_match(lab)                                # before the session
    sess = tmp_path / "sessions.jsonl"
    m = json.loads((rehearsal / "match.json").read_text())
    sess.write_text(json.dumps({"session_id": "s1", "started_at": m["finished_at"]}) + "\n")
    lines: list[str] = []
    assert demo_match.open_replay(runs, out_fn=lines.append, sessions=sess) == 2
    assert lines == ["REFUSED: no completed free-play demo match in demo session s1: run matchup 2 "
                     "first (scripts/demo.sh)"]
    assert demo_match.latest_freeplay(runs, since=m["finished_at"]) is None
    assert demo_match.latest_freeplay(runs, since=m["started_at"]) == rehearsal


def test_new_session_cli_is_free_and_needs_no_go(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ARENA_GO", raising=False)
    monkeypatch.setattr(demo_match, "SESSIONS", tmp_path / "s.jsonl")
    monkeypatch.setattr(demo_match, "new_session", lambda path=tmp_path / "s.jsonl":
                        {"session_id": "x", "started_at": "2026-12-03T17:00:00.000Z"})
    assert demo_match.main(["--new-session"]) == 0
    assert "demo session x started" in capsys.readouterr().out


def test_demo_sh_new_session_mode_exists():
    text = DEMO_SH.read_text()
    assert "--new-session)" in text and "tools/demo_match.py --new-session" in text


# ---- demo.sh preflight: every failure prints DEMO STOP (2026-11-26 silent-exit bug) ------
# demo.sh runs from a COPY in a throwaway repo: a stub venv python (the GO check only), a stub
# docker on PATH, no dashboard build unless asked. Every case stops before caffeinate, the
# live server, the browser and tools/demo_match.py: nothing reaches a network or a provider.

FAKE_PY = """#!/bin/sh
# stub venv python: only the GO well-formedness check is reachable
[ "$1" = "-c" ] || { echo "stub python reached: $*" >&2; exit 97; }
exit "${FAKE_GO_RC:-0}"
"""
FAKE_DOCKER = """#!/bin/sh
[ -z "$FAKE_DOCKER_FAIL" ] || { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
printf '%s\\n' "${FAKE_DOCKER_PS:-juice-shop running healthy
nginx running }"
"""


def _sandbox(tmp_path, *, dist=False, sessions=None, lock=False, venv=True, demo_is_file=False):
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(DEMO_SH, root / "scripts" / "demo.sh")
    if venv:
        (root / ".venv" / "bin").mkdir(parents=True)
        (root / ".venv" / "bin" / "python").write_text(FAKE_PY)
        (root / ".venv" / "bin" / "python").chmod(0o755)
    live = root / "data" / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text("")
    if lock:
        (live / "match.lock").write_text("")
    demo = root / "data" / "runs" / "demo"
    if demo_is_file:
        demo.write_text("")  # makes `mkdir -p data/runs/demo/transcripts` fail: an unguarded step
    elif sessions is not None:
        demo.mkdir(parents=True)
        (demo / "sessions.jsonl").write_text(sessions)
    if dist:
        (root / "dashboard" / "dist").mkdir(parents=True)
        (root / "dashboard" / "dist" / "index.html").write_text("")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "docker").write_text(FAKE_DOCKER)
    (bin_ / "docker").chmod(0o755)
    return root, bin_


def _sh_in(root, bin_, *args, go="manual-test-preflight", **env_extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ARENA_", "FAKE_"))}
    env.update({"DEMO_DRY": "1", "PATH": f"{bin_}:{env['PATH']}", **env_extra})
    if go is not None:
        env["ARENA_GO"] = go  # a well-formed placeholder; the stub python never calls anything
    return subprocess.run(["bash", str(root / "scripts" / "demo.sh"), *args],
                          capture_output=True, text=True, env=env, timeout=30)


def _assert_stopped_with_message(r, *needles):
    assert r.returncode != 0
    stops = [ln for ln in r.stderr.splitlines() if ln.startswith("DEMO STOP: ")]
    assert len(stops) == 1, (r.stdout, r.stderr)  # exactly one message, never zero
    for n in needles:
        assert n in stops[0], (n, stops[0])
    assert "live server" not in r.stdout and "starting" not in r.stdout and "stub python reached" not in r.stderr


@pytest.mark.parametrize("args", [[], ["--taxonomy"], ["--open-replay"]])
def test_demo_sh_no_sessions_file_warns_and_continues(tmp_path, args):
    """The 2026-11-26 bug: no data/runs/demo/sessions.jsonl -> sed failed under pipefail and
    set -e exited 1 with no message. Now: WARN, then the next check (here: dashboard)."""
    root, bin_ = _sandbox(tmp_path)
    r = _sh_in(root, bin_, *args)
    assert "WARN  no demo session" in r.stdout
    _assert_stopped_with_message(r, "dashboard not built")


def test_demo_sh_reads_the_current_session(tmp_path):
    root, bin_ = _sandbox(tmp_path, sessions='{"session_id": "s1"}\n{"session_id": "s2"}\n')
    r = _sh_in(root, bin_, "--open-replay")
    assert "ok    demo session s2" in r.stdout
    _assert_stopped_with_message(r, "dashboard not built")


@pytest.mark.parametrize("case, args, kw, env, needles", [
    ("no venv", [], {"venv": False}, {}, ["no project venv"]),
    ("no GO", [], {}, {"go": None}, ["ARENA_GO is not set", "ARENA_GO=<token> scripts/demo.sh"]),
    ("bad GO", [], {}, {"FAKE_GO_RC": "1"}, ["not a well-formed token"]),
    ("docker down", [], {}, {"FAKE_DOCKER_FAIL": "1"},
     ["docker compose ps failed", "docker compose up -d --wait"]),
    ("juice-shop absent", [], {}, {"FAKE_DOCKER_PS": "nginx running "},
     ["juice-shop is 'absent'", "docker compose up -d --wait"]),
    ("juice-shop starting", ["--taxonomy"], {},
     {"FAKE_DOCKER_PS": "juice-shop running starting\nnginx running "},
     ["juice-shop is starting", "docker compose up -d --wait"]),
    ("stale lock", [], {"lock": True}, {}, ["stale lock", "remove it by hand"]),
    ("stale lock, matchup 3", ["--open-replay"], {"lock": True}, {}, ["stale lock"]),
    ("dashboard missing", [], {"sessions": '{"session_id": "s1"}\n'}, {}, ["dashboard not built"]),
    ("unguarded step fails", ["--open-replay"], {"dist": True, "demo_is_file": True}, {},
     ["unexpected failure", "line ", "--replay"]),
])
def test_demo_sh_every_failing_preflight_prints_one_demo_stop(tmp_path, case, args, kw, env,
                                                               needles):
    root, bin_ = _sandbox(tmp_path, **kw)
    r = _sh_in(root, bin_, *args, **env)
    _assert_stopped_with_message(r, *needles)


def test_demo_sh_every_pipeline_before_the_run_is_guarded():
    """Static backstop: under set -euo pipefail, a $(a | b) assignment before the run must be
    guarded (|| die / || true / inside an if on the file's existence), or carry the ERR trap."""
    text = DEMO_SH.read_text()
    assert "set -euo pipefail" in text and "trap '" in text and "' ERR" in text
    pre_run = text.split("# ---- the run")[0]
    assert pre_run.index("' ERR") < pre_run.index("# ---- options")
    assert "trap - ERR" in text.split("# ---- the run")[1].split('"$PY" -u tools/demo_match.py')[0]
