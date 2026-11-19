"""The GO token by construction (Stage 6.1b): every paid entry point refuses (exit 2)
without ARENA_GO=<its gate id>, BEFORE constructing Ops, touching Docker, building an AI
client or running a match / replay. Tests never set ARENA_GO (conftest removes every
ARENA_* variable); the helper's matching logic is tested with an explicit mapping."""

from __future__ import annotations

import importlib
import os
import re

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402
from agents import llm_client as lc  # noqa: E402
from runner import go_token, match_ops  # noqa: E402
from tools import replay_blue  # noqa: E402

LIB0 = str(REPO / "data" / "library" / "rule_library_v0000.json")
PAID = [  # (tool module, argv, gate id)
    ("stage5_4_smoke", ["--real-call"], "gate-5.4-1"),
    ("stage5_4_check", ["--real-calls"], "gate-5.4-2"),
    ("stage5_5_check", ["--real-calls"], "gate-5.5"),
    ("stage5_6_smoke", ["--real-call"], "gate-5.6-1"),
    ("stage5_6_check", ["--real-calls"], "gate-5.6-2"),
    ("stage5_7_gate1", ["--real-calls"], "gate-5.7-1"),
    ("stage5_7_check", ["--gate", "2", "--real-calls"], "gate-5.7-2"),
    ("stage5_7_check", ["--gate", "2", "--rules-mode", "off", "--real-calls"], "gate-5.7-2b"),
    ("stage5_7_check", ["--gate", "3", "--real-calls"], "gate-5.7-3"),
    ("stage6_1_check", ["--gate", "1", "--real-calls"], "gate-6.1b-1"),
    ("stage6_1_check", ["--gate", "2", "--library", LIB0, "--real-calls"], "gate-6.1b-2"),
    ("stage6_1_check", ["--gate", "2b", "--real-calls"], "gate-6.1b-2b"),
    ("stage6_3_check", ["--gate", "A", "--probe", "--real-calls"], "gate-6.3-A"),
    ("stage6_3_check", ["--gate", "B", "--real-calls"], "gate-6.3-B"),
    ("stage6_3_check", ["--gate", "C", "--matches", str(REPO / "data" / "golden"
                                                        / "train-6.1b-gate1-match1"),
                        "--real-calls"], "gate-6.3-C"),
    ("stage6_3_check", ["--gate", "B-deepseek", "--real-calls"], "gate-6.3-B-deepseek"),
]


def _boom(*a, **kw):
    raise AssertionError("a paid entry point went past the GO token")


@pytest.fixture
def nothing_may_run(monkeypatch):
    for obj, name in [(run_match, "Ops"), (run_match, "run_match"), (lc, "LLMClient"),
                      (replay_blue, "replay"), (match_ops, "reset_target"),
                      (match_ops, "running_images"), (match_ops, "acquire_lock")]:
        monkeypatch.setattr(obj, name, _boom)


def test_every_gate_id_is_well_formed_for_the_single_exit():
    # a gate id the tool accepts but llm_client.require_go rejects would refuse the GO'd
    # run at the exit (Stage 6.3 Gate A: gate-6.3-A once failed the lower-case pattern)
    for _, _, gate in PAID:
        assert go_token.valid(gate), gate
        lc.require_go({go_token.ENV: gate})


def test_tests_never_carry_the_token():
    assert go_token.ENV not in os.environ
    name = "ARENA" + "_GO"  # built, so this file does not match its own pattern
    pat = re.compile(r"(setenv|environ\[|putenv)[^\n]*" + name)
    for p in (REPO / "tests").glob("*.py"):
        assert not pat.search(p.read_text(encoding="utf-8")), p.name


@pytest.mark.parametrize("tool,argv,gate_id", PAID, ids=[" ".join([t, *a[:3]]) for t, a, _ in PAID])
def test_every_paid_entry_point_refuses_without_the_token(tool, argv, gate_id, capsys,
                                                          nothing_may_run):
    mod = importlib.import_module(f"tools.{tool}")
    assert mod.main(argv) == 2
    out = capsys.readouterr().out
    assert f"ARENA_GO={gate_id} is required" in out and "Nothing was called" in out


def test_every_real_calls_tool_is_covered():
    """A new paid tool cannot be added without joining PAID."""
    paid = {p.stem for p in (REPO / "tools").glob("*.py")
            if re.search(r"--real-calls?\b", p.read_text(encoding="utf-8"))
            and "add_argument" in p.read_text(encoding="utf-8")}
    assert paid == {t for t, _, _ in PAID}
    for t in paid:
        assert "go_token.check(" in (REPO / "tools" / f"{t}.py").read_text(encoding="utf-8")


def test_the_token_must_match_the_gate_exactly():
    assert go_token.check("gate-6.1b-1", {}) is not None
    assert go_token.check("gate-6.1b-1", {"ARENA_GO": "gate-6.1b-2"}) is not None
    assert go_token.check("gate-6.1b-1", {"ARENA_GO": "gate-6.1b-1 "}) is not None
    assert go_token.check("gate-6.1b-1", {"ARENA_GO": "GATE-6.1B-1"}) is not None
    assert go_token.check("gate-6.1b-1", {"ARENA_GO": "gate-6.1b-1"}) is None
    assert "set to 'gate-6.1b-2'" in go_token.check("gate-6.1b-1", {"ARENA_GO": "gate-6.1b-2"})


# ---- the single exit (agents/llm_client.py): a REAL provider client needs ARENA_GO --------

NON_TEST = REPO / "data" / "golden" / "scripted-baseline-benign-match"


@pytest.fixture
def real_ops_no_docker(monkeypatch):
    """The REAL run_match.Ops, with Docker and every Target step made to raise: a direct
    command must be refused at preflight, before any of them."""
    monkeypatch.setattr(run_match.Ops, "preflight", lambda self: {})
    monkeypatch.setattr(match_ops, "check_live_clean", lambda live: None)
    for name in ("reset", "rotate", "traffic", "freeze", "judge_fact1", "blue"):
        monkeypatch.setattr(run_match.Ops, name, _boom)
    monkeypatch.setattr(match_ops, "acquire_lock", _boom)
    for cls in (lc.AnthropicAdapter, lc.OpenAIAdapter, lc.DeepSeekAdapter):
        monkeypatch.setattr(cls, "call", _boom)


@pytest.mark.parametrize("argv", [["--blue", "claude"], ["--red", "ai"],
                                  ["--red", "ai", "--blue", "claude", "--blue-rules-mode", "on"]])
def test_direct_run_match_with_real_engines_refuses_without_the_token(argv, capsys,
                                                                      real_ops_no_docker):
    assert run_match.main(argv) == 2
    out = capsys.readouterr().out
    assert "PREFLIGHT FAILED" in out and "ARENA_GO" in out


def test_direct_replay_with_claude_refuses_without_the_token(tmp_path, capsys,
                                                             real_ops_no_docker):
    out_dir = tmp_path / "replay"
    assert replay_blue.main(["--match", str(NON_TEST), "--engine", "claude",
                             "--out", str(out_dir)]) == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and "ARENA_GO" in out and not out_dir.exists()


def test_a_real_client_needs_a_well_formed_token():
    cfg, prices = lc.load_config(), lc.cost_mod.load_prices()
    for env in ({}, {"ARENA_GO": ""}, {"ARENA_GO": "yes"}, {"ARENA_GO": "manual-"},
                {"ARENA_GO": "gate-"}, {"ARENA_GO": "Manual-Test"}):
        with pytest.raises(lc.GoTokenError):
            lc.LLMClient(config=cfg, prices=prices, env=env)  # default = real adapters
    for token in ("gate-6.1b-1", "manual-red-model-probe"):
        assert go_token.valid(token)
        lc.LLMClient(config=cfg, prices=prices, env={"ARENA_GO": token})  # builds


def test_the_fake_provider_never_needs_the_token(tmp_path):
    from llm_fakes import FakeAdapter, make_client, run_dir, SYSTEM, MESSAGES
    assert go_token.ENV not in os.environ
    client, _ = make_client(FakeAdapter(), env={}, tmp_path=tmp_path)
    r = client.complete("blue", "fake-small", SYSTEM, MESSAGES, run_dir=run_dir(tmp_path),
                        log_seq_first=1, log_seq_last=1)
    assert r.ok
    keyed = FakeAdapter(provider="anthropic", needs_key=True)  # a keyed fake is still fake
    assert not lc.is_real(keyed) and not lc.is_real(FakeAdapter())
    assert lc.is_real(lc.AnthropicAdapter()) and lc.is_real(lc.OpenAIAdapter())
    assert lc.is_real(lc.DeepSeekAdapter())
    assert not lc.is_real(lc.AnthropicAdapter(http_client_factory=lambda: None))


@pytest.mark.parametrize("cls", [lc.AnthropicAdapter, lc.OpenAIAdapter, lc.DeepSeekAdapter])
def test_a_real_adapter_checks_the_token_before_building_the_sdk_client(cls, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_sdk(name, *a, **kw):
        if name in ("anthropic", "openai"):
            raise AssertionError(f"SDK {name} imported without the GO token")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", no_sdk)
    with pytest.raises(lc.GoTokenError):
        cls().call(model="m", system="s", messages=[], max_output_tokens=1, timeout=1,
                   api_key="not-a-real-key", request={"thinking": None, "effort": None},
                   output_schema=None)


def test_go_token_error_is_raised_not_logged_as_a_failed_call(tmp_path, monkeypatch):
    """Even past construction (token in the client's own env mapping, none in the
    process), the adapter's check raises through complete(): never a retried failure."""
    from llm_fakes import MESSAGES, SYSTEM, run_dir
    monkeypatch.setattr(lc, "is_real", lambda a: False)  # skip the construction check
    cfg = lc.load_config()
    client = lc.LLMClient(config=cfg, prices=lc.cost_mod.load_prices(),
                          env={"ARENA_ANTHROPIC_API_KEY": "not-a-real-key"},
                          dotenv_path=tmp_path / "no.env")
    d = run_dir(tmp_path)
    with pytest.raises(lc.GoTokenError):
        client.complete("blue", cfg["agents"]["blue"]["model"], SYSTEM, MESSAGES, run_dir=d,
                        log_seq_first=1, log_seq_last=1)
    assert not (d / lc.API_CALLS).exists() or "error_type" not in (d / lc.API_CALLS).read_text()


# ---- only the single exit imports a provider SDK -------------------------------------------

SDKS = ("anthropic", "openai", "google")


def test_only_llm_client_imports_a_provider_sdk():
    import ast
    offenders = []
    for p in REPO.rglob("*.py"):
        rel = p.relative_to(REPO).as_posix()
        if rel.startswith((".venv/", "data/")) or "/." in f"/{rel}":
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            for n in names:
                if n.split(".")[0] in SDKS and rel != "agents/llm_client.py":
                    offenders.append(f"{rel}: {n}")
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "__import__" \
                    and node.args and isinstance(node.args[0], ast.Constant) \
                    and str(node.args[0].value).split(".")[0] in SDKS:
                offenders.append(f"{rel}: __import__({node.args[0].value!r})")
    assert offenders == []
