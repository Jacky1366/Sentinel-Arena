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
]


def _boom(*a, **kw):
    raise AssertionError("a paid entry point went past the GO token")


@pytest.fixture
def nothing_may_run(monkeypatch):
    for obj, name in [(run_match, "Ops"), (run_match, "run_match"), (lc, "LLMClient"),
                      (replay_blue, "replay"), (match_ops, "reset_target"),
                      (match_ops, "running_images"), (match_ops, "acquire_lock")]:
        monkeypatch.setattr(obj, name, _boom)


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
