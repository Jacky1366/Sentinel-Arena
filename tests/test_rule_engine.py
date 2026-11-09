"""rules/engine.py: pure, deterministic; AND of conditions; any-form matching;
RE2, so no pattern can hang the engine."""

from __future__ import annotations

import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from rules import engine, validator  # noqa: E402

SRC = "11111111-1111-4111-8111-111111111111"


@contextmanager
def hard_timeout(seconds: int):
    def boom(*_):
        raise TimeoutError(f"engine did not finish within {seconds}s")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def rule(*conds, rid="r-001", cwe="CWE-89"):
    r = {"rule_id": rid, "cwe": cwe, "source_request_id": SRC, "created_at_log_seq": 1,
         "conditions": [{"field": f, "op": op, "pattern": p, "case_insensitive": ci}
                        for f, op, p, ci in conds]}
    [v] = validator.validate_rules([r])
    assert v.valid, v.reasons
    return v


def req(method="GET", path="/", query="", body=""):
    return engine.Request(method, path, query, body)


def fires(v, r) -> bool:
    return engine.fire([v], r) == [v.rule_id]


@pytest.mark.parametrize("op,pattern,ci,value,expected", [
    ("contains", "union", False, "q=UNION", False),
    ("contains", "union", True, "q=UNION", True),
    ("equals", "q=a", False, "q=a", True),
    ("equals", "q=a", False, "q=ab", False),
    ("equals", "Q=A", True, "q=a", True),
    ("regex", r"union\s+select", True, "q=UNION+SELECT", True),   # via '+' form
    ("regex", r"^q=a$", False, "q=a", True),
    ("regex", "UNION", False, "q=union", False),
])
def test_ops_and_case(op, pattern, ci, value, expected):
    assert fires(rule(("query", op, pattern, ci)), req(query=value)) is expected


def test_any_form_matches():
    v = rule(("path", "contains", "%00", False))
    assert fires(v, req(path="/f.bak%2500.md"))      # intermediate step
    assert not fires(v, req(path="/f.bak.md"))


def test_method_is_never_decoded():
    assert not fires(rule(("method", "equals", "GET", False)), req(method="G%45T"))
    assert fires(rule(("method", "equals", "get", True)), req(method="GET"))


def test_all_conditions_must_match():
    v = rule(("method", "equals", "POST", False), ("body", "contains", "'", False))
    assert fires(v, req("POST", body="'"))
    assert not fires(v, req("GET", body="'"))
    assert not fires(v, req("POST", body="x"))


def test_fields_are_matched_separately():
    # Unlike scripted Blue's joined haystack, a pattern never spans two fields.
    v = rule(("query", "regex", "a.b", False))
    assert not fires(v, req(path="/xa", query="b"))


def test_order_and_only_valid_rules():
    a, b = rule(("query", "contains", "x", False), rid="r-002"), \
        rule(("query", "contains", "x", False), rid="r-001")
    assert engine.fire([a, b], req(query="x")) == ["r-002", "r-001"]
    [bad] = validator.validate_rules([{"rule_id": "r-003"}])
    assert engine.fire([bad, a], req(query="x")) == ["r-002"]
    with pytest.raises(ValueError):
        engine.fires(bad, engine.forms(req()))


def test_deterministic():
    v = rule(("body", "regex", r"'\s*or\s+1=1", True))
    r = req(body='{"email": "\' OR 1=1--"}')
    assert {tuple(engine.fire([v], r)) for _ in range(50)} == {("r-001",)}


def test_field_cap():
    big = "a" * (engine.FIELD_CAP + 10) + "MARK"
    f = engine.forms(req(body=big))
    assert all(len(x) <= engine.FIELD_CAP for x in f["body"])
    assert not fires(rule(("body", "contains", "MARK", False)), req(body=big))
    # nothing nginx accepts (client_max_body_size 1m) is ever cut
    assert engine.FIELD_CAP == 1 << 20


@pytest.mark.parametrize("pattern", ["(a+)+$", "(a|a)+$", "(a*)*b", "(.*a){12}"])
def test_catastrophic_patterns_finish_fast(pattern):
    v = rule(("body", "regex", pattern, False))
    evil = "a" * (1 << 20) + "!"
    with hard_timeout(5):
        t = time.perf_counter()
        engine.fire([v], req(body=evil))
        assert time.perf_counter() - t < 2.0


def test_engine_is_pure(monkeypatch):
    import builtins
    import socket

    def refuse(*a, **k):
        raise AssertionError("engine touched the outside world")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(builtins, "open", refuse)
    engine.fire([rule(("body", "contains", "x", False))], req(body="x"))


def test_expressiveness_scripted_blue_as_rules_reproduces_classify(capsys):
    # Part F (report): 20 signatures -> 60 rules, 31/31 golden verdicts. The
    # probes document the known gaps (cross-field, Unicode \b \s \d).
    sys.path.insert(0, str(REPO / "tools"))
    import expressiveness_check
    assert expressiveness_check.main() == 0
    out = capsys.readouterr().out
    assert "rules reproduce classify(): 31/31" in out and out.count("DIFFERS") == 4
