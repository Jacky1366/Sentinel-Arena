"""AI Blue with a rule library (Stage 6.1, D21, D22). Fake provider through the REAL body:
a library rule answers a line with no API call (rule_origin "library"); the prompt and
the messages are byte-identical with and without a library; verdicts are 0.4 only with a
library; a library needs rules mode on; the library file is never written."""

from __future__ import annotations

import hashlib
import json

import pytest

from llm_fakes import lc
from test_blue_rules import M, RIDS, VERDICT, Brain, client, pline, union_brain, write_log
from test_rule_library import make_library, rule
from blue import claude_engine as ce  # noqa: E402
from blue import run_blue  # noqa: E402
from rules import library as rule_library  # noqa: E402


def library(tmp_path, *rules):
    d = tmp_path / "lib"
    return make_library(d, ("20261120T010000Z-aaaa", list(rules or [rule(1, pattern="drop")])))[-1]


def run(tmp_path, lines, answer, lib_path=None, mode="on"):
    brain = Brain(answer)
    log = write_log(tmp_path, lines)
    lib = rule_library.load(lib_path) if lib_path else None
    out = ce.classify(log, M, client(brain), "fake-small", tmp_path, rules_mode=mode,
                      library=lib)
    for r in out.verdicts:
        VERDICT[r["schema_version"]].validate(r)
    calls = [json.loads(l) for l in (tmp_path / lc.API_CALLS).read_text().splitlines()] \
        if (tmp_path / lc.API_CALLS).exists() else []
    return out, brain, calls


LINES = [pline(RIDS[0], query="q=drop+table"), pline(RIDS[1], query="q=union+select"),
         pline(RIDS[2], query="q=union+all"), pline(RIDS[3], query="q=apple")]


def test_a_library_rule_answers_from_line_one_without_a_call(tmp_path):
    lib = library(tmp_path, rule(1, pattern="drop"))
    out, brain, calls = run(tmp_path, LINES, union_brain, lib)
    v = out.verdicts
    assert all(r["schema_version"] == "0.4" for r in v)
    assert v[0]["source"] == "rule" and v[0]["fired_rule_ids"] == ["lib-0001"]
    assert v[0]["rule_origin"] == "library" and v[0]["reason"] == "rule lib-0001 fired"
    assert v[1]["source"] == "ai" and v[1]["rule_origin"] is None   # in-match rule created here
    assert v[2]["source"] == "rule" and v[2]["rule_origin"] == "match"
    assert v[2]["fired_rule_ids"] == ["r-001"]
    assert [c["log_seq_first"] for c in calls] == [2, 4]  # no call for lines 1 and 3
    assert len(out.rules) == 1  # library rules are never stored in rules.jsonl


def test_prompt_and_messages_identical_with_and_without_a_library(tmp_path):
    lines = [pline(RIDS[0], query="q=apple"), pline(RIDS[1], query="q=pear")]
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir(), b.mkdir()
    _, with_lib, _ = run(a, lines, union_brain, library(tmp_path, rule(1, pattern="drop")))
    _, without, _ = run(b, lines, union_brain)
    assert with_lib.calls == without.calls  # system prompt, line view, output schema


def test_no_library_keeps_verdicts_0_3(tmp_path):
    out, _, _ = run(tmp_path, LINES, union_brain)
    assert {r["schema_version"] for r in out.verdicts} == {"0.3"}
    assert all("rule_origin" not in r for r in out.verdicts)


def test_an_empty_library_writes_0_4_and_changes_nothing_else(tmp_path):
    empty = make_library(tmp_path / "lib")[-1]  # v0000
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    with_empty, _, calls_a = run(a, LINES, union_brain, empty)
    plain, _, calls_b = run(b, LINES, union_brain)
    assert len(calls_a) == len(calls_b)
    strip = [{k: v for k, v in r.items() if k not in ("schema_version", "rule_origin")}
             for r in with_empty.verdicts]
    assert strip == [{k: v for k, v in r.items() if k != "schema_version"}
                     for r in plain.verdicts]


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_a_library_needs_rules_mode_on(tmp_path, mode):
    with pytest.raises(ValueError, match="mode 'on'"):
        run(tmp_path, LINES, union_brain, library(tmp_path), mode=mode)


def test_run_blue_reads_the_library_and_never_writes_it(tmp_path):
    lib = library(tmp_path, rule(1, pattern="drop"))
    before = hashlib.sha256(lib.read_bytes()).hexdigest()
    write_log(tmp_path, LINES)
    run_blue.main(["--engine", "claude", "--match-id", M, "--run-dir", str(tmp_path),
                   "--rules-mode", "on", "--library", str(lib)], client=client(Brain(union_brain)))
    v = [json.loads(l) for l in (tmp_path / "verdicts.jsonl").read_text().splitlines()]
    assert v[0]["rule_origin"] == "library"
    assert hashlib.sha256(lib.read_bytes()).hexdigest() == before


def test_scripted_blue_refuses_a_library(tmp_path):
    write_log(tmp_path, LINES)
    with pytest.raises(ValueError, match="claude-engine"):
        run_blue.run_output("scripted", tmp_path / "proxy.jsonl", M, tmp_path,
                            library=library(tmp_path))


def test_blue_params_record_the_library(tmp_path):
    from llm_fakes import CONFIG
    lib = rule_library.load(library(tmp_path), display="data/library/v.json")
    p = ce.blue_params(CONFIG, "fake-small", 1, "on", lib.params())
    assert p["library"] == lib.params()
    assert ce.blue_params(CONFIG, "fake-small", 1, "on")["library"] is None
    with pytest.raises(ValueError, match="mode 'on'"):
        ce.blue_params(CONFIG, "fake-small", 1, "shadow", lib.params())
