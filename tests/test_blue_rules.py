"""AI Blue rule invention (Stage 5.5): prompt v2, the per-line flow in modes off /
shadow / on, the body's proposal handling (blue/rule_invention.py), the cap, and
refusals. Fake provider only, through the REAL body (agents/llm_client.py), so
api_calls.jsonl is the evidence of which lines made a call."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO, config, lc
from blue import claude_engine as ce  # noqa: E402
from blue import rule_invention, run_blue  # noqa: E402
from judge import fact2_detected  # noqa: E402

M = "20261109T153012Z-a1b2"
RIDS = ["11111111-1111-4111-8111-1111111111%02d" % i for i in range(1, 40)]
VERDICT = {v: Draft202012Validator(json.loads((REPO / "schemas" / f"{n}.schema.json")
                                              .read_text()))
           for v, n in (("0.2", "verdict_v0_2"), ("0.3", "verdict"))}
V1_SHA = "938ea67c385af3b8faa536c9d1a67ff9c6bc394c217dd95be6066145ecc80190"  # Stage 5.4 golden


def pline(rid, path="/rest/products/search", query="q=apple", body="", method="GET"):
    return {"timestamp": "2026-11-09T15:30:13.120Z", "request_id": rid, "method": method,
            "path": path, "query": query, "body": body, "status": 200}


def write_log(d: Path, lines) -> Path:
    p = d / "proxy.jsonl"
    p.write_text("".join(json.dumps(l) + "\n" for l in lines), encoding="utf-8")
    return p


def cond(field="query", op="contains", pattern="union", ci=True):
    return {"field": field, "op": op, "pattern": pattern, "case_insensitive": ci}


def verdict(label, rule=None, rationale=None) -> str:
    item = {"index": 1, "label": label}
    if rationale is not None:
        item["rationale"] = rationale
    if rule is not None:
        item["rule"] = rule
    return json.dumps({"verdicts": [item]})


class Brain:
    """A fake model: answers each call from the request it was shown (never from a
    request_id, which it never sees). `answer(view) -> reply text` or (text, stop)."""
    provider, needs_key = "fake", False

    def __init__(self, answer):
        self.answer = answer
        self.calls: list[dict] = []

    def call(self, **kw):
        msg = kw["messages"][-1]["content"]
        view = json.loads(msg.split("<requests>\n", 1)[1].rsplit("\n</requests>", 1)[0])[0]
        self.calls.append({"system": kw["system"], "view": view,
                           "output_schema": kw.get("output_schema")})
        out = self.answer(view)
        text, stop = out if isinstance(out, tuple) else (out, "end_turn")
        return lc.Reply(text=text, usage=lc.Usage(100, 0, 0, 10), stop_reason=stop)


def client(brain, **caps):
    cfg = config(**caps)
    return lc.LLMClient(config=cfg, prices=__import__("llm_fakes").PRICES,
                        adapters={"fake": brain}, env={}, sleep=lambda s: None,
                        dotenv_path=REPO / "nonexistent" / "no.env")


def run(tmp_path, lines, answer, mode="on", max_rules=10, **caps):
    """Run the engine; return (output, brain, api_calls rows). Every row is validated
    by its own schema_version."""
    brain = Brain(answer)
    log = write_log(tmp_path, lines)
    out = ce.classify(log, M, client(brain, **caps), "fake-small", tmp_path,
                      rules_mode=mode, max_rules=max_rules)
    for r in out.verdicts:
        VERDICT[r["schema_version"]].validate(r)
    for r in out.rules:
        rule_invention.MATCH_RULE.validate(r)
    for r in out.rejections:
        rule_invention.REJECTION.validate(r)
    calls_path = tmp_path / lc.API_CALLS
    calls = [json.loads(l) for l in calls_path.read_text().splitlines()] \
        if calls_path.exists() else []
    return out, brain, calls


def union_brain(view):
    """Labels 'union' queries CWE-89 and proposes a rule for them; else benign."""
    if "union" in view["query"].lower():
        return verdict("CWE-89", {"conditions": [cond()]}, rationale="union-based")
    return verdict("benign")


# ---- prompt v2 ---------------------------------------------------------------

def test_v1_is_untouched_and_v2_is_a_new_version():
    assert ce.SYSTEM_PROMPT_SHA256 == V1_SHA and ce.PROMPT_VERSION == "1"
    assert ce.PROMPT_VERSION_V2 == "2" and ce.SYSTEM_PROMPT_V2_SHA256 != V1_SHA
    assert ce.PROMPTS["off"][2] == V1_SHA and ce.PROMPTS["off"][3] is ce.OUTPUT_SCHEMA
    assert ce.PROMPTS["shadow"] == ce.PROMPTS["on"]  # the AI is never told the mode
    ce.PromptBuilder(ce.SYSTEM_PROMPT_V2)  # no volatile values


def test_v2_classification_part_is_v1_word_for_word():
    head = ce.SYSTEM_PROMPT.split("Reply with JSON only")[0]
    assert ce.SYSTEM_PROMPT_V2.startswith(head)


def test_v2_describes_the_whole_rule_format():
    p = ce.SYSTEM_PROMPT_V2
    for must in ('"method", "path", "query" or "body"', '"contains"', '"equals"', '"regex"',
                 "1 to 3 conditions", "ALL of its conditions", "There is no OR",
                 '"case_insensitive" is true or false', "1 to 200 characters", "RE2",
                 "no lookahead, lookbehind or backreferences", "decoded forms",
                 "up to three", '"+" read as a space', '"method" is never decoded',
                 "nothing about the response", "rejected and never applied",
                 "without consulting you", "will misclassify them"):
        assert must in p, must


def test_v2_example_is_schematic_and_the_prompt_is_neutral():
    p = ce.SYSTEM_PROMPT_V2
    example = [l for l in p.splitlines() if l.startswith('{"conditions"')]
    assert example == ['{"conditions":[{"field":"query","op":"contains","pattern":"<text A>",'
                       '"case_insensitive":true},{"field":"path","op":"regex","pattern":'
                       '"<RE2 expression B>","case_insensitive":false}]}']
    low = p.lower()
    for hint in ("hard negative", "o'brien", "apostrophe", "benign set", "union", "select",
                 "../", "<script", "or 1=1", "request_id", "status"):
        assert hint not in low, hint


def test_v2_output_schema_adds_only_an_optional_rule():
    v1 = ce.OUTPUT_SCHEMA["properties"]["verdicts"]["items"]
    v2 = ce.OUTPUT_SCHEMA_V2["properties"]["verdicts"]["items"]
    assert set(v2["properties"]) - set(v1["properties"]) == {"rule"}
    assert v2["required"] == v1["required"] == ["index", "label"]
    assert set(v2["properties"]["rule"]["properties"]) == {"conditions"}
    assert "rule" not in v1["properties"]  # v1 unchanged


# ---- mode off: identical to Stage 5.4 ------------------------------------------

def test_off_is_the_stage_5_4_engine(tmp_path):
    lines = [pline(RIDS[0], query="q=1 union select"), pline(RIDS[1], query="q=1 UNION all")]
    out, brain, calls = run(tmp_path, lines, union_brain, mode="off")
    assert {r["schema_version"] for r in out.verdicts} == {"0.2"}
    assert out.rules == [] and out.rejections == [] and out.rules_mode == "off"
    assert {c["system"] for c in brain.calls} == {ce.SYSTEM_PROMPT}
    assert all(c["output_schema"] == ce.OUTPUT_SCHEMA for c in brain.calls)
    # v1 has no "rule" key: the reply above is invalid_shape, exactly as in 5.4
    assert [r["failure_detail"] for r in out.verdicts] == ["invalid_shape"] * 2
    assert len(calls) == 2
    (tmp_path / "x").mkdir()
    log = write_log(tmp_path / "x", lines)
    stage54 = ce.classify_log(log, M, client(Brain(union_brain)), "fake-small", tmp_path / "x")
    assert stage54 == out.verdicts  # byte-identical rows


# ---- mode on: hot-load ----------------------------------------------------------

def test_rule_fires_on_later_lines_without_a_call(tmp_path):
    lines = [pline(RIDS[0], query="q=1 union select 1"),   # AI: CWE-89 + rule
             pline(RIDS[1], query="q=apple"),               # AI: benign
             pline(RIDS[2], query="q=2 UNION select 2"),    # rule fires, no call
             pline(RIDS[3], query="q=x%20Union%20y")]       # decoded form, rule fires
    out, brain, calls = run(tmp_path, lines, union_brain)
    v = out.verdicts
    assert [(r["log_seq"], r["source"], r["verdict"]) for r in v] == [
        (1, "ai", "CWE-89"), (2, "ai", "benign"), (3, "rule", "CWE-89"), (4, "rule", "CWE-89")]
    assert v[2]["fired_rule_ids"] == ["r-001"] and v[2]["reason"] == "rule r-001 fired"
    assert "rationale" not in v[2] and v[0]["fired_rule_ids"] == []
    assert [c["log_seq_first"] for c in calls] == [1, 2]  # lines 3 and 4 made no call
    assert len(brain.calls) == 2
    assert {c["system"] for c in brain.calls} == {ce.SYSTEM_PROMPT_V2}
    assert {r["schema_version"] for r in v} == {"0.3"}


def test_the_body_fills_everything_but_the_conditions(tmp_path):
    out, _, _ = run(tmp_path, [pline(RIDS[0], query="q=union")], union_brain)
    assert out.rules == [{"schema_version": "0.1", "match_id": M, "hot_loaded": True,
                          "rule": {"rule_id": "r-001", "cwe": "CWE-89",
                                   "conditions": [cond()], "source_request_id": RIDS[0],
                                   "created_at_log_seq": 1, "created_match": M}}]


def test_a_rule_is_not_applied_to_the_line_that_produced_it(tmp_path):
    same = dict(query="q=1 union select")
    out, brain, _ = run(tmp_path, [pline(RIDS[0], **same), pline(RIDS[1], **same)],
                        union_brain)
    assert [r["source"] for r in out.verdicts] == ["ai", "rule"]
    assert len(brain.calls) == 1


def test_the_ai_never_sees_a_request_id_or_an_existing_rule(tmp_path):
    lines = [pline(RIDS[0], query="q=union"), pline(RIDS[1], query="q=apple")]
    _, brain, _ = run(tmp_path, lines, union_brain)
    for c in brain.calls:
        assert list(c["view"]) == ["index", "method", "path", "query", "body"]
        seen = json.dumps(c["view"]) + c["system"]
        assert not any(r in seen for r in RIDS) and "r-001" not in seen
        assert c["system"] == ce.SYSTEM_PROMPT_V2  # fixed text: no stored rule enters it


def test_tie_break_earliest_rule_wins(tmp_path):
    def brain(view):
        q = view["query"]
        if q == "q=first":
            return verdict("CWE-79", {"conditions": [cond(pattern="x")]})
        if q == "q=second":
            return verdict("CWE-89", {"conditions": [cond(pattern="y")]})
        return verdict("benign")
    lines = [pline(RIDS[0], query="q=first"), pline(RIDS[1], query="q=second"),
             pline(RIDS[2], query="q=xy")]
    out, _, calls = run(tmp_path, lines, brain)
    last = out.verdicts[2]
    assert (last["verdict"], last["fired_rule_ids"]) == ("CWE-79", ["r-001", "r-002"])
    assert len(calls) == 2


def test_too_broad_rule_labels_every_later_line(tmp_path):
    def brain(view):
        return verdict("CWE-22", {"conditions": [cond(field="path", pattern="/")]})
    lines = [pline(RIDS[i], query=f"q=item{i}") for i in range(5)]
    out, _, calls = run(tmp_path, lines, brain)
    assert [r["source"] for r in out.verdicts] == ["ai"] + ["rule"] * 4
    assert {r["verdict"] for r in out.verdicts} == {"CWE-22"} and len(calls) == 1


# ---- mode shadow ----------------------------------------------------------------

def test_shadow_records_rules_but_never_applies_them(tmp_path):
    lines = [pline(RIDS[0], query="q=union 1"), pline(RIDS[1], query="q=union 2"),
             pline(RIDS[2], query="q=union 3")]
    out, brain, calls = run(tmp_path, lines, union_brain, mode="shadow")
    assert [r["source"] for r in out.verdicts] == ["ai"] * 3
    assert all(r["fired_rule_ids"] == [] and r["schema_version"] == "0.3"
               for r in out.verdicts)
    assert [r["rule"]["rule_id"] for r in out.rules] == ["r-001", "r-002", "r-003"]
    assert {r["hot_loaded"] for r in out.rules} == {False}
    assert len(calls) == len(brain.calls) == 3
    assert {c["system"] for c in brain.calls} == {ce.SYSTEM_PROMPT_V2}


def test_shadow_and_on_send_the_same_prompt_and_schema(tmp_path):
    seen = {}
    for mode in ("shadow", "on"):
        d = tmp_path / mode
        d.mkdir()
        _, brain, _ = run(d, [pline(RIDS[0], query="q=union")], union_brain, mode=mode)
        seen[mode] = (brain.calls[0]["system"], brain.calls[0]["output_schema"])
    assert seen["shadow"] == seen["on"] == (ce.SYSTEM_PROMPT_V2, ce.OUTPUT_SCHEMA_V2)


# ---- invalid proposals: rejected with reasons, the verdict stands ----------------

BAD = [
    ("lookaround", {"conditions": [cond(op="regex", pattern="(?=a)b")]},
     "regex_unsupported_feature"),
    ("backreference", {"conditions": [cond(op="regex", pattern="(a)\\1")]},
     "regex_unsupported_feature"),
    ("compile error", {"conditions": [cond(op="regex", pattern="([a-")]},
     "regex_compile_error"),
    ("four conditions", {"conditions": [cond()] * 4}, "condition_count"),
    ("no conditions", {"conditions": []}, "condition_count"),
    ("pattern too long", {"conditions": [cond(pattern="a" * 201)]}, "pattern_too_long"),
    ("empty pattern", {"conditions": [cond(pattern="")]}, "empty_pattern"),
    ("response field", {"conditions": [cond(field="status", pattern="500")]},
     "forbidden_field"),
    ("header field", {"conditions": [cond(field="user_agent")]}, "unknown_field"),
    ("unknown op", {"conditions": [cond(op="startswith")]}, "unknown_op"),
    ("not an object", "union", "schema_error"),
    ("AI writes a rule_id", {"conditions": [cond()], "rule_id": "r-999"}, "schema_error"),
    ("AI writes a source", {"conditions": [cond()], "source_request_id": RIDS[5]},
     "schema_error"),
    ("missing case flag", {"conditions": [{"field": "query", "op": "contains",
                                           "pattern": "x"}]}, "schema_error"),
    ("conditions not a list", {"conditions": {"field": "query"}}, "schema_error"),
]


@pytest.mark.parametrize("desc,proposal,code", BAD, ids=[b[0] for b in BAD])
def test_invalid_proposal_is_rejected_and_the_verdict_stands(tmp_path, desc, proposal, code):
    out, _, _ = run(tmp_path, [pline(RIDS[0], query="q=union"), pline(RIDS[1], query="q=union")],
                    lambda v: verdict("CWE-89", proposal))
    assert [r["verdict"] for r in out.verdicts] == ["CWE-89", "CWE-89"]
    assert [r["source"] for r in out.verdicts] == ["ai", "ai"]  # nothing was hot-loaded
    assert out.rules == [] and len(out.rejections) == 2
    rej = out.rejections[0]
    assert code in {r["code"] for r in rej["reasons"]}, rej["reasons"]
    assert rej["proposal"] == proposal and rej["rule_id"] == "r-001"
    assert (rej["source_request_id"], rej["created_at_log_seq"], rej["label"]) == \
        (RIDS[0], 1, "CWE-89")
    assert out.rejections[1]["rule_id"] == "r-002"  # rejected proposals use up ids


def test_a_rule_on_a_benign_verdict_is_rejected_as_cwe_benign(tmp_path):
    out, _, _ = run(tmp_path, [pline(RIDS[0])],
                    lambda v: verdict("benign", {"conditions": [cond()]}))
    assert out.verdicts[0]["verdict"] == "benign" and out.rules == []
    assert [r["code"] for r in out.rejections[0]["reasons"]] == ["cwe_benign"]


def test_an_invalid_verdict_voids_its_proposal_too(tmp_path):
    out, _, _ = run(tmp_path, [pline(RIDS[0])],
                    lambda v: '{"verdicts":[{"index":1,"label":"SQLi","rule":{"conditions":[]}}]}')
    assert out.verdicts[0]["failure_detail"] == "unknown_label"
    assert out.rules == [] and out.rejections == []  # no verdict, nothing to propose on


# ---- cap ------------------------------------------------------------------------

def test_cap_rejects_valid_rules_beyond_max_rules(tmp_path):
    def brain(view):
        n = view["query"].split("=")[1]
        return verdict("CWE-89", {"conditions": [cond(pattern=f"token{n}")]})
    lines = [pline(RIDS[i], query=f"q={i}") for i in range(4)]
    out, _, calls = run(tmp_path, lines, brain, max_rules=2)
    assert [r["rule"]["rule_id"] for r in out.rules] == ["r-001", "r-002"]
    assert [(x["rule_id"], [c["code"] for c in x["reasons"]]) for x in out.rejections] == \
        [("r-003", ["rule_cap_reached"]), ("r-004", ["rule_cap_reached"])]
    assert len(calls) == 4


def test_cap_zero_stores_nothing(tmp_path):
    out, _, _ = run(tmp_path, [pline(RIDS[0], query="q=union")], union_brain, max_rules=0)
    assert out.rules == [] and out.rejections[0]["reasons"][0]["code"] == "rule_cap_reached"


def test_an_invalid_rule_over_the_cap_keeps_its_own_reasons(tmp_path):
    out, _, _ = run(tmp_path, [pline(RIDS[0], query="q=union")],
                    lambda v: verdict("CWE-89", {"conditions": []}), max_rules=0)
    assert [c["code"] for c in out.rejections[0]["reasons"]] == ["condition_count"]


# ---- refusals (D13) -------------------------------------------------------------

def test_rules_keep_answering_after_a_body_refusal(tmp_path):
    lines = [pline(RIDS[0], query="q=union 1"),  # call 1: rule r-001
             pline(RIDS[1], query="q=apple"),    # call 2: refused by the body
             pline(RIDS[2], query="q=union 3"),  # rule verdict, no call
             pline(RIDS[3], query="q=pear")]     # no rule: instrument failure, no call
    out, _, calls = run(tmp_path, lines, union_brain, blue={"max_calls": 1})
    v = out.verdicts
    assert [(r["source"], r["no_verdict_reason"], r["failure_detail"]) for r in v] == [
        ("ai", None, None), (None, "instrument_failure", "refused_by_body"),
        ("rule", None, None), (None, "instrument_failure", "refused_by_body")]
    assert [(c["log_seq_first"], c["refusal"] is not None) for c in calls] == \
        [(1, False), (2, True)]
    # The Judge accepts it: the refusal covers lines 2..4, but line 3 is a rule
    # verdict (no call) that the hot-load cross-check confirms.
    d = tmp_path
    (d / "verdicts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in v))
    (d / "rules.jsonl").write_text("".join(json.dumps(r) + "\n" for r in out.rules))
    (d / "rule_rejections.jsonl").write_text("")
    rows = fact2_detected.load_verdicts(d)
    assert [r["source"] for r in rows] == ["ai", None, "rule", None]


def test_api_error_on_one_line_keeps_the_rest(tmp_path):
    def brain(view):
        if view["query"] == "q=boom":
            raise lc_error()
        return union_brain(view)
    lines = [pline(RIDS[0], query="q=union"), pline(RIDS[1], query="q=boom"),
             pline(RIDS[2], query="q=union again")]
    out, _, _ = run(tmp_path, lines, brain)
    assert [(r["source"], r["failure_detail"]) for r in out.verdicts] == \
        [("ai", None), (None, "api_error"), ("rule", None)]


def lc_error():
    from llm_fakes import FakeError
    return FakeError("bad request", status_code=400)  # not retryable: fails at once


def test_model_refusal_and_max_tokens_are_brain_failures_without_proposals(tmp_path):
    lines = [pline(RIDS[0], query="q=a"), pline(RIDS[1], query="q=b")]
    out, _, _ = run(tmp_path, lines, lambda v: ((verdict("CWE-89", {"conditions": [cond()]}),
                                                 "refusal") if v["query"] == "q=a" else
                                                (verdict("CWE-89", {"conditions": [cond()]}),
                                                 "max_tokens")))
    assert [r["failure_detail"] for r in out.verdicts] == ["model_refusal", "max_tokens"]
    assert out.rules == [] and out.rejections == []


# ---- configuration --------------------------------------------------------------

def test_rule_invention_needs_one_line_per_call(tmp_path):
    log = write_log(tmp_path, [pline(RIDS[0])])
    with pytest.raises(ValueError, match="chunk_size 1"):
        ce.classify(log, M, client(Brain(union_brain)), "fake-small", tmp_path,
                    chunk_size=2, unscored=True, rules_mode="on")
    with pytest.raises(ValueError, match="unknown rules mode"):
        ce.classify(log, M, client(Brain(union_brain)), "fake-small", tmp_path,
                    rules_mode="maybe")


def test_rules_config_and_blue_params_record_the_mode():
    cfg = config()
    assert ce.rules_config(cfg) == {"mode": "off", "max_rules": 10}
    cfg["agents"]["blue"]["rules"] = {"mode": "shadow", "max_rules": 3}
    assert ce.rules_config(cfg) == {"mode": "shadow", "max_rules": 3}
    assert ce.rules_config(cfg, "on") == {"mode": "on", "max_rules": 3}
    p = ce.blue_params(cfg, "fake-small", 1, "on")
    assert p["rules"] == {"mode": "on", "max_rules": 3}
    assert (p["prompt_version"], p["system_prompt_sha256"]) == ("2", ce.SYSTEM_PROMPT_V2_SHA256)
    p = ce.blue_params(cfg, "fake-small", 1, "off")
    assert (p["prompt_version"], p["system_prompt_sha256"]) == ("1", V1_SHA)
    with pytest.raises(ValueError):
        ce.rules_config(cfg, "always")


@pytest.mark.parametrize("rules", [{"mode": "sometimes"}, {"mode": "on", "max_rules": -1},
                                   {"mode": "on", "extra": 1}, "on", {"max_rules": 3}])
def test_config_validation_rejects_bad_rules_blocks(tmp_path, rules):
    cfg = json.loads((REPO / "config" / "llm.json").read_text())
    cfg["agents"]["blue"]["rules"] = rules
    p = tmp_path / "llm.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(lc.ConfigError, match="rules"):
        lc.load_config(p)


def test_run_blue_cli_writes_rules_and_rejections_only_in_shadow_and_on(tmp_path):
    def brain(view):
        if view["query"] == "q=bad":
            return verdict("CWE-89", {"conditions": []})
        return union_brain(view)
    for mode in ("off", "shadow", "on"):
        d = tmp_path / mode
        d.mkdir()
        write_log(d, [pline(RIDS[0], query="q=union"), pline(RIDS[1], query="q=bad")])
        assert run_blue.main(["--engine", "claude", "--match-id", M, "--run-dir", str(d),
                              "--rules-mode", mode], client=client(Brain(brain))) == 0
        names = sorted(p.name for p in d.iterdir())
        if mode == "off":
            assert "rules.jsonl" not in names and "rule_rejections.jsonl" not in names
        else:
            assert len((d / "rules.jsonl").read_text().splitlines()) == 1
            assert len((d / "rule_rejections.jsonl").read_text().splitlines()) == 1


def test_scripted_blue_has_no_rules_mode(tmp_path):
    log = write_log(tmp_path, [pline(RIDS[0])])
    with pytest.raises(ValueError, match="scripted"):
        run_blue.run_output("scripted", log, M, tmp_path, rules_mode="on")
