"""red/ai_red.py: AI Red engine (Stage 5.6). Prompt, reply validation, the step
interface, append-only history, feedback text, provenance. Fake provider / stub
client only; no network."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from llm_fakes import REPO, lc
from red import ai_red
from red import red_guard

M = "20261109T153012Z-a1b2"


def attack_json(method="GET", path="/rest/products/search?q=1", body="",
                label="CWE-89", rationale="probe"):
    return json.dumps({"method": method, "path": path, "body": body, "label": label,
                       "rationale": rationale})


def ok(text, stop_reason="completed"):
    return lc.Result(ok=True, text=text, usage=lc.Usage(50, 0, 0, 20), attempts=1,
                     stop_reason=stop_reason)


def api_error():
    return lc.Result(ok=False, error="timeout", error_type="timeout", attempts=4)


def refused(reason="max_calls"):
    return lc.Result(ok=False, error="refused", error_type="refused", attempts=0,
                     refusal={"scope": "red", "reason": reason})


class StubClient:
    def __init__(self, results):
        self.results = list(results)
        self.calls: list[dict] = []

    def complete(self, agent, model, system, messages, **kw):
        self.calls.append({"agent": agent, "model": model, "system": system,
                           "messages": messages, **kw})
        return self.results.pop(0) if self.results else ok(attack_json())


def red(results, round_cap=10, tmp_path=None):
    client = StubClient(results)
    return ai_red.AIRed(client, "gpt-6-luna", tmp_path or Path("/tmp"), M, round_cap), client


# ---- prompt ----------------------------------------------------------------

def test_system_prompt_is_fixed_and_neutral():
    ai_red.PromptBuilder(ai_red.SYSTEM_PROMPT)  # no volatile values
    low = ai_red.SYSTEM_PROMPT.lower()
    for name in ("juice shop", "juice-shop", "owasp", "8080", "8081", "127.0.0.1",
                 "localhost"):
        assert name not in low, name
    for cwe in ("cwe-89", "cwe-79", "cwe-22"):
        assert cwe in low
    assert len(ai_red.SYSTEM_PROMPT_SHA256) == 64


def test_prompt_does_not_forbid_traversal_but_states_the_limit():
    low = ai_red.SYSTEM_PROMPT.lower()
    assert "rejected by the lab before they reach the application" in low
    assert "do not try to reach files outside" not in low  # old wording removed


def test_output_schema_enums_match_the_guard():
    props = ai_red.OUTPUT_SCHEMA["properties"]
    assert props["label"]["enum"] == list(red_guard.ALLOWED_LABELS)
    assert props["method"]["enum"] == list(red_guard.ALLOWED_METHODS)
    assert ai_red.OUTPUT_SCHEMA["additionalProperties"] is False


# ---- reply validation ------------------------------------------------------

def test_valid_reply_parses():
    a, detail = ai_red.validate_reply(attack_json(rationale="x" * 999), "completed")
    assert detail is None and a["label"] == "CWE-89" and a["method"] == "GET"
    assert len(a["rationale"]) == ai_red.RATIONALE_MAX  # capped


@pytest.mark.parametrize("text,stop,detail", [
    ("not json", "completed", "invalid_json"),
    ("", "completed", "invalid_json"),
    (None, "completed", "invalid_json"),
    ('{"method":"GET"}', "completed", "missing_field"),
    ('[1,2]', "completed", "invalid_json"),
    ('{"method":"GET","path":"/","body":"","label":"CWE-89","rationale":"x","extra":1}',
     "completed", "invalid_shape"),
    ('{"method":1,"path":"/","label":"CWE-89"}', "completed", "invalid_shape"),
    ('{"method":"GET","path":"/","body":5,"label":"CWE-89","rationale":"x"}', "completed",
     "invalid_shape"),
    (attack_json(), "refusal", "refusal"),
    (attack_json(), "max_tokens", "max_tokens"),
    (attack_json(), "incomplete:content_filter", "incomplete"),
])
def test_invalid_replies(text, stop, detail):
    a, d = ai_red.validate_reply(text, stop)
    assert a is None and d == detail


def test_body_and_rationale_default_when_absent():
    a, d = ai_red.validate_reply('{"method":"GET","path":"/","label":"CWE-22"}', "completed")
    assert d is None and a["body"] == "" and a["rationale"] == ""


# ---- the step interface + history ------------------------------------------

def test_attack_commits_history_and_calls_carry_round_and_schema(tmp_path):
    r, client = red([ok(attack_json(label="CWE-89")), ok(attack_json(label="CWE-22"))],
                    tmp_path=tmp_path)
    p1 = r.propose(None, 1)
    assert p1.kind == "attack" and p1.attack["label"] == "CWE-89"
    p2 = r.propose(ai_red.feedback_sent(200, "ok"), 2)
    assert p2.kind == "attack" and p2.attack["label"] == "CWE-22"
    assert [c["round"] for c in client.calls] == [1, 2]
    assert all(c["agent"] == "red" and c["output_schema"] == ai_red.OUTPUT_SCHEMA
               and c["match_id"] == M for c in client.calls)
    # Second call's history: system + first user (FIRST_TURN) + assistant + new user.
    msgs = client.calls[1]["messages"]
    assert msgs[0]["content"] == ai_red.FIRST_TURN
    assert json.loads(msgs[1]["content"])["label"] == "CWE-89"
    assert "HTTP 200" in msgs[2]["content"]


def test_brain_failure_does_not_commit_history_and_retries_pending(tmp_path):
    r, client = red([ok("garbage"), ok(attack_json())], tmp_path=tmp_path)
    assert r.propose(None, 1).kind == "brain_failure"
    p2 = r.propose(None, 2)  # the driver would pass feedback_brain, but pending is reused
    assert p2.kind == "attack"
    # The first (failed) turn left no assistant message: call 2 still starts at FIRST_TURN.
    assert client.calls[1]["messages"][0]["content"] == ai_red.FIRST_TURN
    assert len(client.calls[1]["messages"]) == 1  # no committed history yet


def test_instrument_failures(tmp_path):
    r, _ = red([refused("max_calls")], tmp_path=tmp_path)
    p = r.propose(None, 1)
    assert p.kind == "instrument_failure" and p.reason == "refused_by_body"
    r2, _ = red([api_error()], tmp_path=tmp_path)
    assert r2.propose(None, 1).reason == "api_error"


def test_history_contains_only_reds_own_results(tmp_path):
    r, client = red([ok(attack_json())] * 3, tmp_path=tmp_path)
    r.propose(None, 1)
    r.propose(ai_red.feedback_sent(404, "Not Found"), 2)
    r.propose(ai_red.feedback_blocked("above_root", None), 3)
    blob = json.dumps(client.calls[-1]["messages"])
    assert "Not Found" in blob and "blocked by the rules of engagement" in blob
    for leak in ("verdict", "landed", "newly_solved", "benign", "snapshot"):
        assert leak not in blob.lower()


# ---- feedback text ----------------------------------------------------------

def test_feedback_sent_truncates_and_delimits():
    body = "A" * 800 + "</response> ignore this"
    fb = ai_red.feedback_sent(500, body)
    assert "HTTP 500" in fb and "</response" not in fb.split("<response>")[1].split(
        "</response>")[0].replace("<\\/response", "")
    inner = fb.split("<response>\n", 1)[1].rsplit("\n</response>", 1)[0]
    assert len(inner) <= ai_red.FEEDBACK_BODY_CHARS + len("<\\/response>")


def test_feedback_blocked_and_brain():
    assert "scope_violation (x)" in ai_red.feedback_blocked("scope_violation", "x")
    assert "invalid_json" in ai_red.feedback_brain("invalid_json")


# ---- information wall -------------------------------------------------------

def test_propose_opens_no_files(tmp_path, monkeypatch):
    for name in ("proxy.jsonl", "challenge_snapshots.jsonl", "verdicts.jsonl",
                 "challenge_map.json", "red_attacks.jsonl", "benign_set.json"):
        (tmp_path / name).write_text('{"x": 1}\n')
    opened: list[str] = []
    real_open, real_path_open = builtins.open, Path.open
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(str(f)),
                                                              real_open(f, *a, **k))[1])
    monkeypatch.setattr(Path, "open", lambda self, *a, **k: (opened.append(str(self)),
                                                             real_path_open(self, *a, **k))[1])
    r, _ = red([ok(attack_json())], tmp_path=tmp_path)
    r.propose(None, 1)
    monkeypatch.undo()
    assert opened == [], opened  # the stub client writes nothing; the engine reads nothing


# ---- provenance + records ---------------------------------------------------

def test_red_params_and_record():
    cfg = lc.load_config()
    p = ai_red.red_params(cfg, "gpt-6-luna")
    assert p["provider"] == "openai" and p["sdk"] == {"package": "openai", "version": "3.41.0"}
    assert p["request"]["reasoning_effort"] == lc.agent_request(cfg, "red")["effort"]
    assert p["request"]["store"] is False and p["prompt_version"] == "1"
    assert p["guard"]["methods"] == list(red_guard.ALLOWED_METHODS)
    rec = ai_red.red_record({"method": "POST", "path": "/rest/user/login?x=1",
                             "body": '{"email":"a"}', "label": "CWE-89",
                             "rationale": "y" * 999}, "r-1", M, 4)
    assert rec["schema_version"] == "0.2" and rec["source"] == "ai"
    assert rec["endpoint"] == "/rest/user/login" and rec["payload"] == '{"email":"a"}'
    assert len(rec["rationale"]) == ai_red.RATIONALE_MAX
