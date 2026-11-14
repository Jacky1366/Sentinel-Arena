"""Prompt caching (Stage 5.7, D18) against mock HTTP transports and the fake provider.
No network, no key (the test key is built at runtime).

- caching off sends the Stage 5.4 / 5.6 request bytes exactly (captured before 5.7);
- caching on adds ONLY the cache markers;
- the prefix sent is byte-identical across Blue calls and across Red turns;
- cache reads / writes map into the usage record (both providers);
- writes at an unpriced lifetime (Anthropic 1h, OpenAI 12h, unknown breakdown) are
  recorded as unpriced_cache_write_tokens and stop the match (unpriced_usage)."""

from __future__ import annotations

import copy
import json

import httpx2
import pytest

from llm_fakes import CONFIG, PRICES, REPO, FakeAdapter, lc
from blue import claude_engine  # noqa: E402
from red import ai_red  # noqa: E402
from stats import cost  # noqa: E402

KEY = "-".join(["caching", "test", "value", "11"])
SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"],
          "additionalProperties": False}
# Captured from the Stage 5.6 adapters (commit ed53b79) before any 5.7 change.
ANTHROPIC_OFF = (b'{"max_tokens":512,"messages":[{"role":"user","content":"line one"}],'
                 b'"model":"claude-haiku-5-5","output_config":{"effort":"low","format":'
                 b'{"type":"json_schema","schema":{"type":"object","properties":{"x":'
                 b'{"type":"string"}},"required":["x"],"additionalProperties":false}}},'
                 b'"system":"SYSTEM PROMPT","thinking":{"type":"disabled"}}')
OPENAI_OFF = (b'{"model":"gpt-6-luna","input":[{"role":"user","content":"turn 1"},'
              b'{"role":"assistant","content":"{\\"a\\": 1}"},{"role":"user","content":'
              b'"turn 2"}],"instructions":"RED SYSTEM","max_output_tokens":2048,'
              b'"prompt_cache_options":{"mode":"explicit"},"reasoning":{"effort":"low"},'
              b'"store":false,"text":{"format":{"type":"json_schema","name":"response",'
              b'"schema":{"type":"object","properties":{"x":{"type":"string"}},"required":'
              b'["x"],"additionalProperties":false},"strict":true}}}')
RED_TURNS = [{"role": "user", "content": "turn 1"},
             {"role": "assistant", "content": '{"a": 1}'},
             {"role": "user", "content": "turn 2"}]


def anthropic_reply(usage=None):
    return {"id": "m", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [{"type": "text", "text": "{}"}], "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": usage or {"input_tokens": 60, "output_tokens": 20,
                               "cache_read_input_tokens": 0,
                               "cache_creation_input_tokens": 0}}


def openai_reply(details=None, input_tokens=1500):
    return {"id": "r", "object": "response", "created_at": 0, "model": "gpt-6-luna",
            "status": "completed", "output": [], "parallel_tool_calls": False,
            "tool_choice": "auto", "tools": [], "incomplete_details": None,
            "usage": {"input_tokens": input_tokens, "output_tokens": 50,
                      "total_tokens": input_tokens + 50,
                      "input_tokens_details": details or {"cached_tokens": 0,
                                                          "cache_write_tokens": 0},
                      "output_tokens_details": {"reasoning_tokens": 0}}}


def adapter(cls, reply):
    seen: list = []

    def handler(req):
        seen.append(req.content)
        return httpx2.Response(200, json=reply)
    return cls(http_client_factory=lambda: httpx2.Client(
        transport=httpx2.MockTransport(handler))), seen


def call_anthropic(a, cache, system="SYSTEM PROMPT", line="line one"):
    return a.call(model="claude-haiku-5-5", system=system,
                  messages=[{"role": "user", "content": line}], max_output_tokens=512,
                  timeout=5, api_key=KEY, request={"thinking": "disabled", "effort": "low"},
                  output_schema=SCHEMA, cache=cache)


def call_openai(a, cache, messages=RED_TURNS):
    return a.call(model="gpt-6-luna", system="RED SYSTEM", messages=messages,
                  max_output_tokens=2048, timeout=5, api_key=KEY,
                  request={"thinking": None, "effort": "low"}, output_schema=SCHEMA,
                  cache=cache)


# -- caching off: the pre-5.7 bytes ------------------------------------------------

def test_caching_off_sends_the_stage_5_4_anthropic_bytes():
    a, seen = adapter(lc.AnthropicAdapter, anthropic_reply())
    call_anthropic(a, cache=False)
    assert seen == [ANTHROPIC_OFF]
    a2, seen2 = adapter(lc.AnthropicAdapter, anthropic_reply())
    a2.call(model="claude-haiku-5-5", system="SYSTEM PROMPT",
            messages=[{"role": "user", "content": "line one"}], max_output_tokens=512,
            timeout=5, api_key=KEY, request={"thinking": "disabled", "effort": "low"},
            output_schema=SCHEMA)  # no cache argument at all = off
    assert seen2 == [ANTHROPIC_OFF]


def test_caching_off_sends_the_stage_5_6_openai_bytes():
    a, seen = adapter(lc.OpenAIAdapter, openai_reply())
    call_openai(a, cache=False)
    assert seen == [OPENAI_OFF]


# -- caching on: only the markers ------------------------------------------------

def test_anthropic_on_adds_only_the_system_breakpoint():
    a, seen = adapter(lc.AnthropicAdapter, anthropic_reply())
    call_anthropic(a, cache=True)
    on, off = json.loads(seen[0]), json.loads(ANTHROPIC_OFF)
    assert on["system"] == [{"type": "text", "text": "SYSTEM PROMPT",
                             "cache_control": {"type": "ephemeral", "ttl": "5m"}}]
    assert {k: v for k, v in on.items() if k != "system"} == \
        {k: v for k, v in off.items() if k != "system"}
    assert "cache_control" not in json.dumps(on["messages"])  # never on the unique line


def test_openai_on_adds_only_breakpoints_and_the_30m_ttl():
    a, seen = adapter(lc.OpenAIAdapter, openai_reply())
    call_openai(a, cache=True)
    on, off = json.loads(seen[0]), json.loads(OPENAI_OFF)
    assert on["prompt_cache_options"] == {"mode": "explicit", "ttl": "30m"}
    assert on["input"] == [
        {"role": "user", "content": [{"type": "input_text", "text": "turn 1",
                                      "prompt_cache_breakpoint": {"mode": "explicit"}}]},
        {"role": "assistant", "content": '{"a": 1}'},
        {"role": "user", "content": [{"type": "input_text", "text": "turn 2",
                                      "prompt_cache_breakpoint": {"mode": "explicit"}}]}]
    rest = ("prompt_cache_options", "input")
    assert {k: v for k, v in on.items() if k not in rest} == \
        {k: v for k, v in off.items() if k not in rest}
    assert "12h" not in seen[0].decode()


def test_blue_prefix_is_byte_identical_across_calls():
    a, seen = adapter(lc.AnthropicAdapter, anthropic_reply())
    _, system, _, _ = claude_engine.PROMPTS["on"]
    call_anthropic(a, True, system=system, line="first line")
    call_anthropic(a, True, system=system, line="second line")
    one, two = (json.loads(b) for b in seen)
    assert one["system"] == two["system"]  # the cached prefix: same bytes
    assert one["messages"] != two["messages"]  # only the line differs
    assert json.dumps(one["system"]).encode() == json.dumps(two["system"]).encode()


def test_red_request_n_plus_1_extends_request_n_byte_for_byte():
    """Every user turn keeps its breakpoint, so the earlier input items never change."""
    a, seen = adapter(lc.OpenAIAdapter, openai_reply())
    turns = [{"role": "user", "content": "turn 1"}]
    call_openai(a, True, turns)
    turns = turns + [{"role": "assistant", "content": '{"a": 1}'},
                     {"role": "user", "content": "turn 2"}]
    call_openai(a, True, turns)
    turns = turns + [{"role": "assistant", "content": '{"a": 2}'},
                     {"role": "user", "content": "turn 3"}]
    call_openai(a, True, turns)
    inputs = [json.loads(b)["input"] for b in seen]
    for prev, nxt in zip(inputs, inputs[1:]):
        assert nxt[:len(prev)] == prev
        assert json.dumps(nxt[:len(prev)]) == json.dumps(prev)
    bps = [m for m in inputs[-1] if m["role"] == "user"]
    assert all(m["content"][0]["prompt_cache_breakpoint"] == {"mode": "explicit"} for m in bps)


def test_ai_red_history_through_the_client_keeps_the_prefix(tmp_path):
    """The real AIRed loop on the fake provider: each call's messages start with the
    previous call's messages (append-only, D11), so the cache markers stay put."""
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["red"]["caching"] = "on"
    fake = FakeAdapter(text=json.dumps({"method": "GET", "path": "/x", "body": "",
                                        "label": "CWE-89", "rationale": "r"}))
    client = lc.LLMClient(config=cfg, prices=PRICES, adapters={"fake": fake}, env={},
                          sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")
    red = ai_red.AIRed(client, "fake-small", tmp_path, "m001", round_cap=3)
    for i in range(1, 4):
        red.propose(None if i == 1 else "HTTP 404", i)
    msgs = [c["messages"] for c in fake.calls]
    assert all(c["cache"] is True for c in fake.calls)
    for prev, nxt in zip(msgs, msgs[1:]):
        assert nxt[:len(prev)] == prev


# -- usage mapping ------------------------------------------------------------

def test_anthropic_cache_read_and_write_map_into_usage():
    a, _ = adapter(lc.AnthropicAdapter, anthropic_reply(
        {"input_tokens": 60, "output_tokens": 20, "cache_read_input_tokens": 900,
         "cache_creation_input_tokens": 0}))
    r = call_anthropic(a, True)
    assert r.usage == lc.Usage(60, 900, 0, 20, 0)
    a, _ = adapter(lc.AnthropicAdapter, anthropic_reply(
        {"input_tokens": 60, "output_tokens": 20, "cache_read_input_tokens": 0,
         "cache_creation_input_tokens": 900,
         "cache_creation": {"ephemeral_5m_input_tokens": 900,
                            "ephemeral_1h_input_tokens": 0}}))
    r = call_anthropic(a, True)
    assert r.usage == lc.Usage(60, 0, 900, 20, 0)
    assert r.raw_usage["cache_creation"]["ephemeral_5m_input_tokens"] == 900


def test_anthropic_1h_write_is_unpriced():
    a, _ = adapter(lc.AnthropicAdapter, anthropic_reply(
        {"input_tokens": 60, "output_tokens": 20, "cache_read_input_tokens": 0,
         "cache_creation_input_tokens": 900,
         "cache_creation": {"ephemeral_5m_input_tokens": 100,
                            "ephemeral_1h_input_tokens": 800}}))
    assert call_anthropic(a, True).usage.unpriced_cache_write_tokens == 800


def test_openai_cache_read_and_write_are_subtracted_from_input():
    a, _ = adapter(lc.OpenAIAdapter, openai_reply(
        {"cached_tokens": 1000, "cache_write_tokens": 300,
         "cache_write_tokens_details": {"ttl_30m_tokens": 300, "ttl_12h_tokens": 0}}))
    r = call_openai(a, True)
    assert r.usage == lc.Usage(200, 1000, 300, 50, 0)
    # the SDK keeps the TTL breakdown it does not model (Gate 1 evidence)
    assert r.raw_usage["input_tokens_details"]["cache_write_tokens_details"] == \
        {"ttl_30m_tokens": 300, "ttl_12h_tokens": 0}


@pytest.mark.parametrize("details,unpriced", [
    ({"ttl_30m_tokens": 100, "ttl_12h_tokens": 200}, 200),
    ({"ttl_30m_tokens": 300, "ttl_24h_tokens": 0}, 0),
    ({"ttl_30m_tokens": 0, "ttl_7d_tokens": 300}, 300),  # an unknown lifetime
    ("opaque", 300),
])
def test_openai_writes_at_another_lifetime_are_unpriced(details, unpriced):
    a, _ = adapter(lc.OpenAIAdapter, openai_reply(
        {"cached_tokens": 0, "cache_write_tokens": 300,
         "cache_write_tokens_details": details}))
    assert call_openai(a, True).usage.unpriced_cache_write_tokens == unpriced


def test_a_12h_breakpoint_in_the_request_makes_every_write_unpriced():
    items = lc.openai_input(RED_TURNS, True)
    items[0]["content"][0]["prompt_cache_breakpoint"]["ttl"] = "12h"
    kw = lc.openai_request_kwargs({"effort": "low"}, None, True)
    assert lc.openai_unpriced_ttl(kw, items) is True
    assert lc.openai_unpriced_ttl(kw, lc.openai_input(RED_TURNS, True)) is False
    assert lc.openai_unpriced_ttl({"prompt_cache_options": {"mode": "explicit",
                                                            "ttl": "12h"}}, []) is True
    u = openai_reply({"cached_tokens": 0, "cache_write_tokens": 300})["usage"]

    class U:  # the SDK object shape openai_usage reads
        input_tokens = u["input_tokens"]
        output_tokens = u["output_tokens"]

        class input_tokens_details:
            cached_tokens = 0
            cache_write_tokens = 300
    assert lc.openai_usage(U, u, unpriced_ttl_sent=True).unpriced_cache_write_tokens == 300


# -- the client: recording, budget stop ----------------------------------------

def client_with(adapter_obj, caching="on"):
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["blue"]["caching"] = caching
    return lc.LLMClient(config=cfg, prices=PRICES, adapters={"fake": adapter_obj}, env={},
                        sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")


def test_cache_flag_reaches_the_adapter_only_when_on(tmp_path):
    for mode, flag in (("on", True), ("off", False)):
        fake = FakeAdapter()
        client_with(fake, mode).complete("blue", "fake-small", "sys",
                                         [{"role": "user", "content": "x"}],
                                         run_dir=tmp_path, log_seq_first=1, log_seq_last=1,
                    match_id="m001")
        assert fake.calls[-1]["cache"] is flag


def test_an_unpriced_write_is_recorded_and_stops_the_match(tmp_path):
    fake = FakeAdapter(usage=lc.Usage(100, 0, 900, 10, unpriced_cache_write_tokens=900))
    c = client_with(fake)
    r1 = c.complete("blue", "fake-small", "sys", [{"role": "user", "content": "x"}],
                    run_dir=tmp_path, log_seq_first=1, log_seq_last=1,
                    match_id="m001")
    assert r1.ok
    r2 = c.complete("blue", "fake-small", "sys", [{"role": "user", "content": "y"}],
                    run_dir=tmp_path, log_seq_first=2, log_seq_last=2,
                    match_id="m001")
    assert r2.refusal == {"scope": "match", "reason": "unpriced_usage"}
    calls = cost.read_calls(tmp_path / lc.API_CALLS)
    assert calls[0]["unpriced_cache_write_tokens"] == 900
    assert calls[0]["schema_version"] == "0.2"
    assert lc.stopped_by(calls, PRICES) == {"scope": "match", "reason": "unpriced_usage"}
    s = cost.summarize(calls, PRICES)
    assert s["unpriced_usage"] and s["lower_bound"]


def test_caching_params_record_mode_and_ttl():
    cfg = copy.deepcopy(lc.load_config())
    assert lc.caching_params(cfg, "blue") == {"mode": "off", "ttl": None}
    assert lc.caching_params(lc.with_caching(cfg, "blue", "on"), "blue") == \
        {"mode": "on", "ttl": "5m"}
    assert lc.caching_params(lc.with_caching(cfg, "red", "on"), "red") == \
        {"mode": "on", "ttl": "30m"}
    assert lc.with_caching(cfg, "blue", None) is cfg
    with pytest.raises(lc.ConfigError):
        lc.with_caching(cfg, "blue", "always")
    on = lc.with_caching(cfg, "blue", "on")
    assert cfg["agents"]["blue"]["caching"] == "off"  # the original is never mutated
    p = claude_engine.blue_params(on, "claude-haiku-5-5", 1, "on")
    assert p["caching"] == {"mode": "on", "ttl": "5m"}
    assert p["system_prompt_sha256"] == claude_engine.SYSTEM_PROMPT_V2_SHA256
    assert ai_red.red_params(lc.with_caching(cfg, "red", "on"), "gpt-6-luna")["caching"] == \
        {"mode": "on", "ttl": "30m"}


def test_prompts_are_unchanged_by_caching():
    """Caching is a cost setting: the prompt text and its hash never change (C1)."""
    import hashlib
    assert claude_engine.SYSTEM_PROMPT_SHA256 == hashlib.sha256(
        claude_engine.SYSTEM_PROMPT.encode()).hexdigest()
    assert claude_engine.SYSTEM_PROMPT_SHA256.startswith("938ea67c385a")
    assert ai_red.RED_PROMPT_VERSION == "1"
