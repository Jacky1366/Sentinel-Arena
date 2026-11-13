"""AnthropicAdapter against a mock HTTP transport (anthropic==2.3.0, httpx2).
No network: every request is answered by `handler` below. The key is an obvious
fake built at runtime."""

from __future__ import annotations

import json

import httpx2
import pytest

from llm_fakes import lc

TEST_KEY = "-".join(["adapter", "test", "value", "42"])
REQUEST = {"thinking": "disabled", "effort": "low"}
SCHEMA = {"type": "object", "properties": {"verdicts": {"type": "array"}},
          "required": ["verdicts"], "additionalProperties": False}


def body(content, stop_reason="end_turn", usage=None):
    return {"id": "msg_test", "type": "message", "role": "assistant",
            "model": "claude-haiku-5-5", "content": content, "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": usage or {"input_tokens": 900, "output_tokens": 40,
                               "cache_read_input_tokens": 0,
                               "cache_creation_input_tokens": 0}}


def adapter_with(reply: dict, status: int = 200):
    seen: list = []

    def handler(req):
        seen.append(req)
        return httpx2.Response(status, json=reply)
    a = lc.AnthropicAdapter(
        http_client_factory=lambda: httpx2.Client(transport=httpx2.MockTransport(handler)))
    return a, seen


def call(a, request=REQUEST, output_schema=SCHEMA):
    return a.call(model="claude-haiku-5-5", system="sys", messages=[
        {"role": "user", "content": "hello"}], max_output_tokens=256, timeout=5,
        api_key=TEST_KEY, request=request, output_schema=output_schema)


@pytest.fixture
def hostile_env(monkeypatch):
    """Every variable the SDK could otherwise use for credentials or the host."""
    for name, val in {"ANTHROPIC_API_KEY": "env-sentinel-api-key",
                      "ANTHROPIC_AUTH_TOKEN": "env-sentinel-auth-token",
                      "ANTHROPIC_BASE_URL": "http://env-sentinel.invalid",
                      "ANTHROPIC_PROFILE": "env-sentinel-profile"}.items():
        monkeypatch.setenv(name, val)


def test_only_our_key_goes_only_to_the_api_host(hostile_env):
    a, seen = adapter_with(body([{"type": "text", "text": "{}"}]))
    call(a)
    [req] = seen
    assert str(req.url) == "https://api.anthropic.com/v1/messages"
    headers = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
    assert TEST_KEY in headers
    assert "env-sentinel" not in headers and "env-sentinel" not in req.content.decode()


def test_request_carries_exactly_the_configured_settings():
    a, seen = adapter_with(body([{"type": "text", "text": "{}"}]))
    call(a)
    sent = json.loads(seen[0].content)
    assert sent["max_tokens"] == 256 and sent["system"] == "sys"
    assert sent["thinking"] == {"type": "disabled"}
    assert sent["output_config"] == {"effort": "low",
                                     "format": {"type": "json_schema", "schema": SCHEMA}}
    for sampling in ("temperature", "top_p", "top_k"):
        assert sampling not in sent


def test_unset_settings_are_not_sent():
    a, seen = adapter_with(body([{"type": "text", "text": "{}"}]))
    call(a, request={"thinking": None, "effort": None}, output_schema=None)
    sent = json.loads(seen[0].content)
    assert "thinking" not in sent and "output_config" not in sent


def test_thinking_blocks_are_never_the_answer():
    a, _ = adapter_with(body([{"type": "thinking", "thinking": "CWE-89?", "signature": "s"},
                              {"type": "text", "text": '{"verdicts": []}'}]))
    assert call(a).text == '{"verdicts": []}'


def test_stop_reason_and_usage_are_mapped():
    usage = {"input_tokens": 900, "output_tokens": 40, "cache_read_input_tokens": 100,
             "cache_creation_input_tokens": 20}
    a, _ = adapter_with(body([], stop_reason="refusal", usage=usage))
    r = call(a)
    assert r.stop_reason == "refusal" and r.text == ""
    assert r.usage == lc.Usage(input_tokens=900, cached_input_tokens=100,
                               cache_write_tokens=20, output_tokens=40)
    assert r.raw_usage["input_tokens"] == 900


def test_http_error_is_raised_and_classified_without_the_key():
    a, _ = adapter_with({"type": "error", "error": {"type": "overloaded_error",
                                                     "message": "busy"}}, status=529)
    with pytest.raises(Exception) as ei:
        call(a)
    kind, status, _ = lc.classify(ei.value)
    assert status == 529 and kind
    assert TEST_KEY not in str(ei.value) and TEST_KEY not in repr(ei.value)
