"""OpenAIAdapter (Responses API, openai==3.41.0) against a mock HTTP transport.
No network: every request is answered by `handler`. The key is an obvious fake
built at runtime. Sentinel OPENAI_* values stay set in the environment DURING the
request (designer, Stage 5.6): some SDK settings may be read per request."""

from __future__ import annotations

import json
import os

import httpx2
import pytest

from llm_fakes import lc

TEST_KEY = "-".join(["openai", "adapter", "test", "value", "7"])
REQUEST = {"thinking": None, "effort": "low"}
SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}},
          "required": ["path"], "additionalProperties": False}
SENTINELS = {"OPENAI_API_KEY": "env-sentinel-api-key",
             "OPENAI_ADMIN_KEY": "env-sentinel-admin-key",
             "OPENAI_BASE_URL": "http://env-sentinel.invalid/v1",
             "OPENAI_ORG_ID": "env-sentinel-org",
             "OPENAI_PROJECT_ID": "env-sentinel-project",
             "OPENAI_WEBHOOK_SECRET": "env-sentinel-webhook",
             "OPENAI_CUSTOM_HEADERS": "X-Env-Sentinel: injected\nAuthorization: Bearer env-sentinel-auth"}


def body(output, status="completed", usage=None, incomplete=None):
    return {"id": "resp_test", "object": "response", "created_at": 0, "model": "gpt-6-luna",
            "status": status, "output": output, "parallel_tool_calls": False,
            "tool_choice": "auto", "tools": [], "incomplete_details": incomplete,
            "usage": usage or {"input_tokens": 900, "output_tokens": 300,
                               "total_tokens": 1200,
                               "input_tokens_details": {"cached_tokens": 0,
                                                        "cache_write_tokens": 0},
                               "output_tokens_details": {"reasoning_tokens": 120}}}


def message(*content):
    return {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
            "content": list(content)}


def text(t):
    return {"type": "output_text", "text": t, "annotations": []}


def adapter_with(reply: dict, status: int = 200, env_seen: list | None = None):
    seen: list = []

    def handler(req):
        seen.append(req)
        if env_seen is not None:  # prove the sentinels were present at request time
            env_seen.append({k: os.environ.get(k) for k in SENTINELS})
        return httpx2.Response(status, json=reply)
    a = lc.OpenAIAdapter(
        http_client_factory=lambda: httpx2.Client(transport=httpx2.MockTransport(handler)))
    return a, seen


def call(a, request=REQUEST, output_schema=SCHEMA):
    return a.call(model="gpt-6-luna", system="sys", messages=[
        {"role": "user", "content": "hello"}], max_output_tokens=2048, timeout=5,
        api_key=TEST_KEY, request=request, output_schema=output_schema)


@pytest.fixture
def hostile_env(monkeypatch):
    for name, val in SENTINELS.items():
        monkeypatch.setenv(name, val)


def test_only_our_key_goes_only_to_the_api_host_with_sentinels_set_during_the_request(
        hostile_env):
    env_seen: list = []
    a, seen = adapter_with(body([message(text("{}"))]), env_seen=env_seen)
    call(a)
    assert env_seen == [SENTINELS]  # every sentinel was in os.environ during the request
    [req] = seen
    assert str(req.url) == "https://api.openai.com/v1/responses"
    assert req.headers["authorization"] == f"Bearer {TEST_KEY}"
    names = {k.lower() for k in req.headers}
    assert not names & {"openai-organization", "openai-project", "x-env-sentinel"}
    blob = "\n".join(f"{k}: {v}" for k, v in req.headers.items()) + req.content.decode()
    assert "env-sentinel" not in blob
    assert {k: os.environ.get(k) for k in SENTINELS} == SENTINELS  # restored afterwards


def test_env_is_restored_even_when_the_call_fails(hostile_env):
    a, _ = adapter_with({"error": {"message": "boom", "type": "server_error"}}, status=500)
    with pytest.raises(Exception):
        call(a)
    assert {k: os.environ.get(k) for k in SENTINELS} == SENTINELS


def test_request_carries_exactly_the_configured_settings():
    a, seen = adapter_with(body([message(text("{}"))]))
    call(a)
    sent = json.loads(seen[0].content)
    assert sent["model"] == "gpt-6-luna" and sent["instructions"] == "sys"
    assert sent["input"] == [{"role": "user", "content": "hello"}]
    assert sent["max_output_tokens"] == 2048 and sent["store"] is False
    assert sent["reasoning"] == {"effort": "low"}
    assert sent["text"] == {"format": {"type": "json_schema", "name": "response",
                                       "schema": SCHEMA, "strict": True}}
    assert sent["prompt_cache_options"] == {"mode": "explicit"}
    for sampling in ("temperature", "top_p"):
        assert sampling not in sent


def test_unset_settings_are_not_sent_and_thinking_is_refused():
    a, seen = adapter_with(body([message(text("{}"))]))
    call(a, request={"thinking": None, "effort": None}, output_schema=None)
    sent = json.loads(seen[0].content)
    assert "reasoning" not in sent and "text" not in sent and sent["store"] is False
    with pytest.raises(lc.ConfigError, match="thinking"):
        call(a, request={"thinking": "disabled", "effort": None})


def test_reasoning_items_are_never_the_answer_and_usage_is_mapped():
    usage = {"input_tokens": 1000, "output_tokens": 300, "total_tokens": 1300,
             "input_tokens_details": {"cached_tokens": 600, "cache_write_tokens": 100},
             "output_tokens_details": {"reasoning_tokens": 250}}
    reasoning = {"type": "reasoning", "id": "rs_1", "summary": []}
    a, _ = adapter_with(body([reasoning, message(text('{"path": "/"}'))], usage=usage))
    r = call(a)
    assert r.text == '{"path": "/"}' and r.stop_reason == "completed"
    # input_tokens is the whole prompt: full-price = 1000 - 600 cached - 100 written;
    # output_tokens already contains the 250 reasoning tokens (billed as output).
    assert r.usage == lc.Usage(input_tokens=300, cached_input_tokens=600,
                               cache_write_tokens=100, output_tokens=300)
    assert r.raw_usage["output_tokens_details"]["reasoning_tokens"] == 250


def test_incomplete_at_the_cap_is_max_tokens():
    a, _ = adapter_with(body([message(text('{"pa'))], status="incomplete",
                             incomplete={"reason": "max_output_tokens"}))
    r = call(a)
    assert r.stop_reason == "max_tokens" and r.text == '{"pa'


def test_other_incomplete_reasons_are_kept():
    a, _ = adapter_with(body([], status="incomplete", incomplete={"reason": "content_filter"}))
    assert call(a).stop_reason == "incomplete:content_filter"


def test_refusal_item_is_a_refusal():
    a, _ = adapter_with(body([message({"type": "refusal", "refusal": "I can't help."})]))
    r = call(a)
    assert r.stop_reason == "refusal" and r.text == ""


def test_http_error_is_classified_without_the_key():
    a, _ = adapter_with({"error": {"message": "slow down", "type": "rate_limit"}}, status=429)
    with pytest.raises(Exception) as ei:
        call(a)
    kind, status, _ = lc.classify(ei.value)
    assert (kind, status) == ("rate_limit", 429)
    assert TEST_KEY not in str(ei.value) and TEST_KEY not in repr(ei.value)


# -- DeepSeek (Stage 6.3 Red candidate): the same adapter, DeepSeek's base URL ------------

def deepseek_with(reply: dict, env_seen: list | None = None):
    seen: list = []

    def handler(req):
        seen.append(req)
        if env_seen is not None:
            env_seen.append({k: os.environ.get(k) for k in SENTINELS})
        return httpx2.Response(200, json=reply)
    a = lc.DeepSeekAdapter(
        http_client_factory=lambda: httpx2.Client(transport=httpx2.MockTransport(handler)))
    return a, seen


def test_deepseek_goes_only_to_its_host_with_only_our_key(hostile_env):
    env_seen: list = []
    a, seen = deepseek_with(body([message(text("{}"))]), env_seen=env_seen)
    assert a.provider == "deepseek" and lc.is_real(lc.DeepSeekAdapter())
    a.call(model="deepseek-v4-pro", system="sys", messages=[{"role": "user", "content": "hi"}],
           max_output_tokens=8192, timeout=5, api_key=TEST_KEY,
           request={"thinking": None, "effort": "max"}, output_schema=SCHEMA, cache=True,
           cache_turns=True)
    assert env_seen == [SENTINELS]
    [req] = seen
    assert str(req.url) == "https://api.deepseek.com/responses"
    assert req.headers["authorization"] == f"Bearer {TEST_KEY}"
    blob = "\n".join(f"{k}: {v}" for k, v in req.headers.items()) + req.content.decode()
    assert "env-sentinel" not in blob
    sent = json.loads(req.content)
    assert sent["model"] == "deepseek-v4-pro" and sent["reasoning"] == {"effort": "max"}
    assert sent["input"] == [{"role": "user", "content": "hi"}]  # no cache breakpoints
    assert "prompt_cache_options" not in sent and "prompt_cache_breakpoint" not in blob
    assert sent["text"]["format"]["type"] == "json_schema" and sent["store"] is False
    assert sent["max_output_tokens"] == 8192
    assert {k: os.environ.get(k) for k in SENTINELS} == SENTINELS


def test_openai_bytes_are_unchanged_by_the_deepseek_subclass():
    a, seen = adapter_with(body([message(text("{}"))]))
    call(a)
    sent = json.loads(seen[0].content)
    assert str(seen[0].url) == "https://api.openai.com/v1/responses"
    assert sent["prompt_cache_options"] == {"mode": "explicit"}


# -- reachability probe + cause chain (2026-11-27 demo incident) --------------------------

def _probe_client(handler, key=TEST_KEY):
    """An LLMClient whose deepseek adapter is the real one on a mock transport (not real:
    no GO needed); the key comes from the client's env, as in a match."""
    a = lc.DeepSeekAdapter(
        http_client_factory=lambda: httpx2.Client(transport=httpx2.MockTransport(handler)))
    cfg = lc.load_config()
    cfg["agents"]["red"]["provider"] = "deepseek"
    env = {} if key is None else {"ARENA_DEEPSEEK_API_KEY": key}
    return lc.LLMClient(config=cfg, adapters={"deepseek": a}, env=env,
                        dotenv_path=lc.REPO / "nonexistent" / "no.env")


def test_probe_is_one_get_of_the_models_endpoint_with_our_key_and_writes_nothing(
        hostile_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = []

    def handler(req):
        seen.append(req)
        return httpx2.Response(200, json={"object": "list", "data": []})
    r = _probe_client(handler).reachable("red")
    assert (r.ok, r.provider, r.kind, r.http_status, r.cause) == (True, "deepseek", "ok", 200, "")
    [req] = seen
    assert req.method == "GET" and str(req.url) == "https://api.deepseek.com/models"
    assert req.headers["authorization"] == f"Bearer {TEST_KEY}"
    assert "env-sentinel" not in "\n".join(f"{k}: {v}" for k, v in req.headers.items())
    assert list(tmp_path.iterdir()) == []  # no api_calls.jsonl, nothing anywhere


@pytest.mark.parametrize("status, kind", [(401, "auth"), (403, "auth"), (503, "server_error"),
                                          (429, "rate_limit")])
def test_probe_reports_http_failures_by_kind_never_the_message(status, kind):
    # DeepSeek's real 401 text echoes the key's last characters: never in the result.
    msg = f"Authentication Fails, Your api key: ****{TEST_KEY[-4:]} is invalid"
    r = _probe_client(lambda req: httpx2.Response(status, json={"error": {"message": msg}})) \
        .reachable("red")
    assert (r.ok, r.kind, r.http_status) == (False, kind, status)
    assert TEST_KEY[-4:] not in repr(r) and "Authentication" not in repr(r)


def test_probe_connection_failure_names_the_cause_type():
    def handler(req):
        raise httpx2.ConnectError("[Errno 8] nodename nor servname provided")
    r = _probe_client(handler).reachable("red")
    assert (r.ok, r.kind, r.http_status) == (False, "connection", None)
    assert r.cause == " [cause: ConnectError]" and "nodename" not in repr(r)


def test_probe_without_a_key_sends_nothing():
    seen = []
    r = _probe_client(lambda req: seen.append(req), key=None).reachable("red")
    assert (r.ok, r.kind) == (False, "missing_key") and seen == []


def test_probe_needs_the_go_token_like_a_call(monkeypatch):
    monkeypatch.delenv("ARENA_GO", raising=False)
    with pytest.raises(lc.GoTokenError):
        lc.DeepSeekAdapter().probe(api_key=TEST_KEY, timeout=1)


def test_fake_adapters_have_no_network_to_probe():
    from llm_fakes import FakeAdapter, make_client
    r = make_client(FakeAdapter())[0].reachable("red")
    assert (r.ok, r.kind) == (True, "no_network")


def test_call_and_probe_build_the_same_client():
    """'Reached the way a Red call is': one builder, used by both."""
    import inspect
    for cls in (lc.OpenAIAdapter, lc.AnthropicAdapter):
        assert "self._client(api_key, timeout)" in inspect.getsource(cls.call)
        assert "self._client(api_key, timeout)" in inspect.getsource(cls.probe)


def test_ledger_excerpt_carries_the_cause_chain_types_only(tmp_path):
    """The incident's ledger said only 'APIConnectionError: Connection error.'. A key with an
    illegal header character and a DNS failure must now be told apart, by type name, and
    the cause's message (which can quote the header, i.e. the key) is never written."""
    from llm_fakes import FakeAdapter, lines, make_client

    class APIConnectionError(Exception):
        pass

    class LocalProtocolError(Exception):
        pass
    key_like = "-".join(["sk", "quoted", "in", "the", "header"])
    exc = APIConnectionError("Connection error.")
    exc.__cause__ = LocalProtocolError(f"Illegal header value b'Bearer {key_like}\\n'")
    client, _ = make_client(FakeAdapter([exc] * 9))
    res = client.complete("red", "fake-small", "s", [{"role": "user", "content": "u"}],
                          run_dir=tmp_path, round=1, match_id="m001")
    assert not res.ok and res.error_type == "connection"
    rows = lines(tmp_path)
    assert rows and all(r["error_excerpt"] == "APIConnectionError: Connection error. "
                                              "[cause: LocalProtocolError]" for r in rows)
    assert key_like not in (tmp_path / lc.API_CALLS).read_text()


def test_cause_chain_follows_cause_then_context_and_stops():
    try:
        try:
            raise OSError("inner")
        except OSError as inner:
            raise ValueError("mid") from inner
    except ValueError as mid:
        top = RuntimeError("top")
        top.__context__ = mid
    assert lc.cause_chain(top) == " [cause: ValueError <- OSError]"
    assert lc.cause_chain(RuntimeError("alone")) == ""
    a, b = RuntimeError("a"), RuntimeError("b")
    a.__cause__, b.__cause__ = b, a  # a cycle never loops
    assert lc.cause_chain(a) == " [cause: RuntimeError]"
