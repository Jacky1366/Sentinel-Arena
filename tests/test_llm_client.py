"""agents/llm_client.py: usage per attempt, retry policy, caps, refusals.
Fake provider only: no network, no SDKs, no keys, zero token cost."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from llm_fakes import (CONFIG, MESSAGES, PRICES, SYSTEM, APITimeoutError, FakeAdapter,
                       FakeError, config, lc, lines, make_client, run_dir)


def blue(client, d, **kw):
    return client.complete("blue", kw.pop("model", "fake-small"), SYSTEM, MESSAGES,
                           run_dir=d, log_seq_first=1, log_seq_last=1, **kw)


def red(client, d, model="fake-small"):
    return client.complete("red", model, SYSTEM, MESSAGES, run_dir=d, round=1)


# ---- usage recorded per attempt -------------------------------------------

def test_success_records_one_attempt_with_usage(tmp_path):
    d = run_dir(tmp_path)
    client, _ = make_client(FakeAdapter(usage=lc.Usage(1200, 300, 0, 80)))
    r = blue(client, d)
    assert r.ok and r.text and r.attempts == 1 and r.usage.output_tokens == 80
    [line] = lines(d)
    assert line["ok"] is True and line["attempt"] == 1 and line["error_type"] is None
    assert (line["input_tokens"], line["cached_input_tokens"], line["cache_write_tokens"],
            line["output_tokens"]) == (1200, 300, 0, 80)
    assert line["agent"] == "blue" and line["provider"] == "fake"
    assert line["match_id"] == d.name and line["latency_ms"] == 250
    assert (line["round"], line["log_seq_first"], line["log_seq_last"]) == (None, 1, 1)


def test_prompt_hash_stored_not_prompt_text(tmp_path):
    d = run_dir(tmp_path)
    client, _ = make_client()
    blue(client, d)
    [line] = lines(d)
    want = hashlib.sha256(lc.canonical_prompt("fake-small", SYSTEM, MESSAGES)
                          .encode()).hexdigest()
    assert line["prompt_sha256"] == want
    raw = (d / lc.API_CALLS).read_text()
    assert SYSTEM not in raw and "apple" not in raw


def test_failed_attempts_are_recorded_with_null_usage(tmp_path):
    d = run_dir(tmp_path)
    client, _ = make_client(FakeAdapter([APITimeoutError("slow"), "ok"]))
    r = blue(client, d)
    assert r.ok and r.attempts == 2
    first, second = lines(d)
    assert (first["ok"], first["error_type"], first["attempt"]) == (False, "timeout", 1)
    assert first["input_tokens"] is None and first["output_tokens"] is None
    assert (second["ok"], second["attempt"]) == (True, 2)


# ---- retry policy ---------------------------------------------------------

@pytest.mark.parametrize("exc,kind", [
    (APITimeoutError("t"), "timeout"),
    (TimeoutError("t"), "timeout"),
    (FakeError("busy", status_code=429), "rate_limit"),
    (FakeError("oops", status_code=503), "server_error"),
    (ConnectionError("reset"), "connection"),
])
def test_retryable_error_then_success(tmp_path, exc, kind):
    d = run_dir(tmp_path)
    client, sleeps = make_client(FakeAdapter([exc, "ok"]))
    r = blue(client, d)
    assert r.ok and r.attempts == 2
    assert [l["error_type"] for l in lines(d)] == [kind, None]
    assert sleeps == [1.0]


def test_backoff_is_exponential_capped_and_honours_retry_after(tmp_path):
    d = run_dir(tmp_path)
    cfg = config()
    cfg["backoff_max_s"] = 3.0
    client, sleeps = make_client(FakeAdapter([
        FakeError("x", status_code=500), FakeError("x", status_code=500),
        FakeError("x", status_code=429, retry_after=2.5), "ok"]), cfg=cfg)
    assert blue(client, d).ok
    assert sleeps == [1.0, 2.0, 3.0]  # 1, 2, then max(4, 2.5) capped at 3


@pytest.mark.parametrize("status,kind", [(400, "bad_request"), (401, "auth"),
                                         (403, "auth"), (404, "bad_request")])
def test_non_retryable_fails_fast(tmp_path, status, kind):
    d = run_dir(tmp_path)
    adapter = FakeAdapter([FakeError("no", status_code=status), "ok"])
    client, sleeps = make_client(adapter)
    r = blue(client, d)
    assert not r.ok and r.error_type == kind and r.attempts == 1
    assert len(adapter.calls) == 1 and sleeps == []
    [line] = lines(d)
    assert line["http_status"] == status


def test_unknown_exception_is_not_retried(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter([ValueError("weird")])
    client, _ = make_client(adapter)
    r = blue(client, d)
    assert not r.ok and r.error_type == "other" and len(adapter.calls) == 1


def test_retries_exhausted_is_a_structured_failure_not_a_crash(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter([APITimeoutError("t")] * 10)
    client, sleeps = make_client(adapter)
    r = blue(client, d)  # must not raise
    assert not r.ok and r.error_type == "timeout" and r.attempts == 4
    assert [l["attempt"] for l in lines(d)] == [1, 2, 3, 4]
    assert sleeps == [1.0, 2.0, 4.0]
    # the match continues: the next call goes through
    adapter.script = []
    assert blue(client, d).ok


# ---- caps -------------------------------------------------------------------

def runaway(client, d, call=blue, limit=500):
    """A buggy agent loop that never stops on its own."""
    for _ in range(limit):
        r = call(client, d)
        if r.refusal is not None:
            return r
    raise AssertionError("the body never stopped the loop")


def test_max_calls_stops_runaway_loop(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()
    client, _ = make_client(adapter, cfg=config(blue={"max_calls": 5}))
    r = runaway(client, d)
    assert r.refusal == {"scope": "blue", "reason": "max_calls"}
    assert len(adapter.calls) == 5
    assert lines(d)[-1]["error_type"] == "refused" and lines(d)[-1]["latency_ms"] == 0


def test_max_tokens_stops_before_the_call_that_could_exceed(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()
    client, _ = make_client(adapter, cfg=config(blue={"max_tokens": 2000}))
    r = runaway(client, d)
    assert r.refusal == {"scope": "blue", "reason": "max_tokens"}
    used = sum(l["input_tokens"] + l["output_tokens"] for l in lines(d) if l["ok"])
    assert used <= 2000 and len(adapter.calls) >= 1


def test_max_usd_stops_runaway_loop(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()  # actual usage within the worst-case estimate
    client, _ = make_client(adapter, cfg=config(blue={"max_usd": 0.001}))
    r = runaway(client, d)
    assert r.refusal == {"scope": "blue", "reason": "max_usd"}
    from stats import cost
    assert cost.summarize(lines(d), PRICES)["total_usd"] <= 0.001  # never exceeded
    assert len(adapter.calls) >= 2


def test_estimate_too_low_overshoots_by_at_most_one_call(tmp_path):
    # Documented fallback: if a reply is far bigger than the estimate, the cap is
    # exceeded by at most that one call, and the next call is refused.
    d = run_dir(tmp_path)
    adapter = FakeAdapter(usage=lc.Usage(50000, 0, 0, 100))  # $0.0502 per call
    client, _ = make_client(adapter, cfg=config(blue={"max_usd": 0.05}))
    r = runaway(client, d)
    assert r.refusal == {"scope": "blue", "reason": "max_usd"}
    from stats import cost
    assert len(adapter.calls) == 1
    assert 0.05 < cost.summarize(lines(d), PRICES)["total_usd"] <= 0.05 + 0.0502


def test_match_total_stops_runaway_loop(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter(usage=lc.Usage(5000, 0, 0, 100))
    client, _ = make_client(adapter, cfg=config(match={"max_usd": 0.02}))
    r = runaway(client, d)
    assert r.refusal == {"scope": "match", "reason": "max_usd"}


def test_worst_case_estimate_refuses_a_single_oversized_call(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()
    client, _ = make_client(adapter, cfg=config(blue={"max_tokens": 50}))
    r = blue(client, d)  # max_output_tokens alone (100) is over the cap
    assert r.refusal == {"scope": "blue", "reason": "max_tokens"} and adapter.calls == []


def test_retries_count_toward_max_calls(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter([APITimeoutError("t")] * 10)
    client, _ = make_client(adapter, cfg=config(blue={"max_calls": 2}))
    r = blue(client, d)
    assert r.refusal == {"scope": "blue", "reason": "max_calls"} and r.attempts == 2
    assert [l["error_type"] for l in lines(d)] == ["timeout", "timeout", "refused"]
    assert lines(d)[-1]["attempt"] == 3


def test_red_can_never_spend_blues_share(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()
    client, _ = make_client(adapter, cfg=config(red={"max_calls": 3}, blue={"max_calls": 3}))
    assert runaway(client, d, call=red).refusal == {"scope": "red", "reason": "max_calls"}
    assert all(blue(client, d).ok for _ in range(3))
    assert blue(client, d).refusal == {"scope": "blue", "reason": "max_calls"}


def test_analyst_caps_zero_refuse_everything(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()
    client, _ = make_client(adapter)
    r = client.complete("analyst", "fake-small", SYSTEM, MESSAGES, run_dir=d)
    assert r.refusal == {"scope": "analyst", "reason": "max_calls"} and adapter.calls == []


def test_unpriced_cache_write_stops_all_further_calls(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter([lc.Usage(10, 0, 500, 5)])
    client, _ = make_client(adapter)
    assert blue(client, d, model="fake-nowrite").ok
    r = red(client, d)
    assert r.refusal == {"scope": "match", "reason": "unpriced_usage"}
    assert len(adapter.calls) == 1
    assert lc.stopped_by(lines(d), PRICES) == {"scope": "match", "reason": "unpriced_usage"}


def test_unpriced_usage_without_a_later_call_still_reported(tmp_path):
    d = run_dir(tmp_path)
    client, _ = make_client(FakeAdapter([lc.Usage(10, 0, 500, 5)]))
    blue(client, d, model="fake-nowrite")
    assert lc.stopped_by(lines(d), PRICES) == {"scope": "match", "reason": "unpriced_usage"}


def test_stopped_by_is_the_first_refusal(tmp_path):
    d = run_dir(tmp_path)
    client, _ = make_client(cfg=config(red={"max_calls": 0}, blue={"max_calls": 0}))
    red(client, d)
    blue(client, d)
    assert lc.stopped_by(lines(d), PRICES) == {"scope": "red", "reason": "max_calls"}
    assert lc.stopped_by([], PRICES) is None


# ---- price and key refusals -----------------------------------------------

def test_missing_price_entry_refuses_the_call(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter()
    client, _ = make_client(adapter)
    r = blue(client, d, model="no-such-model")
    assert r.refusal == {"scope": "blue", "reason": "missing_price"} and adapter.calls == []
    [line] = lines(d)
    assert line["provider"] is None and line["error_type"] == "refused"


def test_placeholder_model_is_never_callable(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter(provider="openai", needs_key=True)
    client, _ = make_client(adapter, prices=lc.cost_mod.load_prices())
    r = red(client, d, model="GPT-6 Luna")
    assert r.refusal["reason"] == "missing_price" and adapter.calls == []


def test_missing_key_refuses_and_never_uses_the_sdk_default_variable(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter(provider="anthropic", needs_key=True)
    env = {"ANTHROPIC_API_KEY": "sdk-default-var-must-be-ignored"}
    client, _ = make_client(adapter, env=env, tmp_path=tmp_path)
    r = blue(client, d, model="fake-keyed")
    assert r.refusal == {"scope": "blue", "reason": "missing_key"} and adapter.calls == []


def test_arena_key_is_passed_explicitly(tmp_path):
    d = run_dir(tmp_path)
    adapter = FakeAdapter(provider="anthropic", needs_key=True)
    client, _ = make_client(adapter, env={"ARENA_ANTHROPIC_API_KEY": "arena-test-value-1"},
                            tmp_path=tmp_path)
    assert blue(client, d, model="fake-keyed").ok
    assert adapter.calls[0]["api_key"] == "arena-test-value-1"


def test_key_read_from_dotenv_when_not_in_environment(tmp_path):
    d = run_dir(tmp_path)
    (tmp_path / "no.env").write_text("ARENA_ANTHROPIC_API_KEY=arena-dotenv-value-2\n")
    adapter = FakeAdapter(provider="anthropic", needs_key=True)
    client, _ = make_client(adapter, tmp_path=tmp_path)
    assert blue(client, d, model="fake-keyed").ok
    assert adapter.calls[0]["api_key"] == "arena-dotenv-value-2"


@pytest.mark.parametrize("adapter", [lc.AnthropicAdapter(), lc.OpenAIAdapter()])
def test_real_adapters_refuse_to_call_without_an_explicit_key(adapter):
    with pytest.raises(lc.ConfigError):
        adapter.call(model="m", system="s", messages=[], max_output_tokens=1, timeout=1,
                     api_key=None)


def test_key_env_names_are_arena_prefixed():
    assert lc.KEY_ENV == {"openai": "ARENA_OPENAI_API_KEY",
                          "anthropic": "ARENA_ANTHROPIC_API_KEY",
                          "gemini": "ARENA_GEMINI_API_KEY"}


# ---- usage mapping (VERIFY AT FIRST REAL CALL) -----------------------------

def test_anthropic_usage_mapping():
    u = SimpleNamespace(input_tokens=100, cache_read_input_tokens=900,
                        cache_creation_input_tokens=50, output_tokens=20)
    assert lc.anthropic_usage(u) == lc.Usage(100, 900, 50, 20)
    bare = SimpleNamespace(input_tokens=100, output_tokens=20)
    assert lc.anthropic_usage(bare) == lc.Usage(100, 0, 0, 20)


def test_openai_usage_mapping_subtracts_cached_from_prompt():
    u = SimpleNamespace(prompt_tokens=1000, completion_tokens=40,
                        prompt_tokens_details=SimpleNamespace(cached_tokens=768))
    assert lc.openai_usage(u) == lc.Usage(232, 768, 0, 40)
    assert lc.openai_usage(SimpleNamespace(prompt_tokens=10, completion_tokens=1,
                                           prompt_tokens_details=None)) == lc.Usage(10, 0, 0, 1)


def test_classify_reads_status_from_response_and_retry_after_header():
    exc = Exception("x")
    exc.response = SimpleNamespace(status_code=429, headers={"retry-after": "7"})
    assert lc.classify(exc) == ("rate_limit", 429, 7.0)


# ---- config and argument rules --------------------------------------------

def test_committed_config_loads_with_designer_caps():
    cfg = lc.load_config()
    assert lc.caps_limits(cfg) == {
        "red": {"max_calls": 60, "max_tokens": 400000, "max_usd": 0.25},
        "blue": {"max_calls": 100, "max_tokens": 300000, "max_usd": 0.25},
        "analyst": {"max_calls": 0, "max_tokens": 0, "max_usd": 0},
        "match": {"max_calls": None, "max_tokens": None, "max_usd": 0.50}}
    assert cfg["provider_caching"] is False


@pytest.mark.parametrize("mutate", [
    lambda c: c["caps"].pop("analyst"),
    lambda c: c["caps"]["red"].update(max_usd=None),
    lambda c: c["caps"]["blue"].pop("max_tokens"),
    lambda c: c["caps"]["match"].update(max_usd=-1),
    lambda c: c.update(provider_caching=True),
    lambda c: c.pop("timeout_s"),
])
def test_bad_config_is_rejected(tmp_path, mutate):
    cfg = json.loads(json.dumps(CONFIG))
    mutate(cfg)
    p = tmp_path / "llm.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(lc.ConfigError):
        lc.load_config(p)


@pytest.mark.parametrize("agent,kw", [
    ("blue", {"round": 1}), ("red", {"log_seq_first": 1}),
    ("analyst", {"log_seq_last": 2}), ("judge", {}),
])
def test_position_fields_follow_the_agent(tmp_path, agent, kw):
    client, _ = make_client()
    with pytest.raises(ValueError):
        client.complete(agent, "fake-small", SYSTEM, MESSAGES, run_dir=run_dir(tmp_path), **kw)
