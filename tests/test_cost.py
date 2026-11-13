"""stats/cost.py: dollars derived from token counts and a dated price table. Pure."""

from __future__ import annotations

import copy
import json

import pytest

from llm_fakes import PRICES
from stats import cost

HAIKU_LIKE = {
    **PRICES,
    "models": {"tiered": {"provider": "anthropic", "as_of": "2026-11-08", "source": "t",
                          "verified": False,
                          "tiers": [{"max_prompt_tokens": 100000, "input": 0.10,
                                     "cached_input": 0.01, "cache_write": 0.125, "output": 0.50},
                                    {"max_prompt_tokens": None, "input": 0.50,
                                     "cached_input": 0.05, "cache_write": 0.625, "output": 2.50}]},
               **PRICES["models"]},
}


def call(model="fake-small", agent="blue", ok=True, i=0, c=0, w=0, o=0, refusal=None):
    line = {"agent": agent, "model": model, "ok": ok, "refusal": refusal,
            "error_type": None if ok else ("refused" if refusal else "timeout"),
            "input_tokens": i, "cached_input_tokens": c, "cache_write_tokens": w,
            "output_tokens": o}
    return line


def test_basic_math():
    # fake-small: input 1.0, cached 0.1, write 1.25, output 2.0 per million
    c = cost.call_cost(call(i=1_000_000, o=500_000), PRICES)
    assert c["usd"] == pytest.approx(1.0 + 1.0)


@pytest.mark.parametrize("prompt,expected_input_price", [(100_000, 0.10), (100_001, 0.50)])
def test_tier_selected_by_whole_prompt_size(prompt, expected_input_price):
    c = cost.call_cost(call("tiered", i=prompt, o=0), HAIKU_LIKE)
    assert c["usd"] == pytest.approx(prompt * expected_input_price / 1e6)


def test_cached_and_cache_write_tokens_count_toward_the_tier():
    # 60K full-price + 50K cached = 110K prompt -> upper tier for every component
    c = cost.call_cost(call("tiered", i=60_000, c=50_000, o=1000), HAIKU_LIKE)
    assert c["usd"] == pytest.approx((60_000 * 0.50 + 50_000 * 0.05 + 1000 * 2.50) / 1e6)


def test_cache_savings_positive_net_of_reads():
    c = cost.call_cost(call(i=0, c=1_000_000), PRICES)
    assert c["savings_usd"] == pytest.approx(1.0 - 0.1)


def test_cache_savings_negative_when_writes_never_get_read():
    c = cost.call_cost(call(i=0, w=1_000_000), PRICES)  # pays the 25% write premium
    assert c["savings_usd"] == pytest.approx(-0.25)
    s = cost.summarize([call(i=0, w=1_000_000)], PRICES)
    assert s["cache_savings_usd"] == pytest.approx(-0.25)  # reported as is


def test_null_cached_price_charges_full_input_and_flags():
    c = cost.call_cost(call("fake-nowrite", i=0, c=1_000_000), PRICES)
    assert c["usd"] == pytest.approx(1.0) and c["cached_at_input_price"]
    assert c["savings_usd"] == 0


def test_null_cache_write_price_is_unpriced_usage():
    c = cost.call_cost(call("fake-nowrite", i=1_000_000, w=10), PRICES)
    assert c["unpriced_usage"] and c["usd"] == pytest.approx(1.0)


def test_unpriced_usage_makes_the_total_a_lower_bound():
    c = cost.call_cost(call("fake-nowrite", i=1_000_000, w=10), PRICES)
    assert c["lower_bound"] is True
    s = cost.summarize([call("fake-nowrite", i=1_000_000, w=10)], PRICES)
    assert s["unpriced_usage"] is True and s["lower_bound"] is True
    line = cost.format_cost_line(s)
    assert "lower bound" in line and "UNPRICED" in line


def test_priced_cache_write_is_not_a_lower_bound():
    s = cost.summarize([call(i=1000, w=10)], PRICES)
    assert s["lower_bound"] is False and s["unpriced_usage"] is False


def test_refused_lines_add_nothing_to_any_count_even_if_malformed():
    # A refusal sends nothing. Even a hand-edited refused line that carries
    # token counts must not reach attempts, tokens or dollars.
    bad = call(ok=False, i=10**6, c=10**6, w=10**6, o=10**6,
               refusal={"scope": "blue", "reason": "max_calls"})
    s = cost.summarize([call(i=1000, o=10), bad, bad], PRICES)
    clean = cost.summarize([call(i=1000, o=10)], PRICES)
    assert s["refused"] == 2
    for k in ("total_usd", "attempts", "failed_attempts", "tokens", "cache_savings_usd"):
        assert s[k] == clean[k], k
    assert s["by_agent"]["blue"]["attempts"] == 1
    assert s["by_agent"]["blue"]["tokens"] == clean["by_agent"]["blue"]["tokens"]


def test_failed_attempts_shown_separately_and_included_in_total():
    calls = [call(i=1_000_000), call(ok=False, i=500_000)]  # a failure that billed input
    s = cost.summarize(calls, PRICES)
    assert s["total_usd"] == pytest.approx(1.5) and s["failed_attempts_usd"] == pytest.approx(0.5)
    assert (s["attempts"], s["failed_attempts"]) == (2, 1)


def test_missing_usage_is_a_lower_bound():
    s = cost.summarize([call(ok=False, i=None, c=None, w=None, o=None)], PRICES)
    assert s["total_usd"] == 0 and s["lower_bound"] is True


def test_refused_calls_cost_nothing_and_are_counted_apart():
    s = cost.summarize([call(ok=False, refusal={"scope": "blue", "reason": "max_usd"})], PRICES)
    assert (s["total_usd"], s["attempts"], s["refused"]) == (0, 0, 1)
    assert s["prices_verified"] is None


def test_by_agent_by_model_and_verified_flag():
    calls = [call(agent="red", i=1_000_000), call(model="fake-nowrite", o=1_000_000)]
    s = cost.summarize(calls, PRICES)
    assert s["by_agent"]["red"]["usd"] == pytest.approx(1.0)
    assert s["by_agent"]["blue"]["usd"] == pytest.approx(2.0)
    assert set(s["by_model"]) == {"fake-small", "fake-nowrite"}
    assert s["tokens"] == {"input": 1_000_000, "cached_input": 0, "cache_write": 0,
                           "output": 1_000_000}
    assert s["prices_verified"] is False  # fake-small is unverified
    assert cost.summarize([calls[1]], PRICES)["prices_verified"] is True


def test_empty_log_is_zero_cost():
    s = cost.summarize([], PRICES)
    assert s["total_usd"] == 0 and s["attempts"] == 0 and s["by_agent"] == {}
    assert cost.format_cost_line(s) == "cost $0.00 (0 API calls)"


def test_cost_line_flags():
    s = cost.summarize([call(i=1_000_000), call(ok=False, i=None, c=None, w=None, o=None)],
                       PRICES)
    line = cost.format_cost_line(s)
    assert line.startswith("cost $1.00 (2 API calls, 1 failed")
    assert "prices unverified" in line and "lower bound" in line and "(net)" in line


def test_placeholder_never_priced():
    prices = {**PRICES, "placeholders": {"Unconfirmed": PRICES["models"][next(
        iter(PRICES["models"]))]}}
    assert cost.entry_for(prices, "Unconfirmed") is None


def test_luna_tier_boundary_at_272k_prompt_tokens():
    prices = cost.load_prices()
    e = cost.entry_for(prices, "gpt-6-luna")
    assert e["verified"] is True and e["provider"] == "openai"
    assert cost.tier_for(e, 272_000)["input"] == 0.10
    t2 = cost.tier_for(e, 272_001)
    assert (t2["input"], t2["cached_input"], t2["cache_write"], t2["output"]) == \
        (0.20, 0.02, 0.25, 0.75)


def test_price_table_ref_ties_snapshot_to_file(tmp_path):
    p = tmp_path / "prices.json"
    p.write_text(json.dumps(PRICES))
    ref = cost.price_table_ref(p)
    assert ref["as_of"] == "2026-11-08" and len(ref["sha256"]) == 64


def test_summarize_never_mutates_input():
    calls = [call(i=5, o=5), call(ok=False, i=None, c=None, w=None, o=None)]
    before = copy.deepcopy(calls)
    cost.summarize(calls, PRICES)
    assert calls == before
