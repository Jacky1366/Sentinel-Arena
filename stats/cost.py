"""API cost: api_calls.jsonl + price table -> dollars. PURE (no network).

Token counts in api_calls.jsonl are the raw evidence; dollars are derived here
from a dated price table (Stage 5 decision D10). The same functions back the
llm_client budget checks, so "what a call cost" has exactly one definition.

Per call (contract §6.3, §6.4):

  prompt tokens = input + cached_input + cache_write      (selects the tier)
  usd           = (input * p.input + cached_input * p.cached_input
                   + cache_write * p.cache_write + output * p.output) / 1e6
  cache savings = cached_input * (p.input - p.cached_input)
                  - cache_write * (p.cache_write - p.input)   (NET, may be < 0)

Unknown prices:
  - cached_input price null  -> charged at the full input price (an upper
    bound; flagged `cached_at_input_price`), and it saves nothing.
  - cache_write price null with cache_write tokens > 0 -> that part cannot be
    priced: it is left out of usd and flagged `unpriced_usage` AND `lower_bound`
    (the total is then an undercount). The budget then refuses every further
    call (stopped_by reason "unpriced_usage").
  - token counts null (the provider reported no usage, e.g. a timeout) ->
    counted as 0 and flagged `lower_bound`: the provider may still have billed it.

Refused calls (refusal non-null) were never sent: they add nothing to any
total (attempts, tokens, usd), so a refusal can never make a cap trigger
earlier. They are only counted in `refused`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRICES_PATH = REPO / "config" / "prices.json"
TOKEN_FIELDS = ("input_tokens", "cached_input_tokens", "cache_write_tokens", "output_tokens")
TOKEN_KEYS = ("input", "cached_input", "cache_write", "output")


def load_prices(path: Path = PRICES_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def price_table_ref(path: Path = PRICES_PATH) -> dict:
    """{path, sha256, as_of} for match.json: ties a dollar snapshot to its table."""
    data = path.read_bytes()
    try:
        shown = path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        shown = str(path)
    return {"path": shown, "sha256": hashlib.sha256(data).hexdigest(),
            "as_of": json.loads(data)["as_of"]}


def read_calls(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def entry_for(prices: dict, model: str) -> dict | None:
    """The callable price entry for a model id. Placeholders never match."""
    return prices["models"].get(model)


def tier_for(entry: dict, prompt_tokens: int) -> dict:
    for tier in entry["tiers"]:
        if tier["max_prompt_tokens"] is None or prompt_tokens <= tier["max_prompt_tokens"]:
            return tier
    return entry["tiers"][-1]


def tokens_of(call: dict) -> dict[str, int]:
    return {k: call.get(f) or 0 for k, f in zip(TOKEN_KEYS, TOKEN_FIELDS)}


def is_sent(call: dict) -> bool:
    return call.get("refusal") is None


def call_cost(call: dict, prices: dict) -> dict:
    """{usd, savings_usd, cached_at_input_price, unpriced_usage, lower_bound, priced}."""
    out = {"usd": 0.0, "savings_usd": 0.0, "cached_at_input_price": False,
           "unpriced_usage": False, "lower_bound": False, "priced": True}
    if not is_sent(call):
        return out
    if call.get("ok") is not True and any(call.get(f) is None for f in TOKEN_FIELDS):
        out["lower_bound"] = True
    entry = entry_for(prices, call["model"])
    if entry is None:  # the client refuses these, so this is a foreign/edited log
        out["priced"] = False
        return out
    t = tokens_of(call)
    tier = tier_for(entry, t["input"] + t["cached_input"] + t["cache_write"])
    p_in, p_out = tier["input"], tier["output"]
    p_cached, p_write = tier["cached_input"], tier["cache_write"]
    usd = t["input"] * p_in + t["output"] * p_out
    savings = 0.0
    if t["cached_input"]:
        if p_cached is None:
            usd += t["cached_input"] * p_in
            out["cached_at_input_price"] = True
        else:
            usd += t["cached_input"] * p_cached
            savings += t["cached_input"] * (p_in - p_cached)
    if t["cache_write"]:
        if p_write is None:
            out["unpriced_usage"] = True
            out["lower_bound"] = True  # left out of usd, so usd undercounts
        else:
            usd += t["cache_write"] * p_write
            savings -= t["cache_write"] * (p_write - p_in)
    out["usd"] = usd / 1e6
    out["savings_usd"] = savings / 1e6
    return out


def _bucket() -> dict:
    return {"usd": 0.0, "failed_attempts_usd": 0.0, "attempts": 0, "failed_attempts": 0,
            "refused": 0, "tokens": {k: 0 for k in TOKEN_KEYS}}


def _add(b: dict, call: dict, c: dict) -> None:
    if not is_sent(call):
        b["refused"] += 1
        return
    b["attempts"] += 1
    b["usd"] += c["usd"]
    if call.get("ok") is not True:
        b["failed_attempts"] += 1
        b["failed_attempts_usd"] += c["usd"]
    for k, v in tokens_of(call).items():
        b["tokens"][k] += v


def _round(b: dict) -> dict:
    return {**b, "usd": round(b["usd"], 6), "failed_attempts_usd": round(b["failed_attempts_usd"], 6)}


def summarize(calls: list[dict], prices: dict) -> dict:
    """The cost block of match.json (contract §6.2). total_usd includes failed
    attempts; failed_attempts_usd is that subset, shown separately."""
    total = _bucket()
    by_agent: dict[str, dict] = {}
    by_model: dict[str, dict] = {}
    savings = 0.0
    flags = {"lower_bound": False, "cached_at_input_price": False, "unpriced_usage": False}
    models_used: set[str] = set()
    for call in calls:
        c = call_cost(call, prices)
        for b in (total, by_agent.setdefault(call["agent"], _bucket()),
                  by_model.setdefault(call["model"], _bucket())):
            _add(b, call, c)
        savings += c["savings_usd"]
        for k in flags:
            flags[k] = flags[k] or c[k]
        if is_sent(call):
            models_used.add(call["model"])
    verified = None
    if models_used:
        verified = all((entry_for(prices, m) or {}).get("verified") is True for m in models_used)
    t = _round(total)
    return {
        "total_usd": t["usd"],
        "failed_attempts_usd": t["failed_attempts_usd"],
        "cache_savings_usd": round(savings, 6),
        "attempts": t["attempts"],
        "failed_attempts": t["failed_attempts"],
        "refused": t["refused"],
        "tokens": t["tokens"],
        "by_agent": {k: _round(v) for k, v in sorted(by_agent.items())},
        "by_model": {k: _round(v) for k, v in sorted(by_model.items())},
        **flags,
        "prices_verified": verified,
    }


def format_cost_line(cost: dict) -> str:
    """One terminal line. A scripted match prints `cost $0.00 (0 API calls)`."""
    usd = cost["total_usd"]
    shown = f"${usd:.2f}" if usd == 0 or usd >= 0.01 else f"${usd:.4f}"
    parts = [f"cost {shown} ({cost['attempts']} API calls"]
    if cost["failed_attempts"]:
        parts.append(f", {cost['failed_attempts']} failed = ${cost['failed_attempts_usd']:.4f}")
    if cost["refused"]:
        parts.append(f", {cost['refused']} refused")
    parts.append(")")
    if cost["attempts"]:
        parts.append(f"  cache savings ${cost['cache_savings_usd']:.4f} (net)")
    notes = [n for n, on in (("prices unverified", cost["prices_verified"] is False),
                             ("lower bound", cost["lower_bound"]),
                             ("cached input priced as input", cost["cached_at_input_price"]),
                             ("UNPRICED usage", cost["unpriced_usage"])) if on]
    if notes:
        parts.append("  [" + "; ".join(notes) + "]")
    return "".join(parts)
