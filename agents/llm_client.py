"""The single exit for every AI call (Red, Blue, the future analyst).

    client = LLMClient()
    result = client.complete("blue", "claude-haiku-5-5", system, messages,
                             run_dir=match_dir, log_seq_first=1, log_seq_last=20)
    if result.ok: ... result.text ...

Every attempt -- success, failure, retry -- and every call the body refuses is
one line in <run_dir>/api_calls.jsonl (contract §6.3). That file is also the
budget's only state: before each attempt the client re-reads it, so Red and Blue
running as separate steps share one budget without sharing memory.

Before each attempt, in order (a refusal writes a line and sends nothing):
  1. the model has a price entry          else refuse: missing_price
  2. the provider's ARENA_* key is set    else refuse: missing_key
  3. no earlier call left unpriced usage  else refuse: unpriced_usage
  4. worst case fits every cap: per-agent caps, then the match total. Worst
     case = input estimated from the built prompt (1 token per
     `chars_per_token` chars) + max_output_tokens, priced at the applicable
     tier. Retries count as calls (D13: a refusal is an instrument failure).

Failures: timeout / 429 / 5xx / connection errors are retried with exponential
backoff (honouring Retry-After); anything else fails fast. When retries run out
the result is a structured failure (ok=False): one failed call never raises.

Keys: read ONLY from ARENA_OPENAI_API_KEY / ARENA_ANTHROPIC_API_KEY /
ARENA_GEMINI_API_KEY (environment first, then .env) and passed explicitly to
the SDK. Never an SDK's default variable: if ANTHROPIC_API_KEY were exported,
Claude Code itself would bill that key (docs/ops.md). A key never reaches a log
line, an artifact, an error message or exception text (`redact`).

SDKs are imported lazily, so tests need neither network nor keys. Pinned SDK
versions are added when first used: Anthropic in Stage 5.4, OpenAI in 5.6.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from stats import cost as cost_mod  # noqa: E402

CONFIG_PATH = REPO / "config" / "llm.json"
DOTENV_PATH = REPO / ".env"
API_CALLS = "api_calls.jsonl"
AGENTS = ("red", "blue", "analyst")
CAP_SCOPES = AGENTS + ("match",)
CAP_FIELDS = ("max_calls", "max_tokens", "max_usd")
KEY_ENV = {
    "openai": "ARENA_OPENAI_API_KEY",
    "anthropic": "ARENA_ANTHROPIC_API_KEY",
    "gemini": "ARENA_GEMINI_API_KEY",
}
RETRYABLE = frozenset({"timeout", "rate_limit", "server_error", "connection"})
API_CALL_SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "api_call.schema.json").read_text(encoding="utf-8")))


class ConfigError(ValueError):
    """config/llm.json or config/prices.json is unusable. Raised at load time."""


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

_KEY_SHAPES = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
]


def _dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    from dotenv import dotenv_values  # parse only; never exported into os.environ
    return {k: v for k, v in dotenv_values(path).items() if v}


def key_values(env: dict | None = None, dotenv_path: Path = DOTENV_PATH) -> list[str]:
    env = os.environ if env is None else env
    dot = _dotenv(dotenv_path)
    vals = {env.get(v) or dot.get(v) for v in KEY_ENV.values()}
    return sorted((v for v in vals if v and len(v) >= 8), key=len, reverse=True)


def redact(text: str, keys: list[str] | None = None) -> str:
    """Remove every configured key value and anything shaped like a provider key."""
    for k in key_values() if keys is None else keys:
        text = text.replace(k, "[REDACTED]")
    for pattern in _KEY_SHAPES:
        text = pattern.sub("[REDACTED]", text)
    return text


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def load_config(path: Path = CONFIG_PATH) -> dict:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    for name in ("timeout_s", "max_retries", "backoff_base_s", "backoff_max_s",
                 "max_output_tokens", "chars_per_token", "provider_caching", "caps", "agents"):
        if name not in cfg:
            raise ConfigError(f"{path.name}: missing {name!r}")
    if cfg["provider_caching"] is not False:
        raise ConfigError("provider_caching must stay false until the agent loop is stable "
                          "(D11; enabled in Stage 5.7)")
    caps = cfg["caps"]
    for scope in CAP_SCOPES:
        if scope not in caps:
            raise ConfigError(f"caps: missing scope {scope!r} (per-agent caps are required)")
        for f in CAP_FIELDS:
            if f not in caps[scope]:
                raise ConfigError(f"caps.{scope}: missing {f!r}")
            v = caps[scope][f]
            if scope in AGENTS and v is None:
                raise ConfigError(f"caps.{scope}.{f} must be a number (per-agent caps "
                                  f"are required; only the match total may be null)")
            if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0):
                raise ConfigError(f"caps.{scope}.{f} must be a non-negative number or null")
    return cfg


def caps_limits(cfg: dict) -> dict:
    return {s: {f: cfg["caps"][s][f] for f in CAP_FIELDS} for s in CAP_SCOPES}


# --------------------------------------------------------------------------
# Results and provider adapters
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Usage:
    input_tokens: int
    cached_input_tokens: int
    cache_write_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class Reply:
    text: str
    usage: Usage
    http_status: int | None = 200


@dataclass(frozen=True)
class Result:
    ok: bool
    text: str | None = None
    usage: Usage | None = None          # of the successful attempt
    error: str | None = None            # redacted, human-readable
    error_type: str | None = None
    attempts: int = 0                   # attempts actually sent
    refusal: dict | None = None         # {scope, reason} if the body refused


class Adapter(Protocol):
    provider: str
    needs_key: bool

    def call(self, *, model: str, system: str, messages: list[dict],
             max_output_tokens: int, timeout: float, api_key: str | None) -> Reply: ...


# VERIFY AT FIRST REAL CALL (Stage 5.4 / 5.6): these usage mappings follow the
# providers' documented fields, but must be checked against a real response.
# Common rule: input_tokens = full-price input only; the whole prompt is
# input + cached_input + cache_write.

def anthropic_usage(u: Any) -> Usage:
    """Anthropic input_tokens already EXCLUDES cache reads and cache writes."""
    return Usage(input_tokens=u.input_tokens,
                 cached_input_tokens=getattr(u, "cache_read_input_tokens", None) or 0,
                 cache_write_tokens=getattr(u, "cache_creation_input_tokens", None) or 0,
                 output_tokens=u.output_tokens)


def openai_usage(u: Any) -> Usage:
    """OpenAI prompt_tokens INCLUDES cached tokens; there is no cache-write charge.
    Reasoning tokens are inside completion_tokens (billed as output)."""
    details = getattr(u, "prompt_tokens_details", None)
    cached = getattr(details, "cached_tokens", None) or 0
    return Usage(input_tokens=u.prompt_tokens - cached, cached_input_tokens=cached,
                 cache_write_tokens=0, output_tokens=u.completion_tokens)


class AnthropicAdapter:
    provider = "anthropic"
    needs_key = True

    def call(self, *, model, system, messages, max_output_tokens, timeout, api_key):
        if not api_key:  # never let the SDK fall back to ANTHROPIC_API_KEY
            raise ConfigError("no API key passed")
        import anthropic  # lazy; pinned in requirements.txt in Stage 5.4
        client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0)
        resp = client.messages.create(model=model, system=system, messages=messages,
                                      max_tokens=max_output_tokens)
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return Reply(text=text, usage=anthropic_usage(resp.usage))


class OpenAIAdapter:
    provider = "openai"
    needs_key = True

    def call(self, *, model, system, messages, max_output_tokens, timeout, api_key):
        if not api_key:  # never let the SDK fall back to OPENAI_API_KEY
            raise ConfigError("no API key passed")
        import openai  # lazy; pinned in requirements.txt in Stage 5.6
        client = openai.OpenAI(api_key=api_key, timeout=timeout, max_retries=0)
        resp = client.chat.completions.create(
            model=model, messages=[{"role": "system", "content": system}, *messages],
            max_completion_tokens=max_output_tokens)
        return Reply(text=resp.choices[0].message.content or "",
                     usage=openai_usage(resp.usage))


DEFAULT_ADAPTERS: dict[str, Adapter] = {"anthropic": AnthropicAdapter(),
                                        "openai": OpenAIAdapter()}


def classify(exc: BaseException) -> tuple[str, int | None, float | None]:
    """(error_type, http_status, retry_after seconds) by duck typing, so it works
    for both SDKs' exception classes without importing them."""
    response = getattr(exc, "response", None)
    status = getattr(exc, "status_code", None) or getattr(response, "status_code", None)
    status = status if isinstance(status, int) and 100 <= status <= 599 else None
    retry_after = getattr(exc, "retry_after", None)
    headers = getattr(response, "headers", None)
    if retry_after is None and headers is not None:
        try:
            retry_after = float(headers.get("retry-after"))
        except (TypeError, ValueError):
            retry_after = None
    name = type(exc).__name__.lower()
    if isinstance(exc, TimeoutError) or "timeout" in name:
        kind = "timeout"
    elif status == 429:
        kind = "rate_limit"
    elif status is not None and status >= 500:
        kind = "server_error"
    elif status in (401, 403):
        kind = "auth"
    elif status is not None and 400 <= status < 500:
        kind = "bad_request"
    elif isinstance(exc, ConnectionError) or "connection" in name:
        kind = "connection"
    else:
        kind = "other"
    return kind, status, retry_after


# --------------------------------------------------------------------------
# Budget (pure)
# --------------------------------------------------------------------------

def canonical_prompt(model: str, system: str, messages: list[dict]) -> str:
    return json.dumps({"model": model, "system": system, "messages": messages},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def worst_case(entry: dict, prompt_chars: int, chars_per_token: float,
               max_output_tokens: int) -> tuple[int, float]:
    """(tokens, usd) upper estimate for one call, priced at the applicable tier."""
    est_input = math.ceil(prompt_chars / chars_per_token)
    tier = cost_mod.tier_for(entry, est_input)
    usd = (est_input * tier["input"] + max_output_tokens * tier["output"]) / 1e6
    return est_input + max_output_tokens, usd


def spent(calls: list[dict], prices: dict, scope: str) -> dict:
    """Accumulated attempts / tokens / usd for an agent, or for the whole match."""
    rows = calls if scope == "match" else [c for c in calls if c["agent"] == scope]
    s = cost_mod.summarize(rows, prices)
    return {"calls": s["attempts"], "tokens": sum(s["tokens"].values()), "usd": s["total_usd"],
            "unpriced_usage": s["unpriced_usage"]}


def check_budget(calls: list[dict], prices: dict, limits: dict, agent: str,
                 est_tokens: int, est_usd: float) -> dict | None:
    """The refusal ({scope, reason}) for the next attempt, or None if it may go."""
    if spent(calls, prices, "match")["unpriced_usage"]:
        return {"scope": "match", "reason": "unpriced_usage"}
    for scope in (agent, "match"):
        lim, s = limits[scope], spent(calls, prices, scope)
        if lim["max_calls"] is not None and s["calls"] + 1 > lim["max_calls"]:
            return {"scope": scope, "reason": "max_calls"}
        if lim["max_tokens"] is not None and s["tokens"] + est_tokens > lim["max_tokens"]:
            return {"scope": scope, "reason": "max_tokens"}
        if lim["max_usd"] is not None and s["usd"] + est_usd > lim["max_usd"] + 1e-12:
            return {"scope": scope, "reason": "max_usd"}
    return None


def stopped_by(calls: list[dict], prices: dict) -> dict | None:
    """For match.json: the first refusal, or unpriced usage (the USD cap can no
    longer be enforced). None if nothing stopped any agent."""
    for c in calls:
        if c.get("refusal") is not None:
            return dict(c["refusal"])
    if cost_mod.summarize(calls, prices)["unpriced_usage"]:
        return {"scope": "match", "reason": "unpriced_usage"}
    return None


# --------------------------------------------------------------------------
# The client
# --------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LLMClient:
    def __init__(self, config: dict | None = None, prices: dict | None = None,
                 adapters: dict[str, Adapter] | None = None, env: dict | None = None,
                 dotenv_path: Path = DOTENV_PATH, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, now: Callable[[], str] = utc_now):
        self.cfg = config if config is not None else load_config()
        self.prices = prices if prices is not None else cost_mod.load_prices()
        self.limits = caps_limits(self.cfg)
        self.adapters = DEFAULT_ADAPTERS if adapters is None else adapters
        self.env = os.environ if env is None else env
        self.dotenv_path = dotenv_path
        self.sleep, self.clock, self.now = sleep, clock, now

    # -- keys ---------------------------------------------------------------
    def _key(self, provider: str) -> str | None:
        var = KEY_ENV.get(provider)
        if var is None:
            return None
        return self.env.get(var) or _dotenv(self.dotenv_path).get(var) or None

    def _redact(self, text: str) -> str:
        return redact(text, key_values(self.env, self.dotenv_path))

    # -- log ----------------------------------------------------------------
    def _write(self, run_dir: Path, line: dict) -> None:
        errors = [e.message for e in API_CALL_SCHEMA.iter_errors(line)]
        if errors:  # a bug in this module, never data-dependent
            raise RuntimeError(f"api_calls line is schema-invalid: {errors}")
        with (run_dir / API_CALLS).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
            fh.flush()

    def _base(self, run_dir, match_id, agent, provider, model, round, first, last,
              attempt, prompt_sha) -> dict:
        return {"schema_version": "0.1", "match_id": match_id, "timestamp": self.now(),
                "agent": agent, "provider": provider, "model": model, "round": round,
                "log_seq_first": first, "log_seq_last": last, "attempt": attempt,
                "prompt_sha256": prompt_sha}

    def _refuse(self, run_dir, base: dict, refusal: dict, attempts_sent: int) -> Result:
        self._write(run_dir, {**base, "ok": False, "error_type": "refused",
                              "http_status": None, "refusal": refusal, "input_tokens": 0,
                              "cached_input_tokens": 0, "cache_write_tokens": 0,
                              "output_tokens": 0, "latency_ms": 0})
        return Result(ok=False, error=f"refused by the body: {refusal['scope']} "
                                       f"{refusal['reason']}",
                      error_type="refused", attempts=attempts_sent, refusal=refusal)

    # -- the call -------------------------------------------------------------
    def complete(self, agent: str, model: str, system: str, messages: list[dict], *,
                 run_dir: Path, round: int | None = None, log_seq_first: int | None = None,
                 log_seq_last: int | None = None, match_id: str | None = None) -> Result:
        if agent not in AGENTS:
            raise ValueError(f"unknown agent {agent!r}")
        if agent == "red" and (log_seq_first is not None or log_seq_last is not None):
            raise ValueError("red calls carry round, never log_seq")
        if agent != "red" and round is not None:
            raise ValueError(f"{agent} calls never carry a Red round")
        if agent == "analyst" and (log_seq_first is not None or log_seq_last is not None):
            raise ValueError("analyst calls carry neither round nor log_seq")
        run_dir = Path(run_dir)
        match_id = match_id or run_dir.name
        prompt = canonical_prompt(model, system, messages)
        prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        entry = cost_mod.entry_for(self.prices, model)
        provider = entry["provider"] if entry else None
        max_out = self.cfg["max_output_tokens"]
        attempts_sent = 0

        for attempt in range(1, self.cfg["max_retries"] + 2):
            base = self._base(run_dir, match_id, agent, provider, model, round,
                              log_seq_first, log_seq_last, attempt, prompt_sha)
            if entry is None:
                return self._refuse(run_dir, base, {"scope": agent, "reason": "missing_price"},
                                    attempts_sent)
            adapter = self.adapters.get(provider)
            if adapter is None:
                raise ConfigError(f"no adapter for provider {provider!r}")
            key = self._key(provider)
            if adapter.needs_key and not key:
                return self._refuse(run_dir, base, {"scope": agent, "reason": "missing_key"},
                                    attempts_sent)
            est_tokens, est_usd = worst_case(entry, len(prompt), self.cfg["chars_per_token"],
                                             max_out)
            refusal = check_budget(cost_mod.read_calls(run_dir / API_CALLS), self.prices,
                                   self.limits, agent, est_tokens, est_usd)
            if refusal is not None:
                return self._refuse(run_dir, base, refusal, attempts_sent)

            attempts_sent += 1
            t0 = self.clock()
            try:
                reply = adapter.call(model=model, system=system, messages=messages,
                                     max_output_tokens=max_out,
                                     timeout=self.cfg["timeout_s"], api_key=key)
            except Exception as exc:  # noqa: BLE001 - one failed call never crashes a match
                latency = max(0, round_ms(self.clock() - t0))
                kind, status, retry_after = classify(exc)
                self._write(run_dir, {**base, "ok": False, "error_type": kind,
                                      "http_status": status, "refusal": None,
                                      "input_tokens": None, "cached_input_tokens": None,
                                      "cache_write_tokens": None, "output_tokens": None,
                                      "latency_ms": latency})
                error = self._redact(f"{type(exc).__name__}: {exc}")[:500]
                if kind not in RETRYABLE or attempt > self.cfg["max_retries"]:
                    return Result(ok=False, error=error, error_type=kind,
                                  attempts=attempts_sent)
                delay = min(self.cfg["backoff_max_s"],
                            self.cfg["backoff_base_s"] * 2 ** (attempt - 1))
                if retry_after is not None:
                    delay = min(self.cfg["backoff_max_s"], max(delay, retry_after))
                self.sleep(delay)
                continue
            latency = max(0, round_ms(self.clock() - t0))
            u = reply.usage
            self._write(run_dir, {**base, "ok": True, "error_type": None,
                                  "http_status": reply.http_status, "refusal": None,
                                  "input_tokens": u.input_tokens,
                                  "cached_input_tokens": u.cached_input_tokens,
                                  "cache_write_tokens": u.cache_write_tokens,
                                  "output_tokens": u.output_tokens, "latency_ms": latency})
            return Result(ok=True, text=reply.text, usage=u, attempts=attempts_sent)
        raise AssertionError("unreachable")


def round_ms(seconds: float) -> int:
    return int(seconds * 1000 + 0.5)
