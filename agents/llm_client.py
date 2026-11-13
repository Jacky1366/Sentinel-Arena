"""The single exit for every AI call (Red, Blue, the future analyst).

    client = LLMClient()
    result = client.complete("blue", "claude-haiku-5-5", system, messages,
                             run_dir=match_dir, log_seq_first=1, log_seq_last=20)
    if result.ok: ... result.text ...

Every attempt -- success, failure, retry -- and every call the body refuses is
one line in <run_dir>/api_calls.jsonl (contract §6.3). That file is also the
budget's only state: before each attempt the client re-reads it, so Red and Blue
running as separate steps share one budget without sharing memory.

The provider of every line comes from config/llm.json (agents.<agent>.provider),
never from the price table, so it is known even when a price entry is missing.
A model whose price entry names a different provider is a config error.

Before each attempt, in order (a refusal writes a line and sends nothing):
  1. the model has a price entry          else refuse: missing_price
  2. a REAL provider's price entry is designer-verified (verified: true)
                                          else refuse: price_unverified
     (the fake provider is exempt; Stage 5.4)
  3. the provider's ARENA_* key is set    else refuse: missing_key
  4. no earlier call left unpriced usage  else refuse: unpriced_usage
  5. worst case fits every cap: per-agent caps, then the match total. Worst
     case = input estimated from the built prompt (1 token per
     `chars_per_token` chars) + max_output_tokens, priced at the applicable
     tier. Retries count as calls (D13: a refusal is an instrument failure).
     Refused lines never count toward any total: nothing was sent.

Failures: timeout / 429 / 5xx / connection errors are retried with exponential
backoff (honouring Retry-After); anything else fails fast. When retries run out
the result is a structured failure (ok=False): one failed call never raises.

Keys: read ONLY from ARENA_OPENAI_API_KEY / ARENA_ANTHROPIC_API_KEY /
ARENA_GEMINI_API_KEY (environment first, then .env) and passed explicitly to
the SDK. Never an SDK's default variable: if ANTHROPIC_API_KEY were exported,
Claude Code itself would bill that key (docs/ops.md). A key never reaches a log
line, an artifact, an error message or exception text (`redact`).

Per-agent request settings (config/llm.json agents.<agent>): an optional
`max_output_tokens` (overrides the global one, also in the worst-case estimate)
and an optional `request` block ({thinking, effort}) passed to the adapter, plus
an optional per-call `output_schema` (structured outputs). They are part of the
agent's configuration and are recorded in match.json (blue_params).

SDKs are imported lazily, so tests need neither network nor keys. Pinned SDKs:
Anthropic since Stage 5.4 (anthropic==2.3.0), OpenAI since 5.6 (openai==3.41.0,
Responses API). For OpenAI, `effort` maps to reasoning effort; `thinking` is an
Anthropic setting and is refused.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import time
from contextlib import contextmanager
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
PROVIDERS = tuple(KEY_ENV) + ("fake",)  # "fake" only in tests
RETRYABLE = frozenset({"timeout", "rate_limit", "server_error", "connection"})
API_CALL_SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "api_call.schema.json").read_text(encoding="utf-8")))


THINKING = ("disabled", "adaptive")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
ANTHROPIC_BASE_URL = "https://api.anthropic.com"  # explicit: ANTHROPIC_BASE_URL is never read


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


def key_values(env: dict | None = None, dotenv_path: Path | None = None) -> list[str]:
    env = os.environ if env is None else env
    # DOTENV_PATH is read at call time (not as a default argument), so the test
    # session can point it at a file that does not exist (tests/conftest.py).
    dot = _dotenv(DOTENV_PATH if dotenv_path is None else dotenv_path)
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
    for agent in AGENTS:
        a = cfg["agents"].get(agent)
        if not isinstance(a, dict) or "model" not in a or "provider" not in a:
            raise ConfigError(f"agents.{agent}: needs 'model' and 'provider'")
        if a["provider"] is not None and a["provider"] not in PROVIDERS:
            raise ConfigError(f"agents.{agent}.provider: unknown provider {a['provider']!r}")
        if a["model"] is not None and a["provider"] is None:
            raise ConfigError(f"agents.{agent}: a model needs a provider")
        mot = a.get("max_output_tokens")
        if mot is not None and (isinstance(mot, bool) or not isinstance(mot, int) or mot < 1):
            raise ConfigError(f"agents.{agent}.max_output_tokens must be a positive integer")
        cs = a.get("chunk_size")
        if cs is not None and (isinstance(cs, bool) or not isinstance(cs, int) or cs < 1):
            raise ConfigError(f"agents.{agent}.chunk_size must be a positive integer")
        rc = a.get("round_cap")
        if rc is not None and (isinstance(rc, bool) or not isinstance(rc, int) or rc < 1):
            raise ConfigError(f"agents.{agent}.round_cap must be a positive integer")
        req = a.get("request", {})
        if not isinstance(req, dict) or set(req) - {"thinking", "effort"}:
            raise ConfigError(f"agents.{agent}.request: only 'thinking' and 'effort' are allowed")
        if req.get("thinking") not in (None, *THINKING):
            raise ConfigError(f"agents.{agent}.request.thinking must be one of {THINKING}")
        if req.get("effort") not in (None, *EFFORTS):
            raise ConfigError(f"agents.{agent}.request.effort must be one of {EFFORTS}")
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


def agent_max_output_tokens(cfg: dict, agent: str) -> int:
    return cfg["agents"][agent].get("max_output_tokens") or cfg["max_output_tokens"]


def agent_request(cfg: dict, agent: str) -> dict:
    """{thinking, effort} for the agent (None = provider default)."""
    req = cfg["agents"][agent].get("request") or {}
    return {"thinking": req.get("thinking"), "effort": req.get("effort")}


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
    stop_reason: str | None = None      # provider's stop reason (e.g. end_turn, refusal)
    raw_usage: dict | None = None       # provider's usage object as reported (never stored)


@dataclass(frozen=True)
class Result:
    ok: bool
    text: str | None = None
    usage: Usage | None = None          # of the successful attempt
    error: str | None = None            # redacted, human-readable
    error_type: str | None = None
    attempts: int = 0                   # attempts actually sent
    refusal: dict | None = None         # {scope, reason} if the body refused
    stop_reason: str | None = None      # of the successful attempt
    raw_usage: dict | None = None       # of the successful attempt (Gate 1 evidence)


class Adapter(Protocol):
    provider: str
    needs_key: bool

    def call(self, *, model: str, system: str, messages: list[dict],
             max_output_tokens: int, timeout: float, api_key: str | None,
             request: dict, output_schema: dict | None) -> Reply: ...


# Usage mappings. Common rule: input_tokens = full-price input only; the whole
# prompt is input + cached_input + cache_write.
# Anthropic: VERIFIED 2026-11-12 (Stage 5.4 Gate 1, designer checked the Console:
#   885 input / 60 output) for UNCACHED, NON-THINKING calls only.
#   STILL TO VERIFY: (a) that input_tokens excludes cache reads/writes (caching is
#   off until 5.7, both cache fields were 0); (b) whether output_tokens includes
#   thinking tokens (raw usage reports output_tokens_details.thinking_tokens; thinking
#   was disabled, so 0).
# OpenAI (Responses API): VERIFIED 2026-11-12 (Stage 5.6 Gate 1, designer checked the
#   dashboard: 357 input / 114 output) for UNCACHED calls with ZERO reasoning tokens.
#   STILL TO VERIFY: (a) that input_tokens includes cache reads/writes so subtracting
#   both is right (caching is off until 5.7, both were 0); (b) that output_tokens
#   includes reasoning tokens (effort low produced 0 on the Gate-1 turn).

def anthropic_usage(u: Any) -> Usage:
    """Anthropic input_tokens already EXCLUDES cache reads and cache writes."""
    return Usage(input_tokens=u.input_tokens,
                 cached_input_tokens=getattr(u, "cache_read_input_tokens", None) or 0,
                 cache_write_tokens=getattr(u, "cache_creation_input_tokens", None) or 0,
                 output_tokens=u.output_tokens)


def openai_usage(u: Any) -> Usage:
    """Responses API usage. input_tokens INCLUDES cached (and cache-write) tokens;
    output_tokens INCLUDES reasoning tokens (billed as output)."""
    details = getattr(u, "input_tokens_details", None)
    cached = getattr(details, "cached_tokens", None) or 0
    write = getattr(details, "cache_write_tokens", None) or 0
    return Usage(input_tokens=u.input_tokens - cached - write, cached_input_tokens=cached,
                 cache_write_tokens=write, output_tokens=u.output_tokens)


def anthropic_request_kwargs(request: dict, output_schema: dict | None) -> dict:
    """The optional Messages API fields for {thinking, effort} + structured output.
    Sampling parameters (temperature/top_p/top_k) are never sent: Haiku 5.5 and API
    version 2026-10-21 reject them (Stage 5.4 decision 1)."""
    kw: dict = {}
    if request.get("thinking") is not None:
        kw["thinking"] = {"type": request["thinking"]}
    output_config: dict = {}
    if request.get("effort") is not None:
        output_config["effort"] = request["effort"]
    if output_schema is not None:
        output_config["format"] = {"type": "json_schema", "schema": output_schema}
    if output_config:
        kw["output_config"] = output_config
    return kw


class AnthropicAdapter:
    provider = "anthropic"
    needs_key = True

    def __init__(self, http_client_factory: Callable[[], Any] | None = None):
        self.http_client_factory = http_client_factory  # tests: a mock transport

    def call(self, *, model, system, messages, max_output_tokens, timeout, api_key,
             request, output_schema):
        if not api_key:  # never let the SDK fall back to ANTHROPIC_API_KEY
            raise ConfigError("no API key passed")
        import anthropic  # lazy; pinned in requirements.txt (anthropic==2.3.0)
        # An explicit api_key means the SDK consults no credential env variable,
        # profile or federation config; an explicit base_url means
        # ANTHROPIC_BASE_URL can never redirect the key. No OpenTelemetry spans.
        extra = {} if self.http_client_factory is None else \
            {"http_client": self.http_client_factory()}
        client = anthropic.Anthropic(api_key=api_key, base_url=ANTHROPIC_BASE_URL,
                                     timeout=timeout, max_retries=0, open_telemetry=False,
                                     **extra)
        resp = client.messages.create(model=model, system=system, messages=messages,
                                      max_tokens=max_output_tokens,
                                      **anthropic_request_kwargs(request, output_schema))
        # Read by block type: thinking blocks (if any) are never the answer.
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return Reply(text=text, usage=anthropic_usage(resp.usage),
                     stop_reason=resp.stop_reason,
                     raw_usage=resp.usage.model_dump(mode="json", exclude_none=True))


OPENAI_BASE_URL = "https://api.openai.com/v1"  # explicit: OPENAI_BASE_URL is never read
# Disables OpenAI's implicit prompt-cache breakpoint (no explicit breakpoints are
# sent), so no prompt caching happens until Stage 5.7 (D11).
OPENAI_PROMPT_CACHE = {"mode": "explicit"}


@contextmanager
def scrubbed_env(prefix: str):
    """Remove every `prefix*` variable from os.environ for the duration (the SDK
    reads OPENAI_* for key, base URL, org, project, admin key and custom headers
    whenever an argument is unset). Restored afterwards, even on error."""
    saved = {k: os.environ.pop(k) for k in [k for k in os.environ if k.startswith(prefix)]}
    try:
        yield
    finally:
        os.environ.update(saved)


def openai_request_kwargs(request: dict, output_schema: dict | None) -> dict:
    """Responses API fields for the agent's request settings + structured output.
    Sampling parameters are never sent; responses are never stored server-side."""
    if request.get("thinking") is not None:
        raise ConfigError("'thinking' is an Anthropic setting; use 'effort' for OpenAI")
    kw: dict = {"store": False, "prompt_cache_options": dict(OPENAI_PROMPT_CACHE)}
    if request.get("effort") is not None:
        kw["reasoning"] = {"effort": request["effort"]}
    if output_schema is not None:
        kw["text"] = {"format": {"type": "json_schema", "name": "response",
                                 "schema": output_schema, "strict": True}}
    return kw


def openai_reply_parts(resp: Any) -> tuple[str, str | None]:
    """(text, stop_reason) read by output item type. stop_reason is normalized:
    refusal -> "refusal"; incomplete at the output cap -> "max_tokens"; other
    incomplete -> "incomplete:<reason>"; else the response status."""
    texts, refused = [], False
    for item in getattr(resp, "output", None) or []:
        if getattr(item, "type", None) != "message":
            continue  # reasoning items are never the answer
        for c in getattr(item, "content", None) or []:
            if getattr(c, "type", None) == "output_text":
                texts.append(c.text or "")
            elif getattr(c, "type", None) == "refusal":
                refused = True
    status = getattr(resp, "status", None)
    if refused:
        stop = "refusal"
    elif status == "incomplete":
        reason = getattr(getattr(resp, "incomplete_details", None), "reason", None)
        stop = "max_tokens" if reason == "max_output_tokens" else f"incomplete:{reason}"
    else:
        stop = status
    return "".join(texts), stop


class OpenAIAdapter:
    provider = "openai"
    needs_key = True

    def __init__(self, http_client_factory: Callable[[], Any] | None = None):
        self.http_client_factory = http_client_factory  # tests: a mock transport

    def call(self, *, model, system, messages, max_output_tokens, timeout, api_key,
             request, output_schema):
        if not api_key:  # never let the SDK fall back to OPENAI_API_KEY
            raise ConfigError("no API key passed")
        kwargs = openai_request_kwargs(request, output_schema)
        import openai  # lazy; pinned in requirements.txt (openai==3.41.0)
        extra = {} if self.http_client_factory is None else \
            {"http_client": self.http_client_factory()}
        # The client is built with every OPENAI_* variable removed, and the key and
        # base URL passed explicitly: no environment value can choose the key, the
        # host, the organization, the project or extra headers.
        with scrubbed_env("OPENAI_"):
            client = openai.OpenAI(api_key=api_key, base_url=OPENAI_BASE_URL,
                                   timeout=timeout, max_retries=0, **extra)
        resp = client.responses.create(model=model, instructions=system, input=messages,
                                       max_output_tokens=max_output_tokens, **kwargs)
        text, stop = openai_reply_parts(resp)
        return Reply(text=text, usage=openai_usage(resp.usage), stop_reason=stop,
                     raw_usage=resp.usage.model_dump(mode="json", exclude_none=True))


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
                 dotenv_path: Path | None = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, now: Callable[[], str] = utc_now):
        self.cfg = config if config is not None else load_config()
        self.prices = prices if prices is not None else cost_mod.load_prices()
        self.limits = caps_limits(self.cfg)
        self.adapters = DEFAULT_ADAPTERS if adapters is None else adapters
        self.env = os.environ if env is None else env
        self.dotenv_path = DOTENV_PATH if dotenv_path is None else dotenv_path
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
                              "http_status": None, "refusal": refusal, "stop_reason": None,
                              "input_tokens": 0,
                              "cached_input_tokens": 0, "cache_write_tokens": 0,
                              "output_tokens": 0, "latency_ms": 0})
        return Result(ok=False, error=f"refused by the body: {refusal['scope']} "
                                       f"{refusal['reason']}",
                      error_type="refused", attempts=attempts_sent, refusal=refusal)

    # -- the call -------------------------------------------------------------
    def complete(self, agent: str, model: str, system: str, messages: list[dict], *,
                 run_dir: Path, round: int | None = None, log_seq_first: int | None = None,
                 log_seq_last: int | None = None, match_id: str | None = None,
                 output_schema: dict | None = None) -> Result:
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
        provider = self.cfg["agents"][agent]["provider"]
        if provider is None:
            raise ConfigError(f"agents.{agent}.provider is not set in config/llm.json")
        if entry is not None and entry["provider"] != provider:
            raise ConfigError(f"model {model!r} is priced as {entry['provider']}, but "
                              f"{agent} is configured for {provider}")
        max_out = agent_max_output_tokens(self.cfg, agent)
        request = agent_request(self.cfg, agent)
        attempts_sent = 0

        for attempt in range(1, self.cfg["max_retries"] + 2):
            base = self._base(run_dir, match_id, agent, provider, model, round,
                              log_seq_first, log_seq_last, attempt, prompt_sha)
            if entry is None:
                return self._refuse(run_dir, base, {"scope": agent, "reason": "missing_price"},
                                    attempts_sent)
            if provider != "fake" and entry.get("verified") is not True:
                return self._refuse(run_dir, base,
                                    {"scope": agent, "reason": "price_unverified"},
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
                                     timeout=self.cfg["timeout_s"], api_key=key,
                                     request=request, output_schema=output_schema)
            except Exception as exc:  # noqa: BLE001 - one failed call never crashes a match
                latency = max(0, round_ms(self.clock() - t0))
                kind, status, retry_after = classify(exc)
                self._write(run_dir, {**base, "ok": False, "error_type": kind,
                                      "http_status": status, "refusal": None,
                                      "stop_reason": None,
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
                                  "stop_reason": reply.stop_reason,
                                  "input_tokens": u.input_tokens,
                                  "cached_input_tokens": u.cached_input_tokens,
                                  "cache_write_tokens": u.cache_write_tokens,
                                  "output_tokens": u.output_tokens, "latency_ms": latency})
            return Result(ok=True, text=reply.text, usage=u, attempts=attempts_sent,
                          stop_reason=reply.stop_reason, raw_usage=reply.raw_usage)
        raise AssertionError("unreachable")


def round_ms(seconds: float) -> int:
    return int(seconds * 1000 + 0.5)
