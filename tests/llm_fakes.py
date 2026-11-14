"""Shared fakes for the LLM body tests: a scripted fake provider, fake SDK errors,
a test price table and config. No network, no SDKs, no keys."""

from __future__ import annotations

import copy
import itertools
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from agents import llm_client as lc  # noqa: E402

MATCH_ID = "20261109T153012Z-a1b2"

PRICES = {
    "schema_version": "0.1", "as_of": "2026-11-08", "currency": "USD",
    "unit": "per_million_tokens",
    "models": {
        "fake-small": {"provider": "fake", "as_of": "2026-11-08", "source": "test",
                       "verified": False,
                       "tiers": [{"max_prompt_tokens": None, "input": 1.0, "cached_input": 0.1,
                                  "cache_write": 1.25, "output": 2.0}]},
        "fake-nowrite": {"provider": "fake", "as_of": "2026-11-08", "source": "test",
                         "verified": True,
                         "tiers": [{"max_prompt_tokens": None, "input": 1.0, "cached_input": None,
                                    "cache_write": None, "output": 2.0}]},
        "fake-keyed": {"provider": "anthropic", "as_of": "2026-11-08", "source": "test",
                       "verified": True,
                       "tiers": [{"max_prompt_tokens": None, "input": 1.0, "cached_input": 0.1,
                                  "cache_write": 1.25, "output": 2.0}]},
        "fake-keyed-unverified": {"provider": "anthropic", "as_of": "2026-11-08",
                                  "source": "test", "verified": False,
                       "tiers": [{"max_prompt_tokens": None, "input": 1.0, "cached_input": 0.1,
                                  "cache_write": 1.25, "output": 2.0}]},
    },
    "placeholders": {},
}

CONFIG = {
    "agents": {"red": {"provider": "fake", "model": None},
               "blue": {"provider": "fake", "model": "fake-small"},
               "analyst": {"provider": "fake", "model": None}},
    "timeout_s": 5, "max_retries": 3, "backoff_base_s": 1.0, "backoff_max_s": 30.0,
    "max_output_tokens": 100, "chars_per_token": 3,
    "caps": {"red": {"max_calls": 1000, "max_tokens": 10**9, "max_usd": 1000.0},
             "blue": {"max_calls": 1000, "max_tokens": 10**9, "max_usd": 1000.0},
             "analyst": {"max_calls": 0, "max_tokens": 0, "max_usd": 0},
             "match": {"max_calls": None, "max_tokens": None, "max_usd": None}},
}

SYSTEM = "You classify HTTP requests. Answer with one JSON object."
MESSAGES = [{"role": "user", "content": "GET /rest/products/search?q=apple"}]


def config(**caps) -> dict:
    """CONFIG with caps overridden, e.g. config(blue={"max_calls": 3})."""
    cfg = copy.deepcopy(CONFIG)
    for scope, over in caps.items():
        cfg["caps"][scope].update(over)
    return cfg


class FakeError(Exception):
    def __init__(self, msg="fake", status_code=None, retry_after=None):
        super().__init__(msg)
        if status_code is not None:
            self.status_code = status_code
        self.retry_after = retry_after


class APITimeoutError(Exception):
    """Named like the SDKs' timeout class; classify() matches on the name."""


class FakeAdapter:
    """Plays a script of outcomes: a Usage (success), an Exception (raised), or
    'ok' (default usage). After the script runs out, every call succeeds."""

    def __init__(self, script=(), provider="fake", needs_key=False,
                 usage=lc.Usage(10, 0, 0, 5), text='{"verdict": "benign"}'):
        self.provider, self.needs_key = provider, needs_key
        self.script = list(script)
        self.usage, self.text = usage, text
        self.calls: list[dict] = []

    def call(self, **kw):
        self.calls.append(kw)
        item = self.script.pop(0) if self.script else "ok"
        if isinstance(item, BaseException):
            raise item
        return lc.Reply(text=self.text, usage=self.usage if item == "ok" else item)


def make_client(adapter=None, cfg=None, prices=None, env=None, tmp_path=None):
    adapter = adapter or FakeAdapter()
    sleeps: list[float] = []
    ticks = itertools.count()
    cfg = copy.deepcopy(cfg or config())
    for a in cfg["agents"].values():  # every agent talks to this adapter's provider
        a["provider"] = adapter.provider
    client = lc.LLMClient(
        config=cfg, prices=prices or PRICES,
        adapters={"fake": adapter, "anthropic": adapter} if adapter.provider == "fake"
        else {adapter.provider: adapter},
        env=env or {}, dotenv_path=(tmp_path or REPO / "nonexistent") / "no.env",
        sleep=sleeps.append, clock=lambda: next(ticks) * 0.25,
        now=lambda: "2026-11-09T15:30:13.000Z")
    return client, sleeps


def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / MATCH_ID
    d.mkdir(exist_ok=True)
    return d


def lines(d: Path) -> list[dict]:
    p = d / lc.API_CALLS
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
