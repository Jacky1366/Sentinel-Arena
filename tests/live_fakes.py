"""A fake live match for the live-server tests (Stage 7 #12): the REAL orchestrator, the
REAL traffic loop (match_ops.run_traffic), real rotate / freeze file moves, and the fake
provider for Red and Blue. Network is stubbed: the arena sender appends an nginx-shaped
line to live/proxy.jsonl (as nginx would), snapshots never touch the admin port, and every
network step of run_match.Ops is overridden. Stdout (out + the traffic log) is tee'd to a
transcript file, as `... | tee <file>` would."""

from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from llm_fakes import CONFIG, PRICES, REPO, lc
import run_match
from runner import arena_client, match_ops
from stats import cost as cost_stats
from test_blue_rules import Brain
from test_run_match_rules import broad

IMAGE = {"image": "x:1", "image_id": "sha256:" + "b" * 64, "repo_digest": None}
SEED = 424242
RED_TEXTS = [
    json.dumps({"method": "GET", "path": "/rest/products/search?q=1%27%20OR%201=1--", "body": "",
                "label": "CWE-89", "rationale": "sqli probe"}),
    "not json",                                                       # brain_failure
    json.dumps({"method": "GET", "path": "http://evil.example/x", "body": "",
                "label": "CWE-22", "rationale": "off scope"}),        # guard_block
    json.dumps({"method": "GET", "path": "/rest/products/search?q=%3Cb%3Ex%3C/b%3E", "body": "",
                "label": "CWE-79", "rationale": "xss probe"}),
]
# A previous match's leftovers in live/proxy.jsonl before rotation: one stray line and
# one line with an id this match never sends.
PREVIOUS = ('{"request_id":"","path":""}\n'
            '{"timestamp":"2026-11-01T00:00:00Z","request_id":"99999999-9999-4999-8999-'
            '999999999999","method":"GET","path":"/old","query":"","body":"","status":200}\n')


class SeqAdapter:
    provider, needs_key = "fake", False

    def __init__(self, texts):
        self.texts = list(texts)

    def call(self, **kw):
        text = self.texts.pop(0) if self.texts else RED_TEXTS[0]
        return lc.Reply(text=text, usage=lc.Usage(50, 0, 0, 20), stop_reason="completed")


def live_config() -> dict:
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["red"].update(provider="fake", model="fake-small", round_cap=len(RED_TEXTS),
                                request={"effort": "low"})
    return cfg


def _client(cfg, prices, adapter):
    return lc.LLMClient(config=cfg, prices=prices, adapters={"fake": adapter}, env={},
                        sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")


class LiveOps(run_match.Ops):
    def __init__(self, live: Path, out, fail_blue: bool = False):
        self.live, self.out, self.fail_blue = live, out, fail_blue

    def preflight(self):
        return {"juice_shop": IMAGE, "nginx": IMAGE}

    def git_info(self):
        return {"commit": "f" * 40, "dirty": False}

    def llm_setup(self):
        return live_config(), PRICES, cost_stats.price_table_ref()

    def reset(self):
        return 0

    def challenge_catalog(self):
        return {}

    def _reopen(self, live_dir):
        return lambda: (live_dir / "proxy.jsonl").touch()

    def rotate(self, live_dir):
        return match_ops.rotate_proxy_log(live_dir, reopen=self._reopen(live_dir),
                                          poll_timeout=1.0)

    def freeze(self, live_dir, match_dir):
        match_ops.freeze_proxy_log(live_dir, match_dir, reopen=self._reopen(live_dir),
                                   poll_timeout=1.0)

    def reopen(self, live_dir):
        match_ops.reopen_and_confirm(live_dir, reopen=self._reopen(live_dir), poll_timeout=1.0)

    def traffic(self, match_id, match_dir, attacks, benign_entries, schedule, settle,
                red_driver=None):
        match_ops.run_traffic(match_id, match_dir, attacks, benign_entries, schedule, settle,
                              log=self.out, red_driver=red_driver)

    def red_client(self, config, prices):
        return _client(config, prices, SeqAdapter(RED_TEXTS))

    def blue_client(self, config, prices):
        return _client(config, prices, Brain(broad))

    def blue(self, *a, **k):
        if self.fail_blue:
            raise RuntimeError("blue fell over (test)")
        return super().blue(*a, **k)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """live/ with a previous match's log, runs/, a transcript path, and the network stubs."""
    runs = tmp_path / "runs"
    live = runs / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text(PREVIOUS)
    transcript = tmp_path / "match.transcript.log"
    state = {"last": ""}

    def fake_send(method, target, request_id, body=None, timeout=None, **k):
        u = urlsplit(target)
        with (live / "proxy.jsonl").open("a", encoding="utf-8") as fh:  # what nginx logs
            fh.write(json.dumps({"timestamp": "2026-11-24T19:00:00Z", "request_id": request_id,
                                 "method": method, "path": u.path, "query": u.query,
                                 "body": body or "", "status": 200}) + "\n")
        state["last"] = target
        time.sleep(0.002)
        return arena_client.Response(200, body_text="OK")

    monkeypatch.setattr(arena_client, "send", fake_send)
    monkeypatch.setattr(match_ops, "solved_now", lambda *a, **k: [])
    monkeypatch.setattr(match_ops, "snapshot_after",
                        lambda before, settle, **k: ["Login Admin"]
                        if "OR%201=1" in state["last"] else list(before))
    return live, runs, transcript


def tee(transcript: Path):
    def out(text: str = "") -> None:
        with transcript.open("a", encoding="utf-8") as fh:
            fh.write(f"{text}\n")
    return out


def play(lab, fail_blue: bool = False) -> tuple[int, Path]:
    live, runs, transcript = lab
    out = tee(transcript)
    code, match_dir = run_match.run_match(
        ops=LiveOps(live, out, fail_blue), live_dir=live, runs_dir=runs, red_engine="ai",
        engine="claude", blue_rules_mode="on", seed=SEED, settle=0, out=out)
    return code, match_dir


def jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []
