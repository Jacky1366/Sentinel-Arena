"""A key value never appears in api_calls.jsonl, match.json, terminal output,
Result.error or exception text.

The sentinel is deliberately NOT shaped like a real provider key, so the
gitleaks pre-commit hook does not (and must not need to) allowlist this file.
Key-shaped strings are built at runtime for the pattern test for the same reason.
"""

from __future__ import annotations

import json

import pytest

from llm_fakes import FakeAdapter, MESSAGES, SYSTEM, lc, lines, make_client, run_dir

SENTINEL = "SENTINEL-FAKE-KEY-not-a-secret-7f3a"
ENV = {"ARENA_ANTHROPIC_API_KEY": SENTINEL}


class LeakyError(Exception):
    """An SDK error that echoes the key it was given (worst case)."""


def leaky_adapter(script):
    a = FakeAdapter(provider="anthropic", needs_key=True)

    def call(**kw):
        a.calls.append(kw)
        item = script.pop(0) if script else "ok"
        if item == "leak":
            raise LeakyError(f"401 invalid x-api-key {kw['api_key']}")
        if item == "leak-retry":
            e = LeakyError(f"503 upstream, key={kw['api_key']}")
            e.status_code = 503
            raise e
        return lc.Reply(text="{}", usage=a.usage)
    a.call = call
    return a


def test_key_never_in_result_or_api_calls(tmp_path):
    d = run_dir(tmp_path)
    adapter = leaky_adapter(["leak-retry", "leak"])
    client, _ = make_client(adapter, env=ENV, tmp_path=tmp_path)
    r = client.complete("blue", "fake-keyed", SYSTEM, MESSAGES, run_dir=d,
                        log_seq_first=1, log_seq_last=1)
    assert not r.ok and adapter.calls[0]["api_key"] == SENTINEL  # it was really used
    assert SENTINEL not in (r.error or "") and "[REDACTED]" in r.error
    assert SENTINEL not in repr(r)
    assert SENTINEL not in (d / lc.API_CALLS).read_text()
    assert len(lines(d)) == 2


def test_a_deepseek_key_is_redacted_too(tmp_path):
    d = run_dir(tmp_path)
    (tmp_path / "no.env").write_text(f"ARENA_DEEPSEEK_API_KEY={SENTINEL}\n")
    assert SENTINEL in lc.key_values({}, tmp_path / "no.env")  # read only inside llm_client
    client, _ = make_client(leaky_adapter(["leak"]), tmp_path=tmp_path)
    r = client.complete("blue", "fake-keyed", SYSTEM, MESSAGES, run_dir=d,
                        log_seq_first=1, log_seq_last=1)
    assert SENTINEL not in (r.error or "") and SENTINEL not in (d / lc.API_CALLS).read_text()


def test_key_in_a_dotenv_file_is_redacted_too(tmp_path):
    d = run_dir(tmp_path)
    (tmp_path / "no.env").write_text(f"ARENA_ANTHROPIC_API_KEY={SENTINEL}\n")
    client, _ = make_client(leaky_adapter(["leak"]), tmp_path=tmp_path)
    r = client.complete("blue", "fake-keyed", SYSTEM, MESSAGES, run_dir=d,
                        log_seq_first=1, log_seq_last=1)
    assert SENTINEL not in r.error


def test_redact_removes_key_shaped_strings_without_knowing_them():
    shaped = ["sk-" + "ant-" + "api03-" + "Ab1_" * 10, "sk-" + "proj-" + "Zz9" * 10,
              "AI" + "za" + "Sy" + "Q" * 30]
    for s in shaped:
        assert s not in lc.redact(f"error near {s} here", keys=[])


def test_claude_code_is_denied_the_env_files():
    from llm_fakes import REPO
    deny = json.loads((REPO / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    for rule in ("Read(./.env)", "Read(./.env.*)", "Read(**/.env)", "Read(**/.env.*)",
                 "Bash(cat .env*)", "Bash(printenv*)"):
        assert rule in deny, rule


def test_key_never_in_match_json_or_terminal(tmp_path, monkeypatch):
    # A step fails with an exception whose text contains the key.
    import run_match
    from test_run_match_failure import FakeOps

    monkeypatch.setenv("ARENA_ANTHROPIC_API_KEY", SENTINEL)

    class LeakingRed(FakeOps):
        def traffic(self, match_id, match_dir, attacks, benign_entries, schedule, settle,
                red_driver=None):
            super().traffic(match_id, match_dir, attacks, benign_entries, schedule, settle)
            raise RuntimeError(f"provider said: bad key {SENTINEL}")

    live = tmp_path / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text("")
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=LeakingRed(live), live_dir=live,
                                          runs_dir=tmp_path / "runs", out=out.append)
    assert code == 1
    manifest = (match_dir / "match.json").read_text()
    assert SENTINEL not in manifest and "[REDACTED]" in json.loads(manifest)["error"]
    assert SENTINEL not in "\n".join(out)
    for f in match_dir.iterdir():
        assert SENTINEL not in f.read_text(), f.name


# ---- the session guard (tests/conftest.py): no real provider is reachable ----------

def test_no_arena_key_is_visible_inside_the_test_session():
    import os
    assert [k for k in os.environ if k.startswith("ARENA_")] == []
    assert not lc.DOTENV_PATH.exists()
    assert lc.key_values() == []
    client = lc.LLMClient(config=lc.load_config(), prices=lc.cost_mod.load_prices(),
                          adapters={})
    assert all(client._key(p) is None for p in lc.KEY_ENV)


def test_a_real_provider_client_is_refused_inside_the_test_session(tmp_path, monkeypatch):
    # Real config, real price table, REAL adapters (the default): exactly what a fake
    # that falls through would hit. Since 6.1b the client is not even built: no ARENA_GO
    # in a test session (conftest), so GoTokenError; the missing_key layer behind it is
    # covered with keyed fakes in tests/test_llm_client.py.
    for cls in (lc.AnthropicAdapter, lc.OpenAIAdapter, lc.DeepSeekAdapter):
        monkeypatch.setattr(cls, "call", lambda self, **kw: (_ for _ in ()).throw(
            AssertionError("a real adapter was called")))
    with pytest.raises(lc.GoTokenError, match="ARENA_GO"):
        lc.LLMClient(config=lc.load_config(), prices=lc.cost_mod.load_prices())


def test_the_guard_redirects_the_repo_dotenv():
    # From 5.4 the repo .env holds real keys. Inside the test session the client
    # must not be looking there at all, whether or not the file exists.
    assert lc.DOTENV_PATH != lc.REPO / ".env"
    assert lc.LLMClient(config=lc.load_config(), prices=lc.cost_mod.load_prices(),
                        adapters={}).dotenv_path == lc.DOTENV_PATH
