"""A key value never appears in api_calls.jsonl, match.json, terminal output,
Result.error or exception text.

The sentinel is deliberately NOT shaped like a real provider key, so the
gitleaks pre-commit hook does not (and must not need to) allowlist this file.
Key-shaped strings are built at runtime for the pattern test for the same reason.
"""

from __future__ import annotations

import json

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


def test_key_never_in_match_json_or_terminal(tmp_path, monkeypatch):
    # A step fails with an exception whose text contains the key.
    import run_match
    from test_run_match_failure import FakeOps

    monkeypatch.setenv("ARENA_ANTHROPIC_API_KEY", SENTINEL)

    class LeakingRed(FakeOps):
        def red(self, match_id, match_dir, payloads, settle):
            super().red(match_id, match_dir, payloads, settle)
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
