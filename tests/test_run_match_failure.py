"""run_match.py failure handling, lock, and the proxy-log rotate/freeze contract.

No Docker: every Docker/network step is replaced by a fake that writes the same
files the real step would (nginx is simulated by appending to live/proxy.jsonl and
by a fake `reopen` that creates a fresh live/proxy.jsonl). The pure steps -- Judge
fact 1, Blue, Judge round record -- run for real on the match directory.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from runner import match_ops  # noqa: E402

MANIFEST = Draft202012Validator(run_match.MANIFEST_SCHEMA)
IMAGE = {"image": "x:1", "image_id": "sha256:" + "b" * 64, "repo_digest": None}
STEPS = ["reset", "rotate", "red", "freeze", "judge_fact1", "blue", "judge_rounds"]
PREVIOUS = '{"request_id":"","note":"previous match traffic"}\n'

ATTACKS = [
    # (request_id, label, method, path, query, body, before, after)
    ("11111111-1111-4111-8111-111111111111", "CWE-89", "POST", "/rest/user/login", "",
     '{"email":"\' OR 1=1--","password":"x"}', [], ["Login Admin"]),
    ("22222222-2222-4222-8222-222222222222", "CWE-79", "GET", "/rest/products/search",
     "q=<script>alert(1)</script>", "", ["Login Admin"], ["Login Admin"]),
]


def fake_reopen(live_dir: Path):
    """nginx reopen: opens the path again, creating a fresh empty file."""
    def reopen():
        (live_dir / "proxy.jsonl").touch()
    return reopen


class FakeOps(run_match.Ops):
    """Real file semantics, no Docker. Override one method to inject a failure."""

    def __init__(self, live_dir: Path, skip_snapshot_for: int | None = None,
                 attacks=ATTACKS):
        self.live = live_dir
        self.attacks = attacks
        self.skip_snapshot_for = skip_snapshot_for
        self.calls: list[str] = []

    def preflight(self):
        return {"juice_shop": IMAGE, "nginx": IMAGE}

    def git_info(self):
        return {"commit": "f" * 40, "dirty": False}

    def reset(self):
        self.calls.append("reset")
        return 0

    def rotate(self, live_dir):
        self.calls.append("rotate")
        return match_ops.rotate_proxy_log(live_dir, reopen=fake_reopen(live_dir),
                                          poll_timeout=0.1)

    def red(self, match_id, match_dir, payloads, settle):
        self.calls.append("red")
        for i, (rid, label, method, path, query, body, before, after) in \
                enumerate(self.attacks, start=1):
            with (match_dir / "red_attacks.jsonl").open("a") as fh:
                fh.write(json.dumps({
                    "schema_version": "0.1", "match_id": match_id, "round": i,
                    "request_id": rid, "label": label, "payload": body or query,
                    "endpoint": path, "method": method,
                    "timestamp": "2026-11-09T00:00:00Z"}) + "\n")
            with (self.live / "proxy.jsonl").open("a") as fh:  # nginx logs it
                fh.write(json.dumps({
                    "timestamp": "2026-11-09T00:00:00Z", "request_id": rid,
                    "method": method, "path": path, "query": query, "body": body,
                    "status": 200}) + "\n")
            if i != self.skip_snapshot_for:
                with (match_dir / "challenge_snapshots.jsonl").open("a") as fh:
                    fh.write(json.dumps({
                        "request_id": rid, "before_solved": before, "after_solved": after,
                        "taken_at": "2026-11-09T00:00:01Z"}) + "\n")

    def freeze(self, live_dir, match_dir):
        self.calls.append("freeze")
        match_ops.freeze_proxy_log(live_dir, match_dir, reopen=fake_reopen(live_dir),
                                   poll_timeout=0.1)

    def reopen(self, live_dir):
        self.calls.append("reopen")
        match_ops.reopen_and_confirm(live_dir, reopen=fake_reopen(live_dir),
                                     poll_timeout=0.1)


def broken_reopen(self, live_dir):
    """nginx never creates a fresh log (e.g. reopen signal not delivered)."""
    match_ops.reopen_and_confirm(live_dir, reopen=lambda: None, poll_timeout=0.05)


def failing(step: str, exc: BaseException = RuntimeError("injected failure")):
    """A FakeOps whose `step` raises (after the fake did nothing for that step)."""
    class Failing(FakeOps):
        pass

    def boom(self, *a, **k):
        self.calls.append(step)
        raise exc
    setattr(Failing, step, boom)
    return Failing


@pytest.fixture
def dirs(tmp_path):
    live = tmp_path / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text(PREVIOUS)  # earlier traffic, not this match's
    return live, tmp_path / "runs"


def go(ops, dirs):
    live, runs = dirs
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=ops, live_dir=live, runs_dir=runs,
                                          out=out.append)
    return code, match_dir, "\n".join(out)


def manifest_of(match_dir: Path) -> dict:
    m = json.loads((match_dir / "match.json").read_text())
    errs = [e.message for e in MANIFEST.iter_errors(m)]
    assert not errs, errs
    return m


def assert_finalized(live: Path, match_dir: Path):
    assert not (live / match_ops.LOCK_NAME).exists(), "lock not released"
    assert match_ops.live_unexpected(live) == [], "artifacts left in live/"
    m = manifest_of(match_dir)
    assert m["artifacts"] == run_match.artifact_hashes(match_dir)
    assert "match.json" not in m["artifacts"]
    return m


# ---------------------------------------------------------------- happy path

def test_completed_match_with_fakes(dirs):
    live, _ = dirs
    code, match_dir, out = go(FakeOps(live), dirs)
    assert code == 0, out
    m = assert_finalized(live, match_dir)
    assert m["status"] == "completed" and m["failed_step"] is None and m["error"] is None
    assert m["match_id"] == match_dir.name
    assert set(m["artifacts"]) == {"red_attacks.jsonl", "challenge_snapshots.jsonl",
                                   "proxy.jsonl", "landed.jsonl", "verdicts.jsonl",
                                   "rounds.jsonl"}
    # previous traffic archived, never deleted; live/ restarts with a fresh empty log
    archived = list((live / "archive").iterdir())
    assert [p.read_text() for p in archived] == [PREVIOUS]
    assert (live / "proxy.jsonl").read_text() == ""
    rounds = [json.loads(l) for l in (match_dir / "rounds.jsonl").read_text().splitlines()]
    assert [(r["landed"], r["detected"], r["type_correct"]) for r in rounds] == \
        [(True, True, True), (None, True, True)]
    assert "detection      2/2 (100%)" in out


def test_match_id_format(dirs):
    _, match_dir, _ = go(FakeOps(dirs[0]), dirs)
    import re
    assert re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}", match_dir.name)


# ---------------------------------------------------------------- failures

@pytest.mark.parametrize("step", STEPS)
def test_any_step_failure_is_finalized(dirs, step):
    live, _ = dirs
    code, match_dir, out = go(failing(step)(live), dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert m["status"] == "failed" and m["failed_step"] == step
    assert "injected failure" in m["error"]
    assert "MATCH FAILED" in out
    if STEPS.index(step) < STEPS.index("red"):
        # Never rotated: live/proxy.jsonl is earlier traffic, NOT this match's.
        assert (live / "proxy.jsonl").read_text() == PREVIOUS
        assert not (match_dir / "proxy.jsonl").exists()
    else:
        assert (match_dir / "proxy.jsonl").exists()


def test_red_fails_midway_partial_artifacts_moved(dirs):
    live, _ = dirs

    class RedDiesAfterOne(FakeOps):
        def red(self, match_id, match_dir, payloads, settle):
            super().red(match_id, match_dir, payloads, settle)  # first attack only
            raise ConnectionError("arena went away")

    code, match_dir, _ = go(RedDiesAfterOne(live, attacks=ATTACKS[:1]), dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert m["failed_step"] == "red" and "ConnectionError" in m["error"]
    assert len((match_dir / "red_attacks.jsonl").read_text().splitlines()) == 1
    assert len((match_dir / "proxy.jsonl").read_text().splitlines()) == 1
    assert (live / "proxy.jsonl").read_text() == ""


def test_freeze_reopen_never_works_file_still_moved_and_reported(dirs):
    live, _ = dirs

    class BrokenNginx(FakeOps):
        def freeze(self, live_dir, match_dir):
            match_ops.freeze_proxy_log(live_dir, match_dir, reopen=lambda: None,
                                       poll_timeout=0.05)
        reopen = broken_reopen

    code, match_dir, _ = go(BrokenNginx(live), dirs)
    assert code == 1
    m = manifest_of(match_dir)
    assert m["failed_step"] == "freeze"
    assert "finalize could not freeze" in m["error"]
    assert "NOT FROZEN" in m["error"]
    assert (match_dir / "proxy.jsonl").exists() and not (live / "proxy.jsonl").exists()
    assert not (live / match_ops.LOCK_NAME).exists()


def test_fallback_move_then_reopen_succeeds_is_frozen(dirs):
    # freeze fails BEFORE moving; finalize moves the log, then the best-effort
    # reopen works -> frozen, and live/ gets a fresh empty log.
    live, _ = dirs
    ops = failing("freeze")(live)
    code, match_dir, out = go(ops, dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert m["failed_step"] == "freeze"
    assert "fallback: proxy log moved to the match dir" in m["error"]
    assert "best-effort nginx reopen succeeded: proxy log frozen" in m["error"]
    assert "NOT FROZEN" not in m["error"]
    assert ops.calls[-1] == "reopen"
    assert len((match_dir / "proxy.jsonl").read_text().splitlines()) == len(ATTACKS)
    assert (live / "proxy.jsonl").read_text() == ""  # fresh log from the reopen


def test_fallback_move_then_reopen_fails_is_not_frozen(dirs):
    # freeze fails BEFORE moving; finalize moves the log, the reopen also fails ->
    # the log is in the match dir but marked NOT FROZEN.
    live, _ = dirs

    class FreezeAndReopenBroken(failing("freeze")):
        reopen = broken_reopen

    code, match_dir, out = go(FreezeAndReopenBroken(live), dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert "fallback: proxy log moved to the match dir" in m["error"]
    assert "best-effort nginx reopen failed" in m["error"]
    assert "NOT FROZEN" in m["error"]
    assert "reopen succeeded" not in m["error"]
    assert (match_dir / "proxy.jsonl").exists() and not (live / "proxy.jsonl").exists()
    assert "best-effort nginx reopen failed" in out


def test_reset_not_clean_refuses(dirs):
    live, _ = dirs

    class Dirty(FakeOps):
        def reset(self):
            return 3

    code, match_dir, _ = go(Dirty(live), dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert m["failed_step"] == "reset" and "not clean" in m["error"]


def test_judge_raises_on_ambiguous_data_is_a_failure(dirs):
    live, _ = dirs

    class DuplicateVerdicts(FakeOps):
        def blue(self, match_dir, match_id, engine):
            super().blue(match_dir, match_id, engine)
            path = match_dir / "verdicts.jsonl"
            first = path.read_text().splitlines()[0]
            path.write_text(path.read_text() + first + "\n")  # same request_id twice

    code, match_dir, _ = go(DuplicateVerdicts(live), dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert m["failed_step"] == "judge_rounds" and "duplicate verdict" in m["error"]
    assert not (match_dir / "rounds.jsonl").exists()


def test_snapshot_missing_is_not_a_failure(dirs):
    live, _ = dirs
    code, match_dir, out = go(FakeOps(live, skip_snapshot_for=1), dirs)
    assert code == 0, out
    assert manifest_of(match_dir)["status"] == "completed"
    rounds = [json.loads(l) for l in (match_dir / "rounds.jsonl").read_text().splitlines()]
    assert rounds[0]["landed_reason"] == "snapshot_missing"
    assert rounds[0]["detected"] is True  # detection still scored


def test_keyboard_interrupt_is_finalized(dirs):
    live, _ = dirs
    code, match_dir, _ = go(failing("red", KeyboardInterrupt())(live), dirs)
    assert code == 1
    m = assert_finalized(live, match_dir)
    assert m["failed_step"] == "red" and m["error"].startswith("KeyboardInterrupt")


# ---------------------------------------------------------------- refusals

def test_lock_held_refuses_without_touching_anything(dirs):
    live, runs = dirs
    lock = match_ops.acquire_lock(live, "20261109T000000Z-dead")
    held = lock.read_text()
    ops = FakeOps(live)
    code, match_dir, out = go(ops, dirs)
    assert code == 3 and match_dir is None
    assert "20261109T000000Z-dead" in out and "rm " in out  # removal instructions
    assert lock.read_text() == held  # never auto-broken
    assert ops.calls == []
    assert sorted(p.name for p in runs.iterdir()) == ["live"]


def test_preflight_failure_no_lock_no_match_dir(dirs):
    live, runs = dirs

    class Down(FakeOps):
        def preflight(self):
            raise match_ops.PreflightError("container 'nginx' is not running")

    code, match_dir, out = go(Down(live), dirs)
    assert code == 2 and match_dir is None and "not running" in out
    assert not (live / match_ops.LOCK_NAME).exists()
    assert sorted(p.name for p in runs.iterdir()) == ["live"]


def test_preflight_refuses_on_leftovers_in_live(dirs):
    live, runs = dirs
    (live / "rounds.jsonl").write_text("{}\n")
    (live / "verdicts.jsonl").write_text("{}\n")
    code, match_dir, out = go(FakeOps(live), dirs)
    assert code == 2 and match_dir is None
    assert "['rounds.jsonl', 'verdicts.jsonl']" in out
    assert (live / "rounds.jsonl").exists()  # never deleted
    assert sorted(p.name for p in runs.iterdir()) == ["live"]


# ---------------------------------------------------------------- rotate / freeze

def test_rotate_archives_nonempty_log(tmp_path):
    (tmp_path / "proxy.jsonl").write_text("line\n")
    archived = match_ops.rotate_proxy_log(tmp_path, reopen=fake_reopen(tmp_path))
    assert archived.parent == tmp_path / "archive" and archived.read_text() == "line\n"
    assert (tmp_path / "proxy.jsonl").read_text() == ""


def test_rotate_deletes_only_an_empty_log(tmp_path):
    (tmp_path / "proxy.jsonl").write_text("")
    assert match_ops.rotate_proxy_log(tmp_path, reopen=fake_reopen(tmp_path)) is None
    assert not (tmp_path / "archive").exists()


def test_rotate_raises_if_nginx_never_creates_fresh_log(tmp_path):
    (tmp_path / "proxy.jsonl").write_text("line\n")
    with pytest.raises(RuntimeError, match="did not create a fresh"):
        match_ops.rotate_proxy_log(tmp_path, reopen=lambda: None, poll_timeout=0.05)
    # the evidence was archived, not lost
    assert [p.read_text() for p in (tmp_path / "archive").iterdir()] == ["line\n"]


def test_freeze_refuses_to_overwrite(tmp_path):
    live, match = tmp_path / "live", tmp_path / "m"
    live.mkdir(), match.mkdir()
    (live / "proxy.jsonl").write_text("new\n")
    (match / "proxy.jsonl").write_text("frozen\n")
    with pytest.raises(FileExistsError):
        match_ops.freeze_proxy_log(live, match, reopen=fake_reopen(live))
    assert (match / "proxy.jsonl").read_text() == "frozen\n"


def test_freeze_raises_without_any_log(tmp_path):
    live, match = tmp_path / "live", tmp_path / "m"
    live.mkdir(), match.mkdir()
    with pytest.raises(FileNotFoundError):
        match_ops.freeze_proxy_log(live, match, reopen=fake_reopen(live))


# ---- Stage 5.1: manifest 0.2, budget, cost ---------------------------------

def test_scripted_match_manifest_v0_2_zero_cost(dirs):
    code, match_dir, out = go(FakeOps(dirs[0]), dirs)
    m = manifest_of(match_dir)
    assert code == 0 and m["schema_version"] == "0.2"
    assert m["models"] == {"red": None, "blue": None, "analyst": None}
    assert m["budget"]["stopped_by"] is None
    assert m["budget"]["limits"]["blue"] == {"max_calls": 100, "max_tokens": 300000,
                                             "max_usd": 0.25}
    assert m["cost"]["total_usd"] == 0 and m["cost"]["attempts"] == 0
    assert m["price_table"]["path"] == "config/prices.json"
    assert not (match_dir / "api_calls.jsonl").exists()
    assert "cost $0.00 (0 API calls)" in out


def _red_with_ai_calls(max_calls):
    """A Red that also makes fake AI calls through the real client and budget."""
    from llm_fakes import FakeAdapter, MESSAGES, SYSTEM, config, make_client

    class AIRed(FakeOps):
        def red(self, match_id, match_dir, payloads, settle):
            super().red(match_id, match_dir, payloads, settle)
            client, _ = make_client(FakeAdapter(), cfg=config(red={"max_calls": max_calls}))
            for i in range(1, 4):
                client.complete("red", "fake-small", SYSTEM, MESSAGES, run_dir=match_dir,
                                round=i)
    return AIRed


def test_budget_refusal_marks_match_stopped_exit_4(dirs):
    code, match_dir, out = go(_red_with_ai_calls(max_calls=2)(dirs[0]), dirs)
    m = manifest_of(match_dir)
    assert code == 4 and m["status"] == "stopped"
    assert m["failed_step"] is None and m["error"] is None
    assert m["budget"]["stopped_by"] == {"scope": "red", "reason": "max_calls"}
    assert (m["cost"]["attempts"], m["cost"]["refused"]) == (2, 1)
    assert "api_calls.jsonl" in m["artifacts"]
    assert (match_dir / "rounds.jsonl").exists()  # the rest of the match still ran
    assert "STOPPED by the AI budget: red max_calls" in out


def test_ai_calls_within_budget_complete(dirs):
    code, match_dir, out = go(_red_with_ai_calls(max_calls=10)(dirs[0]), dirs)
    m = manifest_of(match_dir)
    assert code == 0 and m["status"] == "completed" and m["cost"]["attempts"] == 3
    assert "cost $0.0001 (3 API calls)" in out or "(3 API calls" in out


def test_failure_after_a_cap_is_failed_and_keeps_stopped_by(dirs):
    AIRed = _red_with_ai_calls(max_calls=1)

    class Both(AIRed):
        def blue(self, *a, **k):
            raise RuntimeError("blue broke")
    code, match_dir, _ = go(Both(dirs[0]), dirs)
    m = manifest_of(match_dir)
    assert code == 1 and m["status"] == "failed" and m["failed_step"] == "blue"
    assert m["budget"]["stopped_by"] == {"scope": "red", "reason": "max_calls"}


def test_bad_llm_config_refused_at_preflight(dirs):
    from agents import llm_client

    class BadConfig(FakeOps):
        def llm_setup(self):
            raise llm_client.ConfigError("caps: missing scope 'analyst'")
    code, match_dir, out = go(BadConfig(dirs[0]), dirs)
    assert code == 2 and match_dir is None and "PREFLIGHT FAILED" in out
    assert not (dirs[0] / "match.lock").exists()
