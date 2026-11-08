"""Sentinel Arena orchestrator: one complete scripted match, one command.

    .venv/bin/python run_match.py          # requires: docker compose up -d --wait

The orchestrator is the ONLY thing that sequences components. Components never
call each other; each step reads and writes file artifacts (docs/contract.md).

  1. preflight   both containers Up, juice-shop healthy, live/ has no leftovers,
                 provenance (git commit + dirty, payload sha256) readable
  2. lock        live/match.lock (refuse if held; never auto-broken)
  3. match_id    UTC timestamp + 4 hex, e.g. 20261109T153012Z-a1b2
  4. reset       restart the Target, verify 0 solved (refuse if not clean)
  5. rotate      archive the previous live/proxy.jsonl, nginx reopens a fresh one
  6. red         scripted Red + before/after snapshots -> data/runs/<match_id>/
  7. freeze      move live/proxy.jsonl into the match dir, nginx reopens
  8. judge_fact1 -> blue -> judge_rounds, on the FROZEN directory
  9. match.json  written LAST (status, provenance, sha256 of every artifact)
 10. summary     a pure read of rounds.jsonl + match.json

If any step from 4 on fails, the match is still finalized: whatever this match
produced is in data/runs/<match_id>/, match.json says status "failed" with the
failed step and error, the lock is released, and the exit code is non-zero. A
failed match never leaves its artifacts in live/. Incomplete data
(snapshot_missing) is not a failure; ambiguous data (the Judge raises) is.

Exit codes: 0 completed, 1 match failed, 2 preflight refused, 3 lock held.
No AI API calls: zero token cost.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
from blue import run_blue  # noqa: E402
from judge import JUDGE_VERSION, fact1_landed, round_record  # noqa: E402
from red import scripted_red  # noqa: E402
from runner import match_ops  # noqa: E402
from stats import match_stats  # noqa: E402

MANIFEST_SCHEMA = json.loads(
    (REPO / "schemas" / "match_manifest.schema.json").read_text(encoding="utf-8"))


def new_match_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{secrets.token_hex(2)}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_hashes(match_dir: Path) -> dict:
    """{relative name: {sha256, bytes}} for every file in the match dir except
    match.json itself."""
    out = {}
    for p in sorted(match_dir.rglob("*")):
        if p.is_file():
            name = p.relative_to(match_dir).as_posix()
            if name != "match.json":
                out[name] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    return out


def _display_path(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


class Ops:
    """Real implementations of every step. Tests subclass this to inject fakes or
    failures without Docker."""

    def preflight(self) -> dict:
        return match_ops.running_images()

    def git_info(self) -> dict:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, check=True,
                                capture_output=True, text=True).stdout.strip()
        status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO, check=True,
                                capture_output=True, text=True).stdout
        return {"commit": commit, "dirty": bool(status.strip())}

    def reset(self) -> int:
        return match_ops.reset_target()

    def rotate(self, live_dir: Path) -> Path | None:
        return match_ops.rotate_proxy_log(live_dir)

    def red(self, match_id: str, match_dir: Path, payloads: Path, settle: float) -> None:
        match_ops.run_attacks(match_id, match_dir, payloads, settle)

    def freeze(self, live_dir: Path, match_dir: Path) -> None:
        match_ops.freeze_proxy_log(live_dir, match_dir)

    def reopen(self, live_dir: Path) -> None:
        match_ops.reopen_and_confirm(live_dir)

    # Pure file steps: each component's own CLI entry point, pointed at the frozen
    # match directory.
    def judge_fact1(self, match_dir: Path) -> None:
        fact1_landed.main(["--run-dir", str(match_dir)])

    def blue(self, match_dir: Path, match_id: str, engine: str) -> None:
        run_blue.main(["--engine", engine, "--match-id", match_id,
                       "--run-dir", str(match_dir)])

    def judge_rounds(self, match_dir: Path) -> None:
        round_record.main(["--run-dir", str(match_dir)])


def _fallback_freeze(ops: Ops, live_dir: Path, match_dir: Path, out) -> str:
    """Finalize after a failed freeze. Never leave this match's log in live/: move it
    with a plain rename if it is still there, then try one best-effort nginx reopen.
    The log is "not frozen" only if that reopen also fails (nginx may then keep
    appending to the moved file until the next rotate). Returns text for `error`."""
    src, dst = live_dir / "proxy.jsonl", match_dir / "proxy.jsonl"
    note = ""
    if src.exists() and not dst.exists():
        try:
            src.replace(dst)
            note += " | fallback: proxy log moved to the match dir"
        except OSError as exc:
            return f" | fallback: proxy log left in live/: {exc}"
    if not dst.exists():
        return note + " | fallback: no proxy log to move"
    try:
        ops.reopen(live_dir)
    except Exception as exc:  # noqa: BLE001
        out(f"WARNING: best-effort nginx reopen failed: {exc}")
        return (note + f" | best-effort nginx reopen failed ({type(exc).__name__}: "
                f"{exc}): proxy log NOT FROZEN, nginx may keep appending to it until "
                f"the next rotate")
    out(f"proxy log frozen by fallback: {_display_path(dst)}")
    return note + " | best-effort nginx reopen succeeded: proxy log frozen"


def run_match(ops: Ops | None = None, live_dir: Path = match_ops.LIVE,
              runs_dir: Path = match_ops.RUNS, payloads: Path = scripted_red.PAYLOADS,
              settle: float = 3.0, engine: str = "scripted",
              out=print) -> tuple[int, Path | None]:
    """Run one match. Returns (exit_code, match_dir or None if never started)."""
    ops = ops or Ops()

    # 1. Preflight (no match exists yet: on failure, nothing to finalize).
    try:
        images = ops.preflight()
        match_ops.check_live_clean(live_dir)
        provenance = {
            "red_source": {"path": _display_path(payloads), "sha256": sha256_file(payloads)},
            "git": ops.git_info(),
        }
    except (match_ops.PreflightError, OSError, subprocess.CalledProcessError) as exc:
        out(f"PREFLIGHT FAILED: {exc}")
        return 2, None

    # 2-3. Lock, then the match exists.
    match_id = new_match_id()
    try:
        match_ops.acquire_lock(live_dir, match_id)
    except match_ops.LockHeld as exc:
        out(f"REFUSING TO START: {exc}")
        return 3, None

    match_dir = runs_dir / match_id
    try:
        match_dir.mkdir(parents=True, exist_ok=False)
    except OSError:
        match_ops.release_lock(live_dir)
        raise
    started_at = match_ops.utc_now()
    out(f"match {match_id} -> {_display_path(match_dir)}")

    failed_step: str | None = None
    error: str | None = None
    rotated = frozen = False
    step = "reset"
    try:
        solved = ops.reset()
        out(f"target reset: {solved} challenges solved")
        if solved != 0:
            raise RuntimeError(f"refusing to run: target not clean after reset "
                               f"({solved} challenges still solved)")

        step = "rotate"
        archived = ops.rotate(live_dir)
        rotated = True
        if archived is not None:
            out(f"previous proxy log archived: {_display_path(archived)}")

        step = "red"
        ops.red(match_id, match_dir, payloads, settle)

        step = "freeze"
        ops.freeze(live_dir, match_dir)
        frozen = True
        out(f"proxy log frozen: {_display_path(match_dir / 'proxy.jsonl')}")

        step = "judge_fact1"
        ops.judge_fact1(match_dir)
        step = "blue"
        ops.blue(match_dir, match_id, engine)
        step = "judge_rounds"
        ops.judge_rounds(match_dir)
        step = "done"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - finalize on ANY failure
        failed_step = step
        error = f"{type(exc).__name__}: {exc}"
        out(f"MATCH FAILED at step '{step}': {error}")
        out(traceback.format_exc().rstrip())
        # Only this match's artifacts move. The proxy log is this match's once it was
        # rotated; before that, live/proxy.jsonl is earlier traffic and stays for the
        # next rotation to archive.
        if rotated and not frozen:
            try:
                ops.freeze(live_dir, match_dir)
                out(f"proxy log moved to {_display_path(match_dir / 'proxy.jsonl')}")
            except Exception as fexc:  # noqa: BLE001
                error += f" | finalize could not freeze the proxy log: " \
                         f"{type(fexc).__name__}: {fexc}"
                out(f"WARNING: could not freeze the proxy log: {fexc}")
                error += _fallback_freeze(ops, live_dir, match_dir, out)

    # 9. match.json, written LAST, then release the lock.
    try:
        manifest = {
            "schema_version": "0.1",
            "match_id": match_id,
            "started_at": started_at,
            "finished_at": match_ops.utc_now(),
            "status": "completed" if failed_step is None else "failed",
            "failed_step": failed_step,
            "error": error,
            "judge_version": JUDGE_VERSION,
            "blue_engine": engine,
            **provenance,
            "images": images,
            "artifacts": artifact_hashes(match_dir),
        }
        (match_dir / "match.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                              encoding="utf-8")
        schema_errors = [e.message for e in Draft202012Validator(MANIFEST_SCHEMA)
                         .iter_errors(manifest)]
    finally:
        match_ops.release_lock(live_dir)

    if schema_errors:
        out(f"BUG: match.json is schema-invalid: {schema_errors}")
        return 1, match_dir

    # 10. Summary: pure read of the frozen artifacts.
    out("")
    out(match_stats.format_summary(
        match_stats.read_rounds(match_dir / "rounds.jsonl"), manifest))
    return (0 if manifest["status"] == "completed" else 1), match_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one complete scripted match.")
    parser.add_argument("--payloads", type=Path, default=scripted_red.PAYLOADS)
    parser.add_argument("--engine", choices=sorted(run_blue.ENGINES), default="scripted")
    parser.add_argument("--settle", type=float, default=3.0,
                        help="max seconds to wait for a solve to register")
    args = parser.parse_args(argv)
    code, _ = run_match(payloads=args.payloads, settle=args.settle, engine=args.engine)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
