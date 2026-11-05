"""Stage 2 measurement runner (the Stage 4 orchestrator will absorb this).

Responsibilities, all of which involve network/subprocess I/O so the Judge does
NOT have to:

  1. Reset the Target to a clean state (docker compose restart juice-shop), wait
     until healthy, and verify all challenges are unsolved.
  2. For each scripted Red attack, in order:
       snapshot solved-state (admin port 8081) -> fire ONE attack (arena port
       8080, via red.scripted_red) -> wait briefly for the solve to register ->
       snapshot again -> append one line to challenge_snapshots.jsonl.

The admin snapshots go to 127.0.0.1:8081, where nginx has access_log off, so
measuring never adds a line to proxy.jsonl (Blue's input). State is reset ONCE at
the start, not between attacks, so cross-round effects (already-solved) are real.

Outputs under data/runs/live/:  red_attacks.jsonl, challenge_snapshots.jsonl.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from red import scripted_red  # noqa: E402

OUT_DIR = REPO / "data" / "runs" / "live"
ADMIN_URL = "http://127.0.0.1:8081/api/Challenges/"
DOCKER = "/Applications/Docker.app/Contents/Resources/bin/docker"
COMPOSE_ARGS = [DOCKER, "compose"]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([*COMPOSE_ARGS, *args], cwd=REPO, check=check,
                          capture_output=True, text=True)


def solved_now(timeout: float = 10.0) -> list[str]:
    """Sorted names of currently-solved challenges, read via the admin port."""
    req = urllib.request.Request(ADMIN_URL)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)["data"]
    return sorted(c["name"] for c in data if c["solved"])


def reset_target(poll_timeout: float = 120.0) -> int:
    """Restart juice-shop, wait until healthy and the admin port answers, and
    verify challenges reset to unsolved. Returns the solved count after reset."""
    _compose("restart", "juice-shop")
    _compose("up", "-d", "--wait")  # blocks until healthy
    deadline = time.monotonic() + poll_timeout
    while True:
        try:
            count = len(solved_now())
            return count
        except Exception:  # noqa: BLE001 - admin port not up yet
            if time.monotonic() > deadline:
                raise
            time.sleep(1.0)


def rotate_proxy_log(out_dir: Path, poll_timeout: float = 15.0) -> Path | None:
    """Start this run with a clean live proxy log, WITHOUT destroying evidence: a
    non-empty existing log is moved to out_dir/archive/ before nginx reopens a fresh
    proxy.jsonl. Returns the archive path (or None if there was nothing to keep).
    A match begins fresh, but raw logs are never silently deleted."""
    log = out_dir / "proxy.jsonl"
    archived: Path | None = None
    if log.exists() and log.stat().st_size > 0:
        archive_dir = out_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%f")[:-3] + "Z"
        archived = archive_dir / f"proxy-{ts}.jsonl"
        log.replace(archived)  # move: preserve the bytes, then nginx recreates
    elif log.exists():
        log.unlink()  # empty file: nothing to preserve
    _compose("exec", "-T", "nginx", "nginx", "-s", "reopen")
    deadline = time.monotonic() + poll_timeout
    while not log.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    return archived


def snapshot_after(before, settle: float, poll: float = 0.25, stable_polls: int = 3,
                   poll_fn=solved_now, sleep_fn=time.sleep, clock=time.monotonic):
    """Snapshot solved-state after an attack, robust to a single attack solving
    several challenges at slightly different times.

    Wait for the first change from `before`, then keep polling until the solved set
    is unchanged for `stable_polls` consecutive reads, so a challenge that registers
    late is captured in THIS round (not leaked into the next round's diff). If
    nothing changes within `settle` seconds, return `before` unchanged. The whole
    wait is capped by `settle`.

    poll_fn/sleep_fn/clock are injectable for testing without a live Target.
    """
    deadline = clock() + settle
    after = poll_fn()
    # Phase 1: wait for the first observable change.
    while after == before and clock() < deadline:
        sleep_fn(poll)
        after = poll_fn()
    if after == before:
        return after  # no change at all within the settle window
    # Phase 2: wait for the solved set to stop growing/changing.
    last = after
    stable = 0
    while stable < stable_polls and clock() < deadline:
        sleep_fn(poll)
        current = poll_fn()
        if current == last:
            stable += 1
        else:
            last = current
            stable = 0
    return last


def run(match_id: str, out_dir: Path, settle: float) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Fresh artifacts for this run.
    (out_dir / "red_attacks.jsonl").write_text("", encoding="utf-8")
    snap_path = out_dir / "challenge_snapshots.jsonl"
    snap_path.write_text("", encoding="utf-8")

    reset_count = reset_target()
    print(f"target reset: {reset_count} challenges solved "
          f"({'clean' if reset_count == 0 else 'NOT CLEAN'})")
    if reset_count != 0:
        raise SystemExit("refusing to run: restart did not reset challenge state")
    archived = rotate_proxy_log(out_dir)
    if archived is not None:
        print(f"previous proxy log archived: {archived.relative_to(REPO)}")

    attacks = scripted_red.load_attacks()
    results = []
    with snap_path.open("a", encoding="utf-8") as snap_fh:
        for i, attack in enumerate(attacks, start=1):
            before = solved_now()
            res = scripted_red.send_one(attack, match_id, i, out_dir)
            after = snapshot_after(before, settle)
            snap_fh.write(json.dumps({
                "request_id": res["request_id"],
                "before_solved": before,
                "after_solved": after,
                "taken_at": utc_now(),
            }) + "\n")
            newly = sorted(set(after) - set(before))
            where = res["status"] if res["error"] is None else res["error"]
            print(f"round {i} {res['label']:7} -> {where}; newly_solved={newly}")
            results.append(res)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--match-id", default=scripted_red.DEFAULT_MATCH)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    parser.add_argument("--settle", type=float, default=3.0,
                        help="max seconds to wait for a solve to register")
    args = parser.parse_args(argv)
    run(args.match_id, args.out_dir, args.settle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
