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


def rotate_proxy_log(out_dir: Path, poll_timeout: float = 15.0) -> None:
    """Start this run with a clean live proxy log: remove it and tell nginx to
    reopen, so proxy.jsonl holds only this run's lines (a match begins fresh)."""
    log = out_dir / "proxy.jsonl"
    log.unlink(missing_ok=True)
    _compose("exec", "-T", "nginx", "nginx", "-s", "reopen")
    deadline = time.monotonic() + poll_timeout
    while not log.exists() and time.monotonic() < deadline:
        time.sleep(0.2)


def snapshot_after(before: list[str], settle: float, poll: float = 0.25) -> list[str]:
    """Poll the after-snapshot: return as soon as state changes, else after `settle`
    seconds (so no-change attacks don't block longer than necessary)."""
    deadline = time.monotonic() + settle
    after = solved_now()
    while after == before and time.monotonic() < deadline:
        time.sleep(poll)
        after = solved_now()
    return after


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
    rotate_proxy_log(out_dir)

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
