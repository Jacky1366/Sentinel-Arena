"""Shared match operations: the ONE code path for everything that touches Docker,
the network, or the staged proxy log. run_match.py and every check tool use this
module; nothing else may carry a copy of this logic.

Responsibilities (all involve I/O, so the Judge does NOT have to):

  - preflight: both containers up, juice-shop healthy, image versions as running.
  - lock: one match at a time (data/runs/live/match.lock), never auto-broken.
  - reset_target: restart juice-shop, verify all challenges unsolved.
  - rotate_proxy_log: archive the previous live log, nginx reopens a fresh one.
  - run_attacks: per scripted attack, snapshot (admin :8081) -> fire ONE attack
    (arena :8080, via red.scripted_red) -> stable after-snapshot.
  - freeze_proxy_log: move this match's proxy.jsonl into the match dir, then nginx
    reopens so later traffic can never append to the frozen file.

nginx behaviour this relies on (verified empirically, Stage 4, Docker Desktop on
macOS with a bind mount): nginx keeps its access-log file descriptor open, so after
the file is renamed -- even out of the bind-mounted directory -- nginx KEEPS
appending to the renamed file until `nginx -s reopen`. A move is therefore only
final once reopen has created a fresh live/proxy.jsonl; both rotate and freeze
raise if that file does not appear.

The admin snapshots go to 127.0.0.1:8081, where nginx has access_log off, so
measuring never adds a line to proxy.jsonl (Blue's input). State is reset ONCE per
match, not between attacks, so cross-round effects (already-solved) are real.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from red import scripted_red  # noqa: E402

RUNS = REPO / "data" / "runs"
LIVE = RUNS / "live"
LOCK_NAME = "match.lock"
ADMIN_URL = "http://127.0.0.1:8081/api/Challenges/"
DOCKER = "/Applications/Docker.app/Contents/Resources/bin/docker"
COMPOSE_ARGS = [DOCKER, "compose"]
SERVICES = ("juice-shop", "nginx")

# What may legitimately sit in live/ between matches. Anything else is a leftover
# from an earlier (crashed or pre-Stage-4) run, and preflight refuses to start.
# .DS_Store is macOS Finder metadata, not evidence.
LIVE_ALLOWED = {"proxy.jsonl", "archive", LOCK_NAME, ".DS_Store"}


class PreflightError(RuntimeError):
    """The stack or live/ is not in a state a match can start from."""


class LockHeld(RuntimeError):
    """Another match holds the lock (or a crashed one left it behind)."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([*COMPOSE_ARGS, *args], cwd=REPO, check=check,
                          capture_output=True, text=True)


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([DOCKER, *args], cwd=REPO, check=True,
                          capture_output=True, text=True)


# ---------------------------------------------------------------- preflight

def running_images() -> dict:
    """Inspect the RUNNING containers (not the compose file). Returns
    {service: {image, image_id, repo_digest}} after checking that both are up and
    juice-shop is healthy. Raises PreflightError with a clear message otherwise.
    Never starts the stack."""
    out: dict = {}
    for service in SERVICES:
        try:
            cid = _compose("ps", "-q", service).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise PreflightError(f"cannot query docker compose: {exc}") from exc
        if not cid:
            raise PreflightError(
                f"container '{service}' is not running. Start the stack first: "
                f"docker compose up -d --wait")
        info = json.loads(_docker("inspect", cid).stdout)[0]
        state = info["State"]
        if not state.get("Running"):
            raise PreflightError(f"container '{service}' is not Up (status "
                                 f"{state.get('Status')}). Run: docker compose up -d --wait")
        if service == "juice-shop":
            health = (state.get("Health") or {}).get("Status")
            if health != "healthy":
                raise PreflightError(f"juice-shop is not healthy (health={health}). "
                                     f"Wait, or run: docker compose up -d --wait")
        image_id = info["Image"]
        digests = json.loads(_docker("image", "inspect", image_id).stdout)[0].get(
            "RepoDigests") or []
        out[service.replace("-", "_")] = {
            "image": info["Config"]["Image"],
            "image_id": image_id,
            "repo_digest": digests[0] if digests else None,
        }
    return out


def live_unexpected(live_dir: Path) -> list[str]:
    """Names in live/ that are not allowed between matches (sorted)."""
    if not live_dir.is_dir():
        return []
    return sorted(p.name for p in live_dir.iterdir() if p.name not in LIVE_ALLOWED)


def check_live_clean(live_dir: Path) -> None:
    leftovers = live_unexpected(live_dir)
    if leftovers:
        raise PreflightError(
            f"unexpected file(s) in {live_dir}: {leftovers}. A match must not mix "
            f"with leftovers from an earlier run. Inspect them and move them to "
            f"{live_dir / 'archive'}/ (never delete raw evidence), then retry.")


# ---------------------------------------------------------------- lock

def acquire_lock(live_dir: Path, match_id: str) -> Path:
    """Create live/match.lock atomically. Refuses if it exists -- a crashed match
    (kill -9) can leave a stale lock; that is cleared by a human, never here."""
    live_dir.mkdir(parents=True, exist_ok=True)
    lock = live_dir / LOCK_NAME
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        try:
            held = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            held = {}
        raise LockHeld(
            f"a match is in progress: {lock} is held by match "
            f"{held.get('match_id', '?')} (pid {held.get('pid', '?')}, started "
            f"{held.get('started_at', '?')}). If no match is running (check: "
            f"ps -p {held.get('pid', '<pid>')}), the lock is stale from a crash: "
            f"move that match's artifacts out of live/ if any, then remove the lock "
            f"by hand: rm '{lock}'") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"match_id": match_id, "pid": os.getpid(), "started_at": utc_now()}, fh)
    return lock


def release_lock(live_dir: Path) -> None:
    (live_dir / LOCK_NAME).unlink(missing_ok=True)


# ---------------------------------------------------------------- target

def solved_now(timeout: float = 10.0) -> list[str]:
    """Sorted names of currently-solved challenges, read via the admin port."""
    req = urllib.request.Request(ADMIN_URL)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)["data"]
    return sorted(c["name"] for c in data if c["solved"])


def reset_target(poll_timeout: float = 120.0) -> int:
    """Restart juice-shop, wait until healthy and the admin port answers, and
    return the solved count after reset (the caller refuses to run unless 0)."""
    _compose("restart", "juice-shop")
    _compose("up", "-d", "--wait")  # blocks until healthy
    deadline = time.monotonic() + poll_timeout
    while True:
        try:
            return len(solved_now())
        except Exception:  # noqa: BLE001 - admin port not up yet
            if time.monotonic() > deadline:
                raise
            time.sleep(1.0)


# ---------------------------------------------------------------- proxy log

def nginx_reopen() -> None:
    _compose("exec", "-T", "nginx", "nginx", "-s", "reopen")


def _wait_for_fresh_log(log: Path, poll_timeout: float, sleep_fn=time.sleep,
                        clock=time.monotonic) -> None:
    deadline = clock() + poll_timeout
    while not log.exists():
        if clock() >= deadline:
            raise RuntimeError(
                f"nginx did not create a fresh {log} within {poll_timeout}s after "
                f"reopen. nginx may still be writing to the moved file.")
        sleep_fn(0.2)


def reopen_and_confirm(live_dir: Path, reopen=nginx_reopen, poll_timeout: float = 15.0,
                       sleep_fn=time.sleep, clock=time.monotonic) -> None:
    """Make nginx reopen its log and confirm a fresh live/proxy.jsonl exists. Only
    then is a previously moved log final (nginx appends to a moved file until it
    reopens). Raises if the fresh file does not appear."""
    reopen()
    _wait_for_fresh_log(live_dir / "proxy.jsonl", poll_timeout, sleep_fn, clock)


def _archive_name() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%f")[:-3] + "Z"
    return f"proxy-{ts}.jsonl"


def rotate_proxy_log(live_dir: Path = LIVE, reopen=nginx_reopen,
                     poll_timeout: float = 15.0, sleep_fn=time.sleep,
                     clock=time.monotonic) -> Path | None:
    """Start the match with a clean live proxy log, WITHOUT destroying evidence: a
    non-empty existing log is moved to live/archive/ before nginx reopens a fresh
    proxy.jsonl. An EMPTY log is deleted -- the one deliberate exception to "never
    delete raw evidence" (it holds no evidence; contract §3). Returns the archive
    path, or None if there was nothing to keep. Raises if nginx does not create the
    fresh file."""
    log = live_dir / "proxy.jsonl"
    archived: Path | None = None
    if log.exists() and log.stat().st_size > 0:
        archive_dir = live_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        archived = archive_dir / _archive_name()
        log.replace(archived)  # rename: nginx appends here until it reopens
    elif log.exists():
        log.unlink()  # empty file: no evidence to preserve
    reopen_and_confirm(live_dir, reopen, poll_timeout, sleep_fn, clock)
    return archived


def freeze_proxy_log(live_dir: Path, match_dir: Path, reopen=nginx_reopen,
                     poll_timeout: float = 15.0, sleep_fn=time.sleep,
                     clock=time.monotonic) -> Path:
    """Move live/proxy.jsonl into the match dir, then make nginx reopen so later
    traffic goes to a fresh live/proxy.jsonl and can never append to the frozen
    file. The frozen file is final only once that fresh file exists; otherwise this
    raises. Safe to call again after a failed reopen (the move is not repeated)."""
    src = live_dir / "proxy.jsonl"
    dst = match_dir / "proxy.jsonl"
    if src.exists():
        if dst.exists():
            raise FileExistsError(f"refusing to overwrite frozen log {dst}")
        src.replace(dst)
    elif not dst.exists():
        raise FileNotFoundError(f"no live proxy log at {src} to freeze")
    reopen_and_confirm(live_dir, reopen, poll_timeout, sleep_fn, clock)
    return dst


# ---------------------------------------------------------------- attacks

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


def run_attacks(match_id: str, match_dir: Path, payloads: Path = scripted_red.PAYLOADS,
                settle: float = 3.0, log=print) -> list[dict]:
    """Fire the scripted attack set with before/after snapshots. Writes
    red_attacks.jsonl and challenge_snapshots.jsonl straight into match_dir."""
    match_dir.mkdir(parents=True, exist_ok=True)
    (match_dir / "red_attacks.jsonl").write_text("", encoding="utf-8")
    snap_path = match_dir / "challenge_snapshots.jsonl"
    snap_path.write_text("", encoding="utf-8")

    attacks = scripted_red.load_attacks(payloads)
    results = []
    with snap_path.open("a", encoding="utf-8") as snap_fh:
        for i, attack in enumerate(attacks, start=1):
            before = solved_now()
            res = scripted_red.send_one(attack, match_id, i, match_dir)
            after = snapshot_after(before, settle)
            snap_fh.write(json.dumps({
                "request_id": res["request_id"],
                "before_solved": before,
                "after_solved": after,
                "taken_at": utc_now(),
            }) + "\n")
            snap_fh.flush()
            newly = sorted(set(after) - set(before))
            where = res["status"] if res["error"] is None else res["error"]
            log(f"round {i} {res['label']:7} -> {where}; newly_solved={newly}")
            results.append(res)
    return results
