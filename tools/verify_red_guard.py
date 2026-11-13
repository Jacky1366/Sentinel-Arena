"""Verify the AI-Red above_root guard against the real nginx (Stage 5.6).

The guard (red/red_guard.py) must mirror nginx limitation #1: a path that resolves
above the web root is rejected by nginx before it is logged (empty request_id, stray
-> invisible to Blue and the Judge), so Red must never send it. This tool sends a
small set of probe paths -- literal and percent-encoded, inside and above the root --
through the arena port with a unique request id each, then reads the live proxy log
and checks, for every probe:

  - a path the guard ALLOWS is logged by nginx (its request id appears), and
  - a path nginx rejects before logging (request id absent) is BLOCKED by the guard
    with reason above_root.

A mismatch means the guard and nginx disagree about the root boundary: reported, and
the tool exits non-zero. The Target is reset afterwards. No tokens, no AI. Requires
the stack (docker compose up -d --wait); holds the match lock so it never overlaps a
match.

Every probe path passes the guard's scheme/encoding/method/size checks, so the only
variable under test is traversal depth.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from red import red_guard  # noqa: E402
from runner import arena_client, match_ops  # noqa: E402

# (path, expected: "logged" inside the root, or "rejected" above it). All are valid
# request targets (they pass scope/encoding), so above_root is the only question.
PROBES = [
    ("/ftp/legal.md", "logged"),
    ("/ftp/coupons_2013.md.bak", "logged"),
    ("/rest/products/search?q=1", "logged"),
    ("/ftp/..%2fftp%2flegal.md", "logged"),          # decodes inside the root
    ("/ftp/%2e%2e/ftp/legal.md", "logged"),          # encoded .. that stays in root
    ("/ftp/../../etc/passwd", "rejected"),           # literal, climbs out
    ("/ftp/..%2f..%2fetc/passwd", "rejected"),       # encoded, climbs out
    ("/%2e%2e/%2e%2e/etc/passwd", "rejected"),       # encoded .. from the root
    ("/../../../package.json", "rejected"),          # literal, climbs out
    ("/ftp/%2E%2E/%2E%2E/etc/passwd", "rejected"),   # uppercase encoded .., climbs out
    ("/ftp/%252e%252e/legal.md", "logged"),          # double-encoded: nginx decodes once -> literal
    ("/ftp/..%5c..%5cwindows/win.ini", "logged"),    # backslash is not a separator on nginx (Linux)
]


def _logged_ids(live_log: Path) -> set[str]:
    if not live_log.is_file():
        return set()
    out = set()
    for line in live_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rid = json.loads(line).get("request_id", "")
        if rid:
            out.add(rid)
    return out


def run(settle: float = 1.0) -> list[dict]:
    live_log = match_ops.LIVE / "proxy.jsonl"
    match_ops.rotate_proxy_log(match_ops.LIVE)  # a fresh log to read
    results = []
    for path, expected in PROBES:
        rid = arena_client.new_request_id()
        g = red_guard.check("GET", path, "", "CWE-22")
        status, error = None, None
        try:
            status = arena_client.send("GET", path, rid).status
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
        results.append({"path": path, "expected": expected, "request_id": rid,
                        "guard_ok": g.ok, "guard_reason": g.reason, "status": status,
                        "error": error})
    time.sleep(settle)  # let nginx flush
    logged = _logged_ids(live_log)
    for r in results:
        r["logged"] = r["request_id"] in logged
        if r["expected"] == "logged":
            r["match"] = r["guard_ok"] and r["logged"]
        else:  # nginx rejects before logging -> guard must block with above_root
            r["match"] = (not r["logged"]) and (not r["guard_ok"]) \
                and r["guard_reason"] == "above_root"
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--settle", type=float, default=1.0)
    args = ap.parse_args(argv)
    match_ops.running_images()  # raises if the stack is not up
    match_ops.acquire_lock(match_ops.LIVE, "red-guard-verification")
    try:
        results = run(args.settle)
    finally:
        match_ops.reset_target()  # leave the Target clean
        match_ops.release_lock(match_ops.LIVE)

    print(f"{'path':40} {'expected':9} {'guard':12} {'nginx':7} result")
    for r in results:
        guard = "allow" if r["guard_ok"] else f"block:{r['guard_reason']}"
        nginx = "logged" if r["logged"] else f"not({r['status']})"
        print(f"{r['path']:40} {r['expected']:9} {guard:12} {nginx:7} "
              f"{'PASS' if r['match'] else 'FAIL'}")
    bad = [r for r in results if not r["match"]]
    print(f"\n{len(results) - len(bad)}/{len(results)} probes agree; "
          f"{'all guard/nginx boundaries match' if not bad else 'MISMATCH — see FAIL rows'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
