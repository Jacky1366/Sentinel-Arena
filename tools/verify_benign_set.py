"""Verify the benign set empirically against a freshly reset Target (Stage 5.2).

For each entry (or each `requires` chain, e.g. n10 -> n11) the Target is reset
first, so one entry's solve can never hide another's. Each request goes through
the arena HTTP client (the same one Red uses) with its own request id, and is
bracketed by before/after challenge snapshots read via the admin port.

Reports per entry: HTTP status, newly_solved, expected_solves, and whether they
match exactly. Any 5xx is flagged for designer review. Writes the full record to
--out (default benign/verification.json) as evidence.

Requires the stack (docker compose up -d --wait). Holds the match lock while it
runs, so it never overlaps a match. Exit 0 iff every entry's newly_solved equals
its expected_solves and the status is not 5xx unless that entry expects solves.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from benign import send_benign  # noqa: E402
from red import scripted_red  # noqa: E402
from runner import arena_client, match_ops  # noqa: E402


QUIRK_SHORT_BODY = (
    "Juice Shop's /ftp/ directory listing sends a body 59 bytes shorter than its "
    "Content-Length (11343 declared, 11284 sent). Reproduced inside the Docker network "
    "without nginx (wget from the nginx container straight to juice-shop:3000) and "
    "with curl through the proxy (curl exit 18). The arena client tolerates exactly "
    "this case: status returned, body_incomplete=true (contract 9).")


def groups(entries: list[dict]) -> list[list[dict]]:
    """Each entry alone, except a `requires` chain, which is verified together."""
    out: list[list[dict]] = []
    where: dict[str, list[dict]] = {}
    for e in entries:
        g = where[e["requires"]] if e.get("requires") else None
        if g is None:
            g = []
            out.append(g)
        g.append(e)
        where[e["benign_id"]] = g
    return out


def verify(entries: list[dict], settle: float, log=print) -> list[dict]:
    results = []
    for group in groups(entries):
        solved = match_ops.reset_target()
        if solved != 0:
            raise RuntimeError(f"target not clean after reset ({solved} solved)")
        for e in group:
            before = match_ops.solved_now()
            body = json.dumps(e["json_body"]) if e.get("json_body") is not None else None
            status, error, incomplete = None, None, False
            try:
                resp = arena_client.send(e["method"], scripted_red.request_target(e),
                                         arena_client.new_request_id(), body=body)
                status, incomplete = resp.status, resp.body_incomplete
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
            after = match_ops.snapshot_after(before, settle)
            newly = sorted(set(after) - set(before))
            expected = sorted(e.get("expected_solves", []))
            r = {"benign_id": e["benign_id"], "category": e["category"],
                 "method": e["method"], "target": scripted_red.request_target(e),
                 "status": status, "body_incomplete": incomplete, "error": error, "newly_solved": newly,
                 "expected_solves": expected, "solves_match": newly == expected,
                 "server_error": status is not None and status >= 500,
                 "fresh_reset": e is group[0]}
            results.append(r)
            flag = "" if r["solves_match"] else "  <-- SOLVES DIFFER FROM expected_solves"
            if incomplete:
                flag += "  (body shorter than Content-Length: known Target quirk)"
            if r["server_error"]:
                flag += "  <-- 5xx (designer review)"
            log(f"{e['benign_id']}  {e['method']:4} {r['target'][:60]:60}  "
                f"status={status if error is None else error}  newly_solved={newly}  "
                f"expected={expected}{flag}")
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--set", type=Path, default=send_benign.BENIGN_SET)
    ap.add_argument("--settle", type=float, default=3.0)
    ap.add_argument("--out", type=Path, default=REPO / "benign" / "verification.json")
    ap.add_argument("--only", nargs="*", default=None,
                    help="verify only these benign_ids (a requires-chain is kept whole)")
    args = ap.parse_args(argv)

    data = send_benign.load_set(args.set)
    entries = data["entries"]
    if args.only:
        keep = set(args.only)
        for e in entries:  # pull in what a selected entry requires
            if e["benign_id"] in keep and e.get("requires"):
                keep.add(e["requires"])
        entries = [e for e in entries if e["benign_id"] in keep]
    images = match_ops.running_images()
    match_ops.acquire_lock(match_ops.LIVE, "benign-verification")
    try:
        started = match_ops.utc_now()
        results = verify(entries, args.settle)
    finally:
        match_ops.release_lock(match_ops.LIVE)
    record = {"verified_at": started, "only": args.only, "set_path": "benign/benign_set.json",
              "set_version": data["set_version"], "set_sha256": send_benign.set_sha256(args.set),
              "images": images, "settle_s": args.settle,
              "method": "Target reset before each entry (a requires-chain shares one reset); "
                        "before/after snapshots via the admin port; arena HTTP client.",
              "results": results,
              "known_target_quirks": [
                  {"benign_id": r["benign_id"], "quirk": QUIRK_SHORT_BODY}
                  for r in results if r["body_incomplete"]]}
    args.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    bad = [r["benign_id"] for r in results if not r["solves_match"]]
    errs = [r["benign_id"] for r in results if r["server_error"]]
    print(f"\n{len(results)} entries; solves differ: {bad or 'none'}; 5xx: {errs or 'none'}"
          f"\nrecord -> {args.out}")
    unexpected_5xx = [r for r in results if r["server_error"] and not r["expected_solves"]]
    return 0 if not bad and not unexpected_5xx else 1


if __name__ == "__main__":
    raise SystemExit(main())
