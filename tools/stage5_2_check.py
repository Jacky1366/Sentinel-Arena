"""Stage 5.2 end-to-end check: benign traffic + Judge fact 4a, reproducible by seed.

Requires the stack up (docker compose up -d --wait). Runs run_match.py TWICE with
the same fixed seed, then checks:

  match A (everything stage4_check checks, plus):
    - every benign request appears exactly once in the frozen proxy.jsonl
    - every benign request has exactly one benign_results line, and the results
      match tools/stage5_2_expected.json (hand-predicted; never edited to pass)
    - anomalies.jsonl is empty (no benign_solved_challenge, nothing unmatched)
    - the executed order (snapshot rows) equals match.json's planned schedule
  A vs B (same seed):
    - same schedule, same per-slot round records and benign results, same
      per-slot newly_solved (compared by round / benign_id: request ids are random)
  HTTP level:
    - Red and benign header profiles are identical (a local capture server
      receives one Red and one benign request per method through the real senders)

Exits non-zero on any problem. On a mismatch with the expectations: STOP and
report to the designer; do not edit the expectations.
"""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import run_match  # noqa: E402
import stage2_check  # noqa: E402
import stage3_check  # noqa: E402
import stage4_check  # noqa: E402
from benign import send_benign  # noqa: E402
from red import scripted_red  # noqa: E402
from runner import arena_client, match_ops  # noqa: E402

EXPECTED = json.loads((REPO / "tools" / "stage5_2_expected.json").read_text(encoding="utf-8"))
SEED = EXPECTED["seed"]
ROUND_FIELDS = ("label", "verdict", "landed", "landed_reason", "newly_solved", "detected",
                "type_correct", "detected_reason")
BENIGN_FIELDS = ("category", "verdict", "false_positive", "fp_reason")
check = stage4_check.check
read = stage2_check._read_jsonl


def slot_labels(match_dir: Path) -> dict[str, str]:
    """request_id -> 'red:<round>' / 'benign:<benign_id>'."""
    out = {r["request_id"]: f"red:{r['round']}" for r in read(match_dir / "red_attacks.jsonl")}
    out.update({b["request_id"]: f"benign:{b['benign_id']}"
                for b in read(match_dir / "benign_requests.jsonl")})
    return out


def check_benign(match_dir: Path) -> list[str]:
    fails: list[str] = []
    manifest = json.loads((match_dir / "match.json").read_text(encoding="utf-8"))
    traffic = manifest.get("traffic") or {}
    print()
    check("traffic.seed is the fixed seed", traffic.get("seed") == SEED
          and traffic.get("seed_source") == "cli", fails, str(traffic.get("seed")))
    check("traffic.benign_set sha256 matches benign/benign_set.json",
          traffic.get("benign_set", {}).get("sha256") == send_benign.set_sha256(), fails)

    benign = read(match_dir / "benign_requests.jsonl")
    entries = send_benign.load_set()["entries"]
    check("one benign record per benign set entry, in set order",
          [b["benign_id"] for b in benign] == [e["benign_id"] for e in entries], fails,
          str([b["benign_id"] for b in benign]))

    proxy_counts: dict[str, int] = {}
    for line in read(match_dir / "proxy.jsonl"):
        proxy_counts[line.get("request_id", "")] = proxy_counts.get(line.get("request_id", ""), 0) + 1
    bad = [b["benign_id"] for b in benign if proxy_counts.get(b["request_id"]) != 1]
    check("every benign request_id appears exactly once in proxy.jsonl", not bad, fails, str(bad))

    results = read(match_dir / "benign_results.jsonl")
    per_rid: dict[str, int] = {}
    for r in results:
        per_rid[r["request_id"]] = per_rid.get(r["request_id"], 0) + 1
    check("every benign request has exactly one benign_results line",
          sorted(per_rid) == sorted(b["request_id"] for b in benign)
          and set(per_rid.values()) <= {1}, fails)

    print(f"\n{'benign':6} {'category':13} {'verdict':7} {'fp':5} {'reason':10} result")
    by_id = {r["benign_id"]: r for r in results}
    for bid, exp in EXPECTED["benign"].items():
        got = by_id.get(bid)
        if got is None:
            fails.append(f"benign {bid}: no result")
            continue
        diffs = {k: (got[k], exp[k]) for k in ("verdict", "false_positive", "fp_reason")
                 if got[k] != exp[k]}
        if diffs:
            fails.append(f"benign {bid}: " + ", ".join(
                f"{k} got {g!r} expected {e!r}" for k, (g, e) in diffs.items()))
        print(f"{bid:6} {got['category']:13} {str(got['verdict']):7} "
              f"{str(got['false_positive']):5} {str(got['fp_reason']):10} "
              f"{'PASS' if not diffs else 'FAIL'}")

    anomalies = read(match_dir / "anomalies.jsonl")
    print()
    check("no anomalies (no benign_solved_challenge, nothing unmatched)",
          anomalies == EXPECTED["anomalies"], fails, json.dumps(anomalies))

    labels = slot_labels(match_dir)
    executed = [labels.get(s["request_id"], "?") for s in read(match_dir / "challenge_snapshots.jsonl")]
    check("executed order (snapshot rows) equals the planned schedule",
          executed == traffic.get("schedule"), fails, f"{executed} vs {traffic.get('schedule')}")
    kinds = {labels.get(s["request_id"], "?").split(":")[0] == s.get("traffic")
             for s in read(match_dir / "challenge_snapshots.jsonl")}
    check("every snapshot row is marked with its own traffic kind", kinds == {True}, fails)
    return fails


def per_slot(match_dir: Path) -> dict:
    """Everything that must be identical between two runs of one seed."""
    labels = slot_labels(match_dir)
    rounds = {f"red:{r['round']}": {k: r[k] for k in ROUND_FIELDS}
              for r in read(match_dir / "rounds.jsonl")}
    benign = {f"benign:{b['benign_id']}": {k: b[k] for k in BENIGN_FIELDS}
              for b in read(match_dir / "benign_results.jsonl")}
    solved = {labels[s["request_id"]]: sorted(set(s["after_solved"]) - set(s["before_solved"]))
              for s in read(match_dir / "challenge_snapshots.jsonl")}
    manifest = json.loads((match_dir / "match.json").read_text(encoding="utf-8"))
    return {"schedule": manifest["traffic"]["schedule"], "rounds": rounds, "benign": benign,
            "newly_solved": solved}


def check_reproducible(a: Path, b: Path) -> list[str]:
    fails: list[str] = []
    pa, pb = per_slot(a), per_slot(b)
    print()
    for key in ("schedule", "rounds", "benign", "newly_solved"):
        x, y = pa[key], pb[key]
        if isinstance(x, dict):
            diff = sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k))
        else:
            diff = [i for i in range(max(len(x), len(y)))
                    if (x[i] if i < len(x) else None) != (y[i] if i < len(y) else None)]
        check(f"same seed -> same {key} ({a.name} vs {b.name})", not diff, fails,
              f"differs at {diff}")
    return fails


# ---- header profiles (no Target: a local capture server) -------------------------

def _capture_server(requests: list[bytes]):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    data += conn.recv(65536)
                head, _, rest = data.partition(b"\r\n\r\n")
                length = next((int(l.split(b":")[1]) for l in head.split(b"\r\n")
                               if l.lower().startswith(b"content-length:")), 0)
                while len(rest) < length:
                    rest += conn.recv(65536)
                requests.append(head)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    threading.Thread(target=serve, daemon=True).start()
    return sock


def _profile(head: bytes) -> list[tuple[str, str]]:
    out = []
    for line in head.decode().split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.lower() in ("x-arena-request-id", "content-length", "host"):
            v = "<varies>"
        out.append((k, v.strip()))
    return out


def check_header_profiles() -> list[str]:
    fails: list[str] = []
    attacks = scripted_red.load_attacks()
    entries = send_benign.load_set()["entries"]
    requests: list[bytes] = []
    sock = _capture_server(requests)
    real_port = arena_client.ARENA_PORT
    arena_client.ARENA_PORT = sock.getsockname()[1]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for method in ("GET", "POST"):
                requests.clear()
                red = next(a for a in attacks if a["method"] == method)
                ben = next(e for e in entries if e["method"] == method)
                scripted_red.send_one(red, "m001", 1, Path(tmp))
                send_benign.send_one(ben, "m001", Path(tmp))
                ok = len(requests) == 2 and _profile(requests[0]) == _profile(requests[1])
                check(f"Red and benign {method} header profiles identical", ok, fails,
                      f"{[_profile(r) for r in requests]}")
    finally:
        arena_client.ARENA_PORT = real_port
        sock.close()
    return fails


def run_seeded() -> tuple[Path | None, list[str]]:
    code, match_dir = run_match.run_match(seed=SEED)
    return match_dir, ([] if code == 0 else [f"run_match exited {code}"])


def main() -> int:
    live_dir = match_ops.LIVE
    fails: list[str] = []
    a, f = run_seeded()
    fails += f
    if a is None:
        return stage2_check.report(fails, "")
    print(f"\nchecking {a}")
    fails += stage3_check.check_rounds(a)
    fails += stage2_check.check_landed(a, scripted_red.load_attacks())
    fails += stage2_check.check_proxy(a)
    fails += stage4_check.check_manifest(a)
    fails += check_benign(a)
    fails += stage4_check.check_live_after(live_dir)

    b, f = run_seeded()
    fails += f
    if b is not None:
        fails += check_reproducible(a, b)
        fails += stage4_check.check_live_after(live_dir)
        fails += stage4_check.check_post_freeze_probe(b, live_dir)
    print()
    fails += check_header_profiles()
    return stage2_check.report(
        fails, f"matches {a.name} + {b.name if b else '?'} (seed {SEED}) verified")


if __name__ == "__main__":
    raise SystemExit(main())
