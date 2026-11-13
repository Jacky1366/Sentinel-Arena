"""Stage 4 end-to-end check: one-command match + frozen, self-describing match dir.

Requires the stack up (docker compose up -d --wait). Runs run_match.py once, then
checks the resulting data/runs/<match_id>/:

  - every round matches tools/stage3_expected.json (never edited to pass), rounds
    are schema-valid and 1:1 by request_id, and NO snapshot_missing (tripwire)
  - every landed fact matches payloads.json expectations
  - match.json is schema-valid, status "completed", and every artifact's sha256 and
    size recompute to what match.json recorded (and match.json lists every file)
  - match.json is schema_version 0.5 (0.4 before Stage 5.6) and shows the scripted
    match's AI side: blue/red engine scripted, blue_params/red_params null, models all null, $0
    cost, 0 API calls, no api_calls.jsonl, budget not hit,
    and the price table it recorded is the current config/prices.json
  - every request_id appears exactly once in the frozen proxy.jsonl, and it has
    no /api/Challenges line
  - post-freeze probe: one arena request (same HTTP client as Red) lands in
    live/proxy.jsonl, and the frozen proxy.jsonl's sha256 is unchanged
  - the lock is released and live/ holds no match artifacts

Exits non-zero on any problem.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import run_match  # noqa: E402
import stage2_check  # noqa: E402
import stage3_check  # noqa: E402
from red import scripted_red  # noqa: E402
from runner import match_ops  # noqa: E402
from stats import cost as cost_stats  # noqa: E402


def check(name: str, ok: bool, fails: list[str], detail: str = "") -> None:
    print(f"{name}: {'PASS' if ok else 'FAIL'}{'  ' + detail if detail and not ok else ''}")
    if not ok:
        fails.append(f"{name}{': ' + detail if detail else ''}")


def check_manifest(match_dir: Path) -> list[str]:
    fails: list[str] = []
    path = match_dir / "match.json"
    if not path.is_file():
        return ["match.json missing"]
    manifest = json.loads(path.read_text(encoding="utf-8"))
    errs = run_match.validate_manifest(manifest)
    print()
    check("match.json schema-valid", not errs, fails, str(errs))
    check("match.json status completed", manifest.get("status") == "completed", fails,
          f"status={manifest.get('status')} failed_step={manifest.get('failed_step')} "
          f"error={manifest.get('error')}")
    check("match.json match_id matches directory", manifest.get("match_id") == match_dir.name,
          fails, f"{manifest.get('match_id')} vs {match_dir.name}")
    recomputed = run_match.artifact_hashes(match_dir)
    recorded = manifest.get("artifacts", {})
    check("artifacts: match.json lists every file", set(recorded) == set(recomputed), fails,
          f"recorded {sorted(recorded)} vs on disk {sorted(recomputed)}")
    bad = [n for n in recorded if recomputed.get(n) != recorded[n]]
    check("artifacts: sha256 + bytes recompute", not bad, fails, f"mismatch: {bad}")
    # Stage 5.1: the scripted match makes no AI calls and says so (0.5 from Stage 5.6).
    check("match.json schema_version 0.5", manifest.get("schema_version") == "0.5", fails,
          str(manifest.get("schema_version")))
    check("scripted Blue/Red: blue_params and red_params null",
          manifest.get("blue_engine") == "scripted" and manifest.get("blue_params") is None
          and manifest.get("red_engine") == "scripted" and manifest.get("red_params") is None,
          fails, f"{manifest.get('red_engine')} {manifest.get('red_params')}")
    check("models all null (scripted)",
          manifest.get("models") == {"red": None, "blue": None, "analyst": None}, fails,
          str(manifest.get("models")))
    cost = manifest.get("cost") or {}
    check("cost zero, 0 API calls", cost.get("total_usd") == 0 and cost.get("attempts") == 0
          and cost.get("refused") == 0, fails, str(cost))
    check("budget not hit", (manifest.get("budget") or {}).get("stopped_by") is None, fails,
          str(manifest.get("budget")))
    check("no api_calls.jsonl", not (match_dir / "api_calls.jsonl").exists(), fails)
    ref = cost_stats.price_table_ref()
    check("price_table sha256 matches config/prices.json",
          manifest.get("price_table") == ref, fails, f"{manifest.get('price_table')} vs {ref}")
    return fails


def check_post_freeze_probe(match_dir: Path, live_dir: Path) -> list[str]:
    fails: list[str] = []
    frozen = match_dir / "proxy.jsonl"
    before = run_match.sha256_file(frozen)
    rid = str(uuid.uuid4())
    status = scripted_red.send_request("GET", "/", rid)
    live_log = live_dir / "proxy.jsonl"
    deadline = time.monotonic() + 5.0
    landed = False
    while time.monotonic() < deadline:
        if live_log.is_file() and rid in live_log.read_text(encoding="utf-8"):
            landed = True
            break
        time.sleep(0.2)
    print()
    check(f"post-freeze probe (status {status}) lands in live/proxy.jsonl", landed, fails)
    check("post-freeze probe not in frozen proxy.jsonl",
          rid not in frozen.read_text(encoding="utf-8"), fails)
    check("frozen proxy.jsonl sha256 unchanged after probe",
          run_match.sha256_file(frozen) == before, fails)
    return fails


def check_live_after(live_dir: Path) -> list[str]:
    fails: list[str] = []
    check("lock released", not (live_dir / match_ops.LOCK_NAME).exists(), fails)
    leftovers = match_ops.live_unexpected(live_dir)
    check("live/ holds no match artifacts", not leftovers, fails, str(leftovers))
    return fails


def main() -> int:
    live_dir = match_ops.LIVE
    match_dir, fails = stage2_check.run_and_require_match()
    if match_dir is None:
        return stage2_check.report(fails, "")
    print(f"\nchecking {match_dir}")
    fails += stage3_check.check_rounds(match_dir)
    fails += stage2_check.check_landed(match_dir, scripted_red.load_attacks())
    fails += stage2_check.check_proxy(match_dir)
    fails += check_manifest(match_dir)
    fails += check_live_after(live_dir)
    fails += check_post_freeze_probe(match_dir, live_dir)
    return stage2_check.report(fails, f"match {match_dir.name} frozen and verified")


if __name__ == "__main__":
    raise SystemExit(main())
