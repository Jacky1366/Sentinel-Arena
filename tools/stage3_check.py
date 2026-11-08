"""Stage 3 end-to-end check: full pipeline vs reasoned expectations.

Requires the stack up (docker compose up -d --wait). Runs one match through
run_match.py (runner -> Judge fact 1 -> Blue -> round record, on the frozen match
directory), then validates rounds.jsonl against the schema and compares each
round's fields to tools/stage3_expected.json (expectations derived by reasoning,
in their own file).

If a live result differs from the expectation, this STOPS and reports the diff. It
never edits the expectations to make the check pass. Exits non-zero on any problem.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import stage2_check  # noqa: E402

EXPECTED = json.loads((REPO / "tools" / "stage3_expected.json").read_text())["rounds"]
SCHEMA = json.loads((REPO / "schemas" / "round_record.schema.json").read_text())
COMPARE = ["label", "verdict", "detected", "type_correct", "detected_reason",
           "landed", "landed_reason"]


def tripwire_failures(rounds: list[dict]) -> list[str]:
    """Harness self-checks: conditions that mean the measurement misbehaved, not
    that a side won/lost. A scripted run should never trip these (contract §6.1)."""
    fails = []
    offenders = [r["round"] for r in rounds if r.get("landed_reason") == "snapshot_missing"]
    if offenders:
        fails.append(
            f"snapshot_missing in round(s) {offenders}: a snapshot was dropped at "
            f"runtime. A scripted run must never produce this (contract §6.1 tripwire).")
    return fails


def check_rounds(match_dir: Path) -> list[str]:
    """Schema validity, per-round fields vs expectations, request_id 1:1, tripwire."""
    rounds = stage2_check._read_jsonl(match_dir / "rounds.jsonl")
    validator = Draft202012Validator(SCHEMA)
    fails: list[str] = []

    by_round = {}
    for r in rounds:
        for e in validator.iter_errors(r):
            fails.append(f"round {r['round']}: schema-invalid: {e.message}")
        by_round[str(r["round"])] = r

    print(f"\n{'rnd':>3} {'label':7} {'verdict':7} {'det':5} {'typ':5} "
          f"{'landed':6} {'reason':15} result")
    for rnd in sorted(EXPECTED, key=int):
        exp = EXPECTED[rnd]
        got = by_round.get(rnd)
        if got is None:
            fails.append(f"round {rnd}: no round record produced")
            print(f"{rnd:>3} (missing)")
            continue
        diffs = {k: (got.get(k), exp[k]) for k in COMPARE if got.get(k) != exp[k]}
        if diffs:
            fails.append(f"round {rnd}: " + ", ".join(
                f"{k} got {g!r} expected {e!r}" for k, (g, e) in diffs.items()))
        print(f"{rnd:>3} {got['label']:7} {str(got['verdict']):7} "
              f"{str(got['detected']):5} {str(got['type_correct']):5} "
              f"{str(got['landed']):6} {str(got['landed_reason']):15} "
              f"{'PASS' if not diffs else 'FAIL'}")
    extra = sorted(set(by_round) - set(EXPECTED), key=int)
    if extra:
        fails.append(f"unexpected extra round(s): {extra}")

    seen: dict[str, int] = {}
    for r in rounds:
        seen[r["request_id"]] = seen.get(r["request_id"], 0) + 1
    dupes = {rid: n for rid, n in seen.items() if n != 1}
    if dupes:
        fails.append(f"request_id not 1:1 in rounds.jsonl: {dupes}")

    # Tripwire: a scripted run must never drop a snapshot (contract §6.1).
    fails.extend(tripwire_failures(rounds))
    return fails


def main() -> int:
    match_dir, fails = stage2_check.run_and_require_match()
    if match_dir is not None:
        print(f"\nchecking {match_dir}")
        fails += check_rounds(match_dir)
    return stage2_check.report(fails, f"{len(EXPECTED)} round records match expected")


if __name__ == "__main__":
    raise SystemExit(main())
