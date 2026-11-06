"""Stage 3 end-to-end check.

Requires the stack up (docker compose up -d --wait). Runs the full pipeline:

    Stage 2 runner  ->  Judge fact 1 (landed)  ->  Blue v0  ->  Judge round record

then validates rounds.jsonl against the schema and compares each round's fields to
tools/stage3_expected.json (expectations derived by reasoning, in their own file).

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
from blue import run_blue  # noqa: E402
from judge import fact1_landed, round_record  # noqa: E402
from runner import stage2_run  # noqa: E402

RUN_DIR = REPO / "data" / "runs" / "live"
MATCH_ID = "m001"
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


def main() -> int:
    challenge_map = json.loads((REPO / "config" / "challenge_map.json").read_text())

    # Full pipeline.
    stage2_run.run(MATCH_ID, RUN_DIR, settle=3.0)
    facts, _ = fact1_landed.judge_run(RUN_DIR, challenge_map)
    (RUN_DIR / "landed.jsonl").write_text(
        "".join(json.dumps(f) + "\n" for f in facts), encoding="utf-8")
    run_blue.main(["--engine", "scripted", "--match-id", MATCH_ID])
    rounds = round_record.build_round_records(RUN_DIR)
    (RUN_DIR / "rounds.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rounds), encoding="utf-8")

    validator = Draft202012Validator(SCHEMA)
    fails: list[str] = []

    # Schema validity + one record per Red round.
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
        ok = not diffs
        if not ok:
            fails.append(f"round {rnd}: " + ", ".join(
                f"{k} got {g!r} expected {e!r}" for k, (g, e) in diffs.items()))
        print(f"{rnd:>3} {got['label']:7} {str(got['verdict']):7} "
              f"{str(got['detected']):5} {str(got['type_correct']):5} "
              f"{str(got['landed']):6} {str(got['landed_reason']):15} "
              f"{'PASS' if ok else 'FAIL'}")

    # request_id appears exactly once across the round records.
    seen: dict[str, int] = {}
    for r in rounds:
        seen[r["request_id"]] = seen.get(r["request_id"], 0) + 1
    dupes = {rid: n for rid, n in seen.items() if n != 1}
    if dupes:
        fails.append(f"request_id not 1:1 in rounds.jsonl: {dupes}")

    # Tripwire: a scripted run must never drop a snapshot. snapshot_missing means
    # the measurement harness misbehaved -> fail loudly (contract §6.1).
    fails.extend(tripwire_failures(rounds))

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} problem(s)) -- STOP, do not edit expectations")
        for f in fails:
            print(f"  - {f}")
        return 1
    print(f"RESULT: PASS ({len(rounds)} round records match expected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
