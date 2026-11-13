"""Stage 5.4 Gate 2: three seeded `--blue claude` matches (only after the designer's GO).

    .venv/bin/python tools/stage5_4_check.py --real-calls

Requires the stack up (docker compose up -d --wait) and ARENA_ANTHROPIC_API_KEY.
Runs run_match.py three times with the Stage 5.2 seed (same schedule, same
traffic) and AI Blue. Checks FORMAT AND COVERAGE ONLY, never the AI's answers:

  - each match finished (exit 0, or 4 with stopped_by reported) and match.json is
    schema-valid with blue_engine claude, models.blue and blue_params
  - verdicts.jsonl: exactly one schema-valid row per judged proxy line
  - api_calls.jsonl: one final line per judged line (log_seq 1..n), unless the
    body refused (then Blue stopped and every later row is instrument_failure)
  - rounds.jsonl / benign_results.jsonl are 0.2, one per Red / benign record

Reports (never fails on): detection, FP and the separate rates per match; the
no-verdict details incl. model_refusal split by attack / benign lines; any
max_tokens stop (at 256 that means our cap is wrong, not the model: REPORT IT);
cost per match and total; run-to-run differences per schedule slot.

Exits non-zero on any format / coverage problem.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import run_match  # noqa: E402
import stage2_check  # noqa: E402
import stage4_check  # noqa: E402
from blue import claude_engine as ce  # noqa: E402
from runner import match_ops  # noqa: E402
from stats import match_stats as ms  # noqa: E402

SEED = json.loads((REPO / "tools" / "stage5_2_expected.json").read_text())["seed"]
RUNS = 3
check = stage4_check.check
read = stage2_check._read_jsonl
SCHEMA = {n: Draft202012Validator(json.loads((REPO / "schemas" / f"{n}.schema.json").read_text()))
          for n in ("verdict", "round_record", "benign_result")}


def slot_of(match_dir: Path) -> dict[str, str]:
    """request_id -> schedule slot label (red:<round> / benign:<id>)."""
    out = {r["request_id"]: f"red:{r['round']}" for r in read(match_dir / "red_attacks.jsonl")}
    out.update({b["request_id"]: f"benign:{b['benign_id']}"
                for b in read(match_dir / "benign_requests.jsonl")})
    return out


def check_match(match_dir: Path, code: int) -> list[str]:
    fails: list[str] = []
    m = json.loads((match_dir / "match.json").read_text())
    check(f"exit {code} is completed (0) or stopped (4)", code in (0, 4), fails,
          f"status {m.get('status')} {m.get('failed_step')} {m.get('error')}")
    check("match.json schema-valid", not run_match.validate_manifest(m), fails,
          str(run_match.validate_manifest(m)))
    check("blue_engine claude with models.blue and blue_params",
          m.get("blue_engine") == "claude" and m["models"]["blue"] and m["blue_params"],
          fails)
    if m["budget"]["stopped_by"]:
        print(f"  NOTE stopped_by {m['budget']['stopped_by']}")
    lines = ce.read_judged_lines(match_dir / "proxy.jsonl")
    verdicts = read(match_dir / "verdicts.jsonl")
    bad = [v["log_seq"] for v in verdicts if not SCHEMA["verdict"].is_valid(v)]
    check("verdicts schema-valid", not bad, fails, f"log_seq {bad}")
    check("one verdict row per judged line, in order",
          [(v["log_seq"], v["request_id"]) for v in verdicts]
          == [(i, l["request_id"]) for i, l in enumerate(lines, start=1)], fails)
    calls = [c for c in read(match_dir / "api_calls.jsonl") if c["agent"] == "blue"]
    final = {}
    for c in calls:
        final[c["log_seq_first"]] = c
    refused = [c["log_seq_first"] for c in calls if c["refusal"]]
    expect = range(1, (min(refused) if refused else len(lines)) + 1)
    check("api_calls: a final Blue line per sent log_seq", sorted(final) == list(expect),
          fails, f"{sorted(final)} vs 1..{expect.stop - 1}")
    for name, schema, n in (("rounds.jsonl", "round_record", "red_attacks.jsonl"),
                            ("benign_results.jsonl", "benign_result", "benign_requests.jsonl")):
        rows = read(match_dir / name)
        check(f"{name}: 0.2, schema-valid, one per record",
              len(rows) == len(read(match_dir / n))
              and all(SCHEMA[schema].is_valid(r) for r in rows), fails)
    return fails


def report_match(match_dir: Path) -> dict:
    m = json.loads((match_dir / "match.json").read_text())
    rounds, benign = read(match_dir / "rounds.jsonl"), read(match_dir / "benign_results.jsonl")
    verdicts = read(match_dir / "verdicts.jsonl")
    s, b = ms.compute(rounds), ms.compute_benign(rounds, benign)
    details = Counter(v["failure_detail"] for v in verdicts if v["failure_detail"])
    stops = Counter(c["stop_reason"] for c in read(match_dir / "api_calls.jsonl")
                    if c["ok"])
    print(f"\n{match_dir.name}: status {m['status']}  {m['cost']['total_usd']:.6f} USD "
          f"({m['cost']['attempts']} attempts, {m['cost']['refused']} refused)")
    print(f"  detection {s['detection'].fmt()}  FP rate {b['fp'].fmt()}  "
          f"FP hard {b['fp_hard'].fmt()}  type acc {s['type_accuracy'].fmt()}")
    print(f"  no-verdict attack {s['no_verdict'].fmt()} benign {b['no_verdict'].fmt()}  "
          f"instr. failure attack {s['instrument_failure'].fmt()} "
          f"benign {b['instrument_failure'].fmt()}")
    print(f"  model refusals {ms.model_refusals(rounds, benign, verdicts)}  "
          f"failure details {dict(details)}  stop reasons {dict(stops)}")
    if stops.get("max_tokens"):
        print(f"  REPORT: {stops['max_tokens']} max_tokens stop(s) at "
              f"{m['blue_params']['request']['max_output_tokens']}: our cap is wrong")
    slots = slot_of(match_dir)
    return {"cost": m["cost"]["total_usd"],
            "by_slot": {slots[v["request_id"]]: v["verdict"] or v["failure_detail"]
                        for v in verdicts}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-calls", action="store_true",
                    help="required: three matches of real, paid Anthropic calls")
    args = ap.parse_args(argv)
    if not args.real_calls:
        print("refusing: pass --real-calls (Gate 2 needs the designer's GO)")
        return 2
    fails: list[str] = []
    reports = []
    for i in range(1, RUNS + 1):
        print(f"\n=== Gate 2 run {i}/{RUNS} (seed {SEED}, --blue claude) ===")
        code, match_dir = run_match.run_match(seed=SEED, engine="claude")
        if match_dir is None:
            fails.append(f"run {i}: no match (exit {code})")
            continue
        fails += [f"run {i}: {f}" for f in check_match(match_dir, code)]
        fails += stage4_check.check_live_after(match_ops.LIVE)
        reports.append((match_dir, report_match(match_dir)))

    if reports:
        print(f"\ntotal cost {sum(r['cost'] for _, r in reports):.6f} USD over "
              f"{len(reports)} matches")
        slots = sorted({s for _, r in reports for s in r["by_slot"]})
        diffs = {s: [r["by_slot"].get(s) for _, r in reports] for s in slots
                 if len({r["by_slot"].get(s) for _, r in reports}) > 1}
        print(f"run-to-run differences: {len(diffs)} of {len(slots)} slots")
        for s, vals in diffs.items():
            print(f"  {s:12} {vals}")
    return stage2_check.report(fails, f"Gate 2: {len(reports)} claude matches, format + "
                                      f"coverage verified")


if __name__ == "__main__":
    raise SystemExit(main())
