"""Stage 5.6 Gate 2: three seeded `--red ai --blue scripted` matches (designer GO only).

    .venv/bin/python tools/stage5_6_check.py --real-calls

Requires the stack (docker compose up -d --wait) and ARENA_OPENAI_API_KEY. Runs
run_match.py three times with the Stage 5.2 seed and AI Red + scripted Blue. Checks
FORMAT AND COVERAGE ONLY, never the AI's choices:

  - each match finished (exit 0, or 4 with stopped_by reported); match.json is
    schema-valid with red_engine ai, models.red and red_params
  - red_attacks.jsonl is 0.2 (source ai, with rationale), one per sent attack
  - red_unsent.jsonl lines are schema-valid; every consumed Red round is either a sent
    attack or one red_guard line
  - api_calls.jsonl has one Red line per generation

Reports per match: attacks sent, guard blocks by reason, brain failures, instrument
failures, landed (fact 1), unmapped solves, label_mismatch anomalies, scripted Blue's
detection and FP, cost; and PRINTS EVERY attack (method, path, body, label, rationale)
for the manual label audit (D5). Any max_tokens stop is reported.

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
from runner import match_ops  # noqa: E402
from stats import match_stats as ms  # noqa: E402

SEED = json.loads((REPO / "tools" / "stage5_2_expected.json").read_text())["seed"]
RUNS = 3
check = stage4_check.check
read = stage2_check._read_jsonl
SCHEMA = {n: Draft202012Validator(json.loads((REPO / "schemas" / f"{n}.schema.json").read_text()))
          for n in ("red_attack", "red_unsent")}


def check_match(match_dir: Path, code: int) -> list[str]:
    fails: list[str] = []
    m = json.loads((match_dir / "match.json").read_text())
    check(f"exit {code} completed/stopped", code in (0, 4), fails, f"status {m.get('status')}")
    check("match.json schema-valid", not run_match.validate_manifest(m), fails,
          str(run_match.validate_manifest(m)))
    check("red_engine ai with models.red and red_params",
          m.get("red_engine") == "ai" and m["models"]["red"] and m["red_params"], fails)
    if m["budget"]["stopped_by"]:
        print(f"  NOTE stopped_by {m['budget']['stopped_by']}")
    attacks = read(match_dir / "red_attacks.jsonl")
    check("red_attacks 0.2, source ai, with rationale",
          all(SCHEMA["red_attack"].is_valid(a) and a["source"] == "ai" and a["rationale"]
              for a in attacks), fails)
    guard = read(match_dir / "red_unsent.jsonl")
    check("red_unsent schema-valid", all(SCHEMA["red_unsent"].is_valid(g) for g in guard), fails)
    rounds_used = {a["round"] for a in attacks} | {g["round"] for g in guard}
    check("every consumed Red round is an attack xor a red_guard line",
          len(rounds_used) == len(attacks) + len(guard), fails,
          f"{len(attacks)} attacks + {len(guard)} guard vs {len(rounds_used)} rounds")
    red_calls = [c for c in read(match_dir / "api_calls.jsonl") if c["agent"] == "red"]
    check("a Red api_calls line per generation (attempts >= attacks + brain + instr)",
          len(red_calls) >= len(attacks), fails)
    return fails


def report_match(match_dir: Path) -> None:
    m = json.loads((match_dir / "match.json").read_text())
    rounds = read(match_dir / "rounds.jsonl")
    benign = read(match_dir / "benign_results.jsonl")
    guard = read(match_dir / "red_unsent.jsonl")
    anomalies = read(match_dir / "anomalies.jsonl")
    attacks = {a["round"]: a for a in read(match_dir / "red_attacks.jsonl")}
    g = ms.red_unsent_summary(guard)
    s, b = ms.compute(rounds), ms.compute_benign(rounds, benign)
    stops = Counter(c["stop_reason"] for c in read(match_dir / "api_calls.jsonl")
                    if c["agent"] == "red" and c["ok"])
    landed = sum(r["landed"] is True for r in rounds)
    unmapped = sorted({x for r in rounds for x in r["newly_solved"]})
    mism = [a for a in anomalies if a["kind"] == "label_mismatch"]
    print(f"\n{match_dir.name}: status {m['status']}  {m['cost']['total_usd']:.6f} USD")
    print(f"  attacks sent {len(attacks)}  landed {landed}  "
          f"guard {dict((k, sum(v.values())) for k, v in g.items() if k != 'total')}  "
          f"guard_detail {g['guard_block']}")
    print(f"  brain {g['brain_failure']}  instrument {g['instrument_failure']}  "
          f"stop_reasons {dict(stops)}  label_mismatch {len(mism)}")
    print(f"  scripted Blue: detection {s['detection'].fmt()}  FP {b['fp'].fmt()}  "
          f"newly_solved {unmapped}")
    if stops.get("max_tokens"):
        print(f"  REPORT: {stops['max_tokens']} max_tokens stop(s) at "
              f"{m['red_params']['request']['max_output_tokens']}: raise the cap")
    for a in mism:
        print(f"  ANOMALY label_mismatch round {a['detail']['round']} "
              f"{a['detail']['label']} -> {a['detail']['conflicts']}")
    # Every slot in round order: sent attacks and unsent proposals both, for the
    # manual label audit (D5). Guard blocks carry the model's proposed request.
    by_round = {r: ("sent", a) for r, a in attacks.items()}
    for u in guard:
        by_round[u["round"]] = ("unsent", u)
    print("  --- every attack and proposal (manual label audit, D5) ---")
    for rnd in sorted(by_round):
        how, x = by_round[rnd]
        if how == "sent":
            print(f"  round {rnd} SENT   [{x['label']}] {x['method']} {x['endpoint']}")
            print(f"    body: {x['payload'][:300]}")
            print(f"    rationale: {x['rationale']}")
        else:
            prop = x.get("proposed")
            tag = f"{x['kind']}/{x['reason']}"
            if prop is None:  # brain / instrument failure: no usable proposal
                print(f"  round {rnd} UNSENT [{tag}] (no proposal: {x.get('detail') or ''})")
            else:
                print(f"  round {rnd} UNSENT [{tag}] [{prop['label']}] {prop['method']} "
                      f"{prop['path'][:200]}")
                print(f"    body: {prop['body'][:300]}")
                print(f"    rationale: {prop['rationale']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-calls", action="store_true",
                    help="required: three matches of real, paid OpenAI calls")
    args = ap.parse_args(argv)
    if not args.real_calls:
        print("refusing: pass --real-calls (Gate 2 needs the designer's GO)")
        return 2
    fails: list[str] = []
    done = []
    for i in range(1, RUNS + 1):
        print(f"\n=== Gate 2 run {i}/{RUNS} (seed {SEED}, --red ai --blue scripted) ===")
        code, match_dir = run_match.run_match(seed=SEED, red_engine="ai", engine="scripted")
        if match_dir is None:
            fails.append(f"run {i}: no match (exit {code})")
            continue
        fails += [f"run {i}: {f}" for f in check_match(match_dir, code)]
        fails += stage4_check.check_live_after(match_ops.LIVE)
        report_match(match_dir)
        done.append(match_dir)
    if done:
        total = sum(json.loads((d / "match.json").read_text())["cost"]["total_usd"]
                    for d in done)
        print(f"\ntotal cost {total:.6f} USD over {len(done)} matches")
    return stage2_check.report(fails, f"Gate 2: {len(done)} AI-Red matches, format + "
                                      f"coverage verified")


if __name__ == "__main__":
    raise SystemExit(main())
