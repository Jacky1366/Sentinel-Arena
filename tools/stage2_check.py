"""Stage 2 end-to-end check: scripted Red + Judge fact 1.

Runs one match through run_match.py (the single code path), then asserts on the
frozen match directory:

  1. Each attack's (landed, landed_reason) matches payloads.json expected_*.
  2. Every attack's request_id appears EXACTLY once in proxy.jsonl (no orphans,
     no duplicates) -- i.e. the arena actually logged each attack.
  3. proxy.jsonl contains NO /api/Challenges lines (the Judge's measurement path
     never leaked onto Blue's input).
  4. Every landed fact validates against schemas/landed_fact.schema.json.

Prints a pass/fail table and exits non-zero on any mismatch. Requires the stack
up (docker compose up -d --wait).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from red import scripted_red  # noqa: E402

LANDED_SCHEMA = json.loads((REPO / "schemas" / "landed_fact.schema.json").read_text())


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def check_landed(match_dir: Path, attacks: list[dict]) -> list[str]:
    """Checks 1 + 4: per-attack landed vs payloads.json expectations, schema-valid."""
    facts_by_round = {f["round"]: f for f in _read_jsonl(match_dir / "landed.jsonl")}
    validator = Draft202012Validator(LANDED_SCHEMA)
    fails: list[str] = []
    print(f"\n{'rnd':>3} {'label':7} {'landed':>6} {'reason':15} "
          f"{'expected':>8} {'exp_reason':15} result")
    for i, atk in enumerate(attacks, start=1):
        fact = facts_by_round.get(i)
        if fact is None:
            print(f"{i:>3} {atk['label']:7} {'--':>6} {'(no fact)':15} "
                  f"{str(atk['expected_landed']):>8} {str(atk['expected_reason']):15} FAIL")
            fails.append(f"round {i}: no landed fact (snapshot missing?)")
            continue
        errs = [e.message for e in validator.iter_errors(fact)]
        if errs:
            fails.append(f"round {i}: landed fact invalid: {errs}")
        ok = (fact["landed"] == atk["expected_landed"]
              and fact["landed_reason"] == atk["expected_reason"] and not errs)
        if not ok and not errs:
            fails.append(f"round {i}: got ({fact['landed']}, {fact['landed_reason']}), "
                         f"expected ({atk['expected_landed']}, {atk['expected_reason']})")
        print(f"{i:>3} {atk['label']:7} {str(fact['landed']):>6} "
              f"{str(fact['landed_reason']):15} {str(atk['expected_landed']):>8} "
              f"{str(atk['expected_reason']):15} {'PASS' if ok else 'FAIL'}")
    return fails


def check_proxy(match_dir: Path) -> list[str]:
    """Checks 2 + 3 on the frozen proxy.jsonl."""
    proxy = _read_jsonl(match_dir / "proxy.jsonl")
    fails: list[str] = []
    counts: dict[str, int] = {}
    for line in proxy:
        rid = line.get("request_id", "")
        if rid:
            counts[rid] = counts.get(rid, 0) + 1
    print()
    for rec in _read_jsonl(match_dir / "red_attacks.jsonl"):
        n = counts.get(rec["request_id"], 0)
        if n != 1:
            fails.append(f"request_id {rec['request_id']} appears {n}x in proxy.jsonl (want 1)")
        print(f"proxy.jsonl round {rec['round']}: request_id x{n}  {'PASS' if n == 1 else 'FAIL'}")
    leaked = [p for p in proxy if p.get("path", "").startswith("/api/Challenges")]
    if leaked:
        fails.append(f"{len(leaked)} /api/Challenges line(s) leaked into proxy.jsonl")
    print(f"\nproxy.jsonl has no /api/Challenges lines: {'PASS' if not leaked else 'FAIL'}")
    return fails


def report(fails: list[str], ok_msg: str) -> int:
    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} problem(s)) -- STOP, do not edit expectations")
        for f in fails:
            print(f"  - {f}")
        return 1
    print(f"RESULT: PASS ({ok_msg})")
    return 0


def run_and_require_match() -> tuple[Path | None, list[str]]:
    """Run one match; a non-zero exit is itself a failure."""
    code, match_dir = run_match.run_match()
    fails = [] if code == 0 else [f"run_match exited {code}"]
    return match_dir, fails


def main() -> int:
    attacks = scripted_red.load_attacks()
    match_dir, fails = run_and_require_match()
    if match_dir is not None:
        print(f"\nchecking {match_dir}")
        fails += check_landed(match_dir, attacks)
        fails += check_proxy(match_dir)
    return report(fails, f"{len(attacks)} attacks, all landed facts match expected")


if __name__ == "__main__":
    raise SystemExit(main())
