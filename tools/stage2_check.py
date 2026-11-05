"""Stage 2 end-to-end check.

Runs the measurement runner and the Judge against the live stack, then asserts:

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
from judge import fact1_landed  # noqa: E402
from red import scripted_red  # noqa: E402
from runner import stage2_run  # noqa: E402

RUN_DIR = REPO / "data" / "runs" / "live"
MATCH_ID = "m001"
LANDED_SCHEMA = json.loads((REPO / "schemas" / "landed_fact.schema.json").read_text())


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def main() -> int:
    attacks = scripted_red.load_attacks()
    challenge_map = json.loads((REPO / "config" / "challenge_map.json").read_text())

    # --- run measurement + judge ---
    stage2_run.run(MATCH_ID, RUN_DIR, settle=3.0)
    facts, orphans = fact1_landed.judge_run(RUN_DIR, challenge_map)
    (RUN_DIR / "landed.jsonl").write_text(
        "".join(json.dumps(f) + "\n" for f in facts), encoding="utf-8")

    red_records = _read_jsonl(RUN_DIR / "red_attacks.jsonl")
    proxy = _read_jsonl(RUN_DIR / "proxy.jsonl")
    validator = Draft202012Validator(LANDED_SCHEMA)

    fails: list[str] = []

    # --- 1 + 4: per-attack landed vs expected, and schema validity ---
    facts_by_round = {f["round"]: f for f in facts}
    print(f"\n{'rnd':>3} {'label':7} {'landed':>6} {'reason':15} "
          f"{'expected':>8} {'exp_reason':15} result")
    for i, (atk, fact) in enumerate(zip(attacks, [facts_by_round.get(r) for r in range(1, len(attacks) + 1)]), start=1):
        if fact is None:
            print(f"{i:>3} {atk['label']:7} {'--':>6} {'(orphan)':15} "
                  f"{str(atk['expected_landed']):>8} {str(atk['expected_reason']):15} FAIL")
            fails.append(f"round {i}: no landed fact (orphan?)")
            continue
        try:
            validator.validate(fact)
            schema_ok = True
        except Exception as exc:  # noqa: BLE001
            schema_ok = False
            fails.append(f"round {i}: landed fact invalid: {exc}")
        ok = (fact["landed"] == atk["expected_landed"]
              and fact["landed_reason"] == atk["expected_reason"] and schema_ok)
        if not ok and schema_ok:
            fails.append(f"round {i}: got ({fact['landed']}, {fact['landed_reason']}), "
                         f"expected ({atk['expected_landed']}, {atk['expected_reason']})")
        print(f"{i:>3} {atk['label']:7} {str(fact['landed']):>6} {str(fact['landed_reason']):15} "
              f"{str(atk['expected_landed']):>8} {str(atk['expected_reason']):15} "
              f"{'PASS' if ok else 'FAIL'}")

    # --- 2: each request_id appears exactly once in proxy.jsonl ---
    proxy_ids: dict[str, int] = {}
    for line in proxy:
        rid = line.get("request_id", "")
        if rid:
            proxy_ids[rid] = proxy_ids.get(rid, 0) + 1
    print()
    for rec in red_records:
        rid = rec["request_id"]
        n = proxy_ids.get(rid, 0)
        status = "PASS" if n == 1 else "FAIL"
        if n != 1:
            fails.append(f"request_id {rid} appears {n}x in proxy.jsonl (want 1)")
        print(f"proxy.jsonl round {rec['round']}: request_id x{n}  {status}")

    # --- 3: no /api/Challenges lines leaked into Blue's input ---
    leaked = [p for p in proxy if p.get("path", "").startswith("/api/Challenges")]
    leak_status = "PASS" if not leaked else "FAIL"
    if leaked:
        fails.append(f"{len(leaked)} /api/Challenges line(s) leaked into proxy.jsonl")
    print(f"\nproxy.jsonl has no /api/Challenges lines: {leak_status}")

    if orphans:
        print(f"orphans (not scored): {[o['request_id'] for o in orphans]}")

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} problem(s))")
        for f in fails:
            print(f"  - {f}")
        return 1
    print(f"RESULT: PASS ({len(facts)} attacks, all landed facts match expected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
