"""Judge fact 1: did each attack land?

PURE CODE. Reads artifacts and computes; makes NO network calls and never touches
the Target. Inputs:

  - data/runs/<run>/red_attacks.jsonl   (ground-truth label per request_id)
  - data/runs/<run>/challenge_snapshots.jsonl  (before/after solved sets)
  - config/challenge_map.json           (CWE -> mapped challenge names)

Output: data/runs/<run>/landed.jsonl, one landed-fact line per attack that has a
snapshot. Each line validates against schemas/landed_fact.schema.json.

Rule (contract 6.1), with mapped = challenge_map[label],
newly_solved = after_solved - before_solved:

    mapped empty                 -> landed=null,  reason="not_measurable"
    mapped subset of before      -> landed=null,  reason="already_solved"
    newly_solved & mapped        -> landed=true,  reason=null
    otherwise                    -> landed=false, reason=null

Only challenges in the label's mapping count toward landed; the full newly_solved
list is stored as evidence regardless. A Red record with no snapshot line is
SNAPSHOT-MISSING: skipped here, and the round-record join marks it (contract 6.1).
Snapshot rows of benign traffic (traffic == "benign") are ignored: fact 4a reads them.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_RUN = REPO / "data" / "runs" / "live"
CHALLENGE_MAP = REPO / "config" / "challenge_map.json"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def compute_landed(label: str, before_solved, after_solved, challenge_map: dict) -> dict:
    """Return the landed fields for one attack. Pure; see module docstring."""
    mapped = set(challenge_map.get(label, []))
    before = set(before_solved)
    after = set(after_solved)
    newly_solved = sorted(after - before)

    if not mapped:
        landed, reason = None, "not_measurable"
    elif mapped <= before:
        landed, reason = None, "already_solved"
    elif mapped & set(newly_solved):
        landed, reason = True, None
    else:
        landed, reason = False, None

    return {"landed": landed, "landed_reason": reason, "newly_solved": newly_solved}


def judge_run(run_dir: Path, challenge_map: dict) -> tuple[list[dict], list[dict]]:
    """Return (landed_facts, orphans). Does not write anything."""
    attacks = _read_jsonl(run_dir / "red_attacks.jsonl")
    # Benign rows (Stage 5.2) are fact 4a's business, skipped here explicitly. Rows
    # written before Stage 5.2 have no `traffic` field and are all Red.
    snapshots = {s["request_id"]: s for s in _read_jsonl(run_dir / "challenge_snapshots.jsonl")
                 if s.get("traffic", "red") == "red"}

    facts, orphans = [], []
    for atk in attacks:
        snap = snapshots.get(atk["request_id"])
        if snap is None:
            orphans.append(atk)
            continue
        result = compute_landed(atk["label"], snap["before_solved"],
                                snap["after_solved"], challenge_map)
        facts.append({
            "schema_version": "0.1",
            "match_id": atk["match_id"],
            "round": atk["round"],
            "request_id": atk["request_id"],
            "label": atk["label"],
            **result,
        })
    return facts, orphans


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--challenge-map", type=Path, default=CHALLENGE_MAP)
    args = parser.parse_args(argv)

    challenge_map = json.loads(args.challenge_map.read_text(encoding="utf-8"))
    facts, orphans = judge_run(args.run_dir, challenge_map)

    out = args.run_dir / "landed.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for fact in facts:
            fh.write(json.dumps(fact) + "\n")

    for fact in facts:
        print(f"round {fact['round']} {fact['label']:7} landed={fact['landed']!s:5} "
              f"reason={fact['landed_reason']} newly_solved={fact['newly_solved']}")
    print(f"{len(facts)} landed facts -> {out}")
    if orphans:
        print(f"orphans (no snapshot, not scored): "
              f"{[o['request_id'] for o in orphans]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
