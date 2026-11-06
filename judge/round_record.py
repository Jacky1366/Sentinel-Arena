"""Judge: assemble the round record by joining fact 1 (landed) and fact 2
(detected) over the Red records.

PURE CODE, no network. Red records are the spine: exactly one round record per Red
record, joined on request_id. Every line is validated against
schemas/round_record.schema.json BEFORE writing; on any failure the Judge raises
and writes nothing, so rounds.jsonl is never partial or invalid.

  - landed / landed_reason / newly_solved come from the landed fact (fact 1).
  - verdict / detected / type_correct / detected_reason come from fact 2.
  - A Red record with no landed fact is snapshot_missing (no snapshot, contract 6.1): the
    round record is still emitted with landed=null, landed_reason="snapshot_missing"
    (excluded from landing stats), while detection is scored normally from fact 2,
    because the request was on Blue's input. In a normal run this never happens.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from judge import fact2_detected

REPO = Path(__file__).resolve().parent.parent
DEFAULT_RUN = REPO / "data" / "runs" / "live"
SCHEMA_PATH = REPO / "schemas" / "round_record.schema.json"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def build_round_records(run_dir: Path) -> list[dict]:
    red = _read_jsonl(run_dir / "red_attacks.jsonl")
    landed_by_id = {r["request_id"]: r for r in _read_jsonl(run_dir / "landed.jsonl")}
    fact2 = fact2_detected.compute_fact2(run_dir)
    validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))

    rounds: list[dict] = []
    for record in red:
        rid = record["request_id"]
        landed = landed_by_id.get(rid)
        if landed is None:
            # snapshot_missing (no snapshot): landing is unknown, excluded from landing
            # stats, but detection is still scored from the proxy line + verdict.
            landed = {"landed": None, "landed_reason": "snapshot_missing", "newly_solved": []}
        detect = fact2[rid]
        round_record = {
            "schema_version": "0.1",
            "match_id": record["match_id"],
            "round": record["round"],
            "request_id": rid,
            "label": record["label"],
            "verdict": detect["verdict"],
            "landed": landed["landed"],
            "landed_reason": landed["landed_reason"],
            "newly_solved": landed["newly_solved"],
            "detected": detect["detected"],
            "type_correct": detect["type_correct"],
            "detected_reason": detect["detected_reason"],
            "replay_blocked": None,
            "benign_fp": None,
        }
        errors = sorted(validator.iter_errors(round_record), key=lambda e: list(e.absolute_path))
        if errors:
            raise ValueError(
                f"round record for request_id {rid} is schema-invalid: "
                f"{'; '.join(e.message for e in errors)}")
        rounds.append(round_record)
    return rounds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    args = parser.parse_args(argv)

    rounds = build_round_records(args.run_dir)
    out = args.run_dir / "rounds.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for r in rounds:
            fh.write(json.dumps(r) + "\n")

    for r in rounds:
        print(f"round {r['round']} {r['label']:7} verdict={r['verdict']!s:7} "
              f"landed={r['landed']!s:5} detected={r['detected']!s:5} "
              f"type_correct={r['type_correct']!s:5} reason={r['detected_reason']}")
    print(f"{len(rounds)} round records -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
