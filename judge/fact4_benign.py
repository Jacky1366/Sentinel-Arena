"""Judge fact 4a: verdict-level false positives on benign traffic (Stage 5.2).

PURE CODE, no network. Inputs (all in the match directory):

  - benign_requests.jsonl        ground truth: which request_ids are benign
  - proxy.jsonl                  which request_ids were actually logged
  - verdicts.jsonl               Blue's label per request_id
  - red_attacks.jsonl            to tell Red verdicts from unmatched ones
  - challenge_snapshots.jsonl    benign rows (traffic == "benign")

Outputs, every line schema-validated BEFORE anything is written:

  benign_results.jsonl, one line per benign record (contract 6.5):
    verdict is a CWE      -> false_positive=true
    verdict is benign     -> false_positive=false
    logged, no verdict    -> false_positive=null, fp_reason="no_verdict"
    instrument failure    -> false_positive=null, fp_reason="instrument_failure" (D13)
    no proxy line         -> false_positive=null, fp_reason="orphan"
  (all nulls are excluded from the FP denominator; no_verdict is counted in the
  benign no-verdict rate, instrument_failure in its own rate. schema_version 0.2,
  with verdict_source. Not a loophole: Blue cannot tell which lines are
  benign, so skipping is punished on the attack side.)

  anomalies.jsonl (contract 6.6), never silently ignored:
    benign_solved_challenge  a benign request's newly_solved differs in ANY way
                             from its expected_solves (exact set equality)
    benign_snapshot_missing  a benign request has no snapshot row
    unmatched_verdict        a verdict whose request_id is neither Red nor benign

A benign request that trips an anomaly is still scored: Blue's verdict on it is a
real result. Duplicate verdicts raise (ambiguous data, same as fact 2).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from judge import fact2_detected

REPO = Path(__file__).resolve().parent.parent
DEFAULT_RUN = REPO / "data" / "runs" / "live"
SCHEMAS = REPO / "schemas"
RESULTS, ANOMALIES = "benign_results.jsonl", "anomalies.jsonl"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def fp_fields(proxy_present: bool, verdict: str | None,
              no_verdict_reason: str | None = None, source: str | None = None) -> dict:
    """Pure branch logic for one benign record."""
    if not proxy_present:
        return {"verdict": None, "verdict_source": None, "false_positive": None,
                "fp_reason": "orphan"}
    if verdict is None:
        reason = "instrument_failure" if no_verdict_reason == "instrument_failure" \
            else "no_verdict"
        return {"verdict": None, "verdict_source": None, "false_positive": None,
                "fp_reason": reason}
    return {"verdict": verdict, "verdict_source": source,
            "false_positive": verdict != "benign", "fp_reason": None}


def compute(run_dir: Path) -> tuple[list[dict], list[dict]]:
    """(benign_results, anomalies). Writes nothing."""
    benign = _read_jsonl(run_dir / "benign_requests.jsonl")
    red_ids = {r["request_id"] for r in _read_jsonl(run_dir / "red_attacks.jsonl")}
    proxy_ids = {l["request_id"] for l in _read_jsonl(run_dir / "proxy.jsonl")
                 if fact2_detected.UUID4.match(l.get("request_id", "") or "")}
    # validated by version, duplicates and instrument_failure cross-checked (raise)
    verdict_rows = fact2_detected.load_verdicts(run_dir)
    verdicts = fact2_detected.verdicts_by_request_id(verdict_rows)
    snaps = {s["request_id"]: s for s in _read_jsonl(run_dir / "challenge_snapshots.jsonl")
             if s.get("traffic") == "benign"}

    results, anomalies = [], []
    benign_ids = set()
    for b in benign:
        rid = b["request_id"]
        benign_ids.add(rid)
        v = verdicts.get(rid) or {}
        results.append({"schema_version": "0.2", "match_id": b["match_id"], "request_id": rid,
                        "benign_id": b["benign_id"], "category": b["category"],
                        **fp_fields(rid in proxy_ids, v.get("verdict"),
                                    v.get("no_verdict_reason"), v.get("source"))})
        snap = snaps.get(rid)
        if snap is None:
            anomalies.append({"schema_version": "0.1", "match_id": b["match_id"],
                              "kind": "benign_snapshot_missing", "request_id": rid,
                              "detail": {"benign_id": b["benign_id"]}})
            continue
        newly = sorted(set(snap["after_solved"]) - set(snap["before_solved"]))
        expected = sorted(b["expected_solves"])
        if newly != expected:
            anomalies.append({"schema_version": "0.1", "match_id": b["match_id"],
                              "kind": "benign_solved_challenge", "request_id": rid,
                              "detail": {"benign_id": b["benign_id"], "newly_solved": newly,
                                         "expected_solves": expected}})
    for v in verdict_rows:
        if v["request_id"] not in red_ids and v["request_id"] not in benign_ids:
            anomalies.append({"schema_version": "0.1", "match_id": v["match_id"],
                              "kind": "unmatched_verdict", "request_id": v["request_id"],
                              "detail": {"log_seq": v["log_seq"], "verdict": v["verdict"]}})
    _validate(results, "benign_result")
    _validate(anomalies, "anomaly")
    return results, anomalies


def _validate(rows: list[dict], schema: str) -> None:
    v = Draft202012Validator(json.loads((SCHEMAS / f"{schema}.schema.json").read_text(
        encoding="utf-8")))
    for row in rows:
        errors = list(v.iter_errors(row))
        if errors:
            raise ValueError(f"{schema} for request_id {row.get('request_id')} is "
                             f"schema-invalid: {'; '.join(e.message for e in errors)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    args = parser.parse_args(argv)

    results, anomalies = compute(args.run_dir)
    for name, rows in ((RESULTS, results), (ANOMALIES, anomalies)):
        with (args.run_dir / name).open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
    for r in results:
        print(f"benign {r['benign_id']} {r['category']:13} verdict={r['verdict']!s:7} "
              f"false_positive={r['false_positive']!s:5} reason={r['fp_reason']}")
    print(f"{len(results)} benign results -> {args.run_dir / RESULTS}")
    for a in anomalies:
        print(f"ANOMALY {a['kind']} {a['request_id']} {a['detail']}")
    print(f"{len(anomalies)} anomalies -> {args.run_dir / ANOMALIES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
