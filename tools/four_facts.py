"""The Stage 5 done-when check (Stage 5.7): are all four facts computed for a match?

    .venv/bin/python tools/four_facts.py --run-dir data/runs/<match_id>

  fact 1  (landed)               rounds.jsonl           every row has `landed`
  fact 2  (detected)             rounds.jsonl           every row has `detected`
  fact 3  (rule replay)          rule_results.jsonl     every row has `replay_fires`
  fact 4b (rule fixture FPs)     rule_results.jsonl     every row has `fixture_fires`
  fact 4a (verdict-level FPs)    benign_results.jsonl   every row has `false_positive`

Three outcomes (designer, Stage 5.7):
  PASS            all four facts computed, every artifact valid and non-empty.
  N/A (no rules)  facts 1, 2 and 4a pass, and there is no rule to score: either
                  rule_results.jsonl exists, is valid and is empty because Blue stored
                  no rule, or the match has no rule invention at all (rules mode off,
                  or scripted Blue: no rule artifacts by design). A legitimate
                  outcome, not a failure.
  FAIL            a required artifact is missing, schema-invalid or empty (rounds,
                  benign results; rule_results.jsonl in rules mode shadow / on), or a
                  row lacks its fact.

Pure: reads files only, writes nothing. Exit 0 PASS, 3 N/A, 1 FAIL. Stage 5 is done
when at least one Gate 3 match (--red ai --blue claude, rules on) reaches PASS.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = REPO / "schemas"
PASS, NA, FAIL = "PASS", "N/A (no rules)", "FAIL"
EXIT = {PASS: 0, NA: 3, FAIL: 1}


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((SCHEMAS / f"{name}.schema.json").read_text()))


VERSIONED = {
    "rounds.jsonl": {"0.1": "round_record_v0_1", "0.2": "round_record_v0_2",
                     "0.3": "round_record"},
    "benign_results.jsonl": {"0.1": "benign_result_v0_1", "0.2": "benign_result_v0_2",
                             "0.3": "benign_result"},
    "rule_results.jsonl": {"0.1": "rule_result"},
}
FACT_FIELDS = {"rounds.jsonl": {"fact1_landed": "landed", "fact2_detected": "detected"},
               "benign_results.jsonl": {"fact4a_benign_fp": "false_positive"},
               "rule_results.jsonl": {"fact3_rule_replay": "replay_fires",
                                      "fact4b_rule_fixture": "fixture_fires"}}


def _manifest(run_dir: Path) -> dict:
    for name in ("match.json", "replay.json"):
        p = run_dir / name
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    return {}


def rules_mode(run_dir: Path) -> str | None:
    """The match's rules mode (None: scripted Blue, or a manifest before 0.6)."""
    params = _manifest(run_dir).get("blue_params") or {}
    return (params.get("rules") or {}).get("mode")


def _load(run_dir: Path, name: str) -> tuple[list[dict] | None, str | None]:
    """(rows, None) or (None, reason): missing, unreadable or schema-invalid."""
    p = run_dir / name
    if not p.is_file():
        return None, f"{name} missing"
    rows = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            return None, f"{name} line {i}: not JSON ({exc.msg})"
        schema = VERSIONED[name].get(row.get("schema_version"))
        if schema is None:
            return None, f"{name} line {i}: unknown schema_version {row.get('schema_version')!r}"
        errors = [e.message for e in _validator(schema).iter_errors(row)]
        if errors:
            return None, f"{name} line {i}: schema-invalid ({errors[0]})"
        rows.append(row)
    return rows, None


def _facts(name: str, rows: list[dict]) -> dict[str, str]:
    out = {}
    for fact, field in FACT_FIELDS[name].items():
        missing = [i for i, r in enumerate(rows, 1) if field not in r]
        out[fact] = "computed" if not missing else f"missing on rows {missing}"
    return out


def check(run_dir: Path) -> dict:
    """{status, facts: {fact: state}, rules_mode, reasons, counts}. Pure."""
    run_dir = Path(run_dir)
    mode = rules_mode(run_dir)
    facts: dict[str, str] = {}
    reasons: list[str] = []
    counts: dict[str, int] = {}
    for name in ("rounds.jsonl", "benign_results.jsonl"):
        rows, err = _load(run_dir, name)
        if err is not None:
            reasons.append(err)
            facts.update({f: "not computed" for f in FACT_FIELDS[name]})
            continue
        counts[name] = len(rows)
        if not rows:
            reasons.append(f"{name} is empty")
            facts.update({f: "empty" for f in FACT_FIELDS[name]})
            continue
        facts.update(_facts(name, rows))
    rule_name = "rule_results.jsonl"
    no_rules = None
    if mode in ("shadow", "on"):
        rows, err = _load(run_dir, rule_name)
        if err is not None:
            reasons.append(f"{err} (rules mode {mode} must score its rules)")
            facts.update({f: "not computed" for f in FACT_FIELDS[rule_name]})
        else:
            counts[rule_name] = len(rows)
            if rows:
                facts.update(_facts(rule_name, rows))
            else:
                no_rules = f"rules mode {mode}: Blue stored no rule (rule_results.jsonl empty)"
                facts.update({f: "no rules" for f in FACT_FIELDS[rule_name]})
    else:
        no_rules = ("scripted Blue: no rule invention" if mode is None
                    else f"rule invention {mode}: no rule artifacts by design")
        facts.update({f: "no rules" for f in FACT_FIELDS[rule_name]})
    bad = [f"{f}: {s}" for f, s in facts.items() if s not in ("computed", "no rules")]
    if reasons or bad:
        status = FAIL
        reasons = reasons or bad  # artifact-level reasons explain the facts they cover
    elif no_rules is not None:
        status = NA
        reasons.append(no_rules)
    else:
        status = PASS
    return {"status": status, "rules_mode": mode, "facts": facts, "reasons": reasons,
            "counts": counts}


def format_result(r: dict) -> str:
    facts = "  ".join(f"{k}={v}" for k, v in r["facts"].items())
    why = f"  ({'; '.join(r['reasons'])})" if r["reasons"] else ""
    return f"four facts: {r['status']}{why}\n  {facts}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--run-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    r = check(args.run_dir)
    print(format_result(r))
    return EXIT[r["status"]]


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    raise SystemExit(main())
