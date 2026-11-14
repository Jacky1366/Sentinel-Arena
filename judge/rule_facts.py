"""Judge facts 3 and 4b: how good is each rule? `score` is PURE (no network, no
file access; callers load the artifacts). Uses the neutral rules/ package, never
blue/.

Two callers: tools/score_rules.py (a rules file against a frozen match, Stage 5.3)
and, from Stage 5.5, the match's own `judge_rules` step (`main --run-dir`): every
rule Blue stored in the match's rules.jsonl is scored into <match>/rule_results.jsonl,
and rule_source_benign anomalies are appended to <match>/anomalies.jsonl. Without
rules.jsonl (scripted Blue, rules mode off) the step writes nothing.

Fact 3 (D2, offline replay): evaluate the rule against the FROZEN recorded proxy
line of its source_request_id. null with a reason when:
    rule_invalid       the validator rejected the rule
    source_benign      the source is a benign request (also an anomaly:
                       rule_source_benign)
    source_orphan      the source is a Red record that was never logged
    source_not_found   the source is neither a Red nor a benign record
When it fires or not, source_label is the Red label and cwe_matches_source says
whether the rule's cwe equals it.

Fact 4b: evaluate the rule against every entry of the fixed benign fixture (benign
lines of a frozen golden proxy log); report the count and which benign_ids.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

from judge import anomalies as anomalies_mod
from judge import rule_verdicts
from rules import engine, validator

REPO = Path(__file__).resolve().parent.parent
DEFAULT_RUN = REPO / "data" / "runs" / "live"
FIXTURE = REPO / "benign" / "fixture_v1.jsonl"
RESULTS = "rule_results.jsonl"


@dataclass(frozen=True)
class MatchView:
    """What fact 3 needs from a frozen match directory."""
    match_id: str
    red_labels: dict[str, str]        # request_id -> Red label
    benign_ids: dict[str, str]        # request_id -> benign_id
    proxy: dict[str, dict]            # request_id -> proxy line


def score(rules: list, match: MatchView, fixture: list[dict],
          fixture_sha256: str) -> tuple[list[dict], list[dict]]:
    """(rule_results, anomalies) for every rule, in order."""
    checked = validator.validate_rules(rules)
    fixture_forms = [(f["benign_id"], engine.forms(engine.Request.from_log(f))) for f in fixture]
    results, anomalies = [], []
    for v in checked:
        rule = v.rule if isinstance(v.rule, dict) else {}
        src = rule.get("source_request_id")
        src = src if isinstance(src, str) else None
        out = {"schema_version": "0.1", "match_id": match.match_id, "rule_index": v.index,
               "rule_id": v.rule_id, "valid": v.valid, "invalid_reasons": v.reasons,
               "cwe": rule.get("cwe") if v.valid else None, "source_request_id": src,
               "replay_fires": None, "replay_reason": None, "source_label": None,
               "cwe_matches_source": None, "fixture_sha256": fixture_sha256,
               "fixture_fires": None, "fixture_benign_ids": []}
        if not v.valid:
            out["replay_reason"] = "rule_invalid"
            results.append(out)
            continue
        hits = [bid for bid, f in fixture_forms if engine.fires(v, f)]
        out["fixture_fires"], out["fixture_benign_ids"] = len(hits), hits
        if src in match.benign_ids:
            out["replay_reason"] = "source_benign"
            anomalies.append({"schema_version": "0.1", "match_id": match.match_id,
                              "kind": "rule_source_benign", "request_id": src,
                              "detail": {"rule_id": v.rule_id,
                                         "benign_id": match.benign_ids[src]}})
        elif src in match.red_labels:
            line = match.proxy.get(src)
            if line is None:
                out["replay_reason"] = "source_orphan"
            else:
                out["replay_fires"] = engine.fires(v, engine.forms(engine.Request.from_log(line)))
                out["source_label"] = match.red_labels[src]
                out["cwe_matches_source"] = rule["cwe"] == match.red_labels[src]
        else:
            out["replay_reason"] = "source_not_found"
        results.append(out)
    return results, anomalies


# --------------------------------------------------------------------------
# File loading (shared with tools/score_rules.py) and the in-match step
# --------------------------------------------------------------------------

def _jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_view(match_dir: Path, match_id: str) -> MatchView:
    """What fact 3 needs from a match directory (frozen or being judged)."""
    return MatchView(
        match_id=match_id,
        red_labels={r["request_id"]: r["label"] for r in _jsonl(match_dir / "red_attacks.jsonl")},
        benign_ids={b["request_id"]: b["benign_id"]
                    for b in _jsonl(match_dir / "benign_requests.jsonl")},
        proxy={l["request_id"]: l for l in _jsonl(match_dir / "proxy.jsonl")
               if l.get("request_id")})


def load_fixture(path: Path = FIXTURE) -> tuple[list[dict], str]:
    v = Draft202012Validator(json.loads((REPO / "schemas" / "benign_fixture.schema.json")
                                        .read_text(encoding="utf-8")))
    rows = _jsonl(path)
    for r in rows:
        v.validate(r)
    return rows, hashlib.sha256(path.read_bytes()).hexdigest()


def score_match(run_dir: Path, fixture_path: Path = FIXTURE
                ) -> tuple[list[dict], list[dict]] | None:
    """(rule_results, anomalies) for every rule in <run_dir>/rules.jsonl, or None if
    the match has no rules.jsonl. Rows are schema-validated; writes nothing."""
    if not (run_dir / rule_verdicts.RULES).is_file():
        return None
    rows = rule_verdicts.load_rules(run_dir)
    match_ids = {r["match_id"] for r in rows}
    if len(match_ids) > 1:
        raise ValueError(f"{rule_verdicts.RULES} mixes match ids {sorted(match_ids)}")
    if not rows:
        return [], []
    fixture, fx_sha = load_fixture(fixture_path)
    results, anomalies = score([r["rule"] for r in rows],
                               load_view(run_dir, match_ids.pop()), fixture, fx_sha)
    v = Draft202012Validator(json.loads((REPO / "schemas" / "rule_result.schema.json")
                                        .read_text(encoding="utf-8")))
    for row in results:
        errors = [e.message for e in v.iter_errors(row)]
        if errors:
            raise ValueError(f"rule_result {row['rule_id']} is schema-invalid: {errors}")
        if not row["valid"]:  # Blue stored it, so the validator accepted it once
            raise ValueError(f"stored rule {row['rule_id']} is invalid: "
                             f"{[x['code'] for x in row['invalid_reasons']]}")
    anomalies_mod.validate(anomalies)
    return results, anomalies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Judge facts 3 + 4b for the rules Blue "
                                                 "stored in this match (Stage 5.5).")
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    args = parser.parse_args(argv)
    scored = score_match(args.run_dir, args.fixture)
    if scored is None:
        print(f"no {rule_verdicts.RULES}: no rules to score")
        return 0
    results, anomalies = scored
    (args.run_dir / RESULTS).write_text("".join(json.dumps(r) + "\n" for r in results),
                                        encoding="utf-8")
    anomalies_mod.append(args.run_dir, anomalies)
    for r in results:
        print(f"{r['rule_id']} {r['cwe']:7} replay={str(r['replay_fires']):5} "
              f"{str(r['replay_reason'] or ''):14} cwe_ok={str(r['cwe_matches_source']):5} "
              f"fixture={r['fixture_benign_ids']}")
    print(f"{len(results)} rule results -> {args.run_dir / RESULTS}")
    for a in anomalies:
        print(f"ANOMALY {a['kind']} {a['request_id']} {a['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
