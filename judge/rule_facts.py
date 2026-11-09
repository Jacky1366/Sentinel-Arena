"""Judge facts 3 and 4b: how good is each rule? PURE (no network, no file access;
callers load the artifacts). Uses the neutral rules/ package, never blue/.

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

from dataclasses import dataclass

from rules import engine, validator


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
