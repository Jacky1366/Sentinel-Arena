"""Judge cross-check of Blue's rule artifacts and rule verdicts (Stage 5.5, D4, D9).
PURE: reads the match directory, writes nothing, raises on any inconsistency
(ambiguous data: the Judge never guesses).

Blue may answer a line from a hot-loaded rule, with no API call. That is only
legitimate if the rules really existed and really fired, so the Judge re-runs the
hot-load sequence itself, from rules.jsonl and the frozen proxy log, with the SAME
neutral code Blue uses (rules/hotload.py; the Judge never imports blue/):

  rules.jsonl         every line schema-valid (match_rule), every rule re-validated
                      (rules/validator.py), all lines the same hot_loaded, created in
                      log_seq order, created_match = the verdicts' match_id
  rule_rejections     every line schema-valid (rule_rejection)
  ids                 unique across both files
  provenance          each stored or rejected proposal sits on a line whose verdict
                      is an AI verdict with the same request_id and label = its cwe
  every verdict line  hot_loaded rules created on EARLIER lines fire exactly
                      fired_rule_ids -> the row is source "rule" with the tie-break
                      CWE; nothing fires -> the row is not a rule verdict and lists
                      no ids. In shadow mode (hot_loaded false) no row is a rule
                      verdict.

Without rules.jsonl and rule_rejections.jsonl (scripted Blue, rules mode off, every
match before Stage 5.5) any rule verdict raises.

Library (Stage 6.1, D21, D22): when the folder holds a library snapshot (library.json,
copied there by the orchestrator / replay tool before Blue ran), it is loaded with the
same read-only code Blue uses (rules/library.py) and its rules are PRELOADED into the
re-run (live from line 1, first in the tie-break). Then every verdict must be 0.4 and
its rule_origin must be the re-run's; and a library needs rules mode on (in-match rules
hot_loaded, if there are any). Without a snapshot no row may be 0.4 or name a library
rule.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from rules import engine, hotload, library, validator

REPO = Path(__file__).resolve().parent.parent
RULES, REJECTIONS = "rules.jsonl", "rule_rejections.jsonl"
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _schema(name: str) -> dict:
    return json.loads((REPO / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


_REGISTRY = Registry().with_resources(
    [(s["$id"], Resource.from_contents(s)) for s in (_schema("rule"),)])
MATCH_RULE = Draft202012Validator(_schema("match_rule"), registry=_REGISTRY)
REJECTION = Draft202012Validator(_schema("rule_rejection"))


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _validated(rows: list[dict], v: Draft202012Validator, name: str) -> list[dict]:
    for i, row in enumerate(rows, start=1):
        errors = [e.message for e in v.iter_errors(row)]
        if errors:
            raise ValueError(f"{name} line {i} is schema-invalid: {'; '.join(errors)}")
    return rows


def load_rules(run_dir: Path) -> list[dict]:
    """rules.jsonl rows, schema-validated (empty if the file is absent)."""
    return _validated(_read_jsonl(run_dir / RULES), MATCH_RULE, RULES)


def load_rejections(run_dir: Path) -> list[dict]:
    return _validated(_read_jsonl(run_dir / REJECTIONS), REJECTION, REJECTIONS)


def judged_lines(run_dir: Path) -> list[dict]:
    """The proxy lines Blue judges, in log order: log_seq = position (1-based)."""
    return [l for l in _read_jsonl(run_dir / "proxy.jsonl")
            if UUID4.match(l.get("request_id", "") or "")]


def check(run_dir: Path, verdicts: list[dict]) -> None:
    """Raise unless every rule artifact and every verdict's rule fields are exactly
    what the hot-load sequence produces. `verdicts` are fact 2's normalized rows
    (each with source and fired_rule_ids)."""
    rules = load_rules(run_dir)
    rejections = load_rejections(run_dir)
    snapshot = run_dir / library.SNAPSHOT
    lib = library.load(snapshot) if snapshot.is_file() else None
    for v in verdicts:
        v4 = v.get("schema_version") == "0.4"
        if lib is None and (v4 or any(i.startswith("lib-") for i in v["fired_rule_ids"])):
            raise ValueError(f"verdict log_seq {v['log_seq']} is a library-era (0.4) row, "
                             f"but the folder has no {library.SNAPSHOT}")
        if lib is not None and not v4:
            raise ValueError(f"verdict log_seq {v['log_seq']} is schema "
                             f"{v.get('schema_version')!r}: with a library every row is 0.4")
    if not rules and not rejections and lib is None:
        for v in verdicts:
            if v["source"] == "rule" or v["fired_rule_ids"]:
                raise ValueError(f"verdict log_seq {v['log_seq']} is a rule verdict, but the "
                                 f"match has no {RULES}")
        return
    by_seq = {v["log_seq"]: v for v in verdicts}
    match_ids = {v["match_id"] for v in verdicts}
    hot = {r["hot_loaded"] for r in rules}
    if len(hot) > 1:
        raise ValueError(f"{RULES} mixes hot_loaded true and false (one mode per match)")
    hot_loaded = hot == {True}
    if lib is not None and hot == {False}:
        raise ValueError(f"a library is loaded, but {RULES} is hot_loaded false (shadow): "
                         f"a library needs rules mode on")
    if lib is not None:
        hot_loaded = True  # mode on (no in-match rule may have been stored)

    ids = [r["rule"]["rule_id"] for r in rules] + [r["rule_id"] for r in rejections]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"rule ids used more than once across {RULES} and {REJECTIONS}: "
                         f"{dupes}")

    def provenance(rule_id: str, seq: int, rid: str, label: str, mid: str) -> None:
        if mid not in match_ids:
            raise ValueError(f"rule {rule_id}: match_id {mid!r} is not the verdicts' "
                             f"{sorted(match_ids)}")
        v = by_seq.get(seq)
        if v is None or v["request_id"] != rid:
            raise ValueError(f"rule {rule_id}: created at log_seq {seq} for request "
                             f"{rid}, but that line's verdict is not for that request")
        if v["source"] != "ai" or v["verdict"] != label:
            raise ValueError(f"rule {rule_id}: proposed with label {label!r} on log_seq "
                             f"{seq}, but that line's verdict is {v['verdict']!r} "
                             f"(source {v['source']!r}); a proposal rides on an AI verdict")

    seen: set[str] = set()
    hl = hotload.HotLoad(lib.entries if lib is not None else ())
    last = 0
    for r in rules:
        rule = r["rule"]
        checked = validator.validate_rule(0, rule, seen)
        if not checked.valid:
            raise ValueError(f"{RULES} holds an invalid rule {rule['rule_id']}: "
                             f"{[x['code'] for x in checked.reasons]}")
        if rule["created_at_log_seq"] < last:
            raise ValueError(f"{RULES} is not in creation order at {rule['rule_id']}")
        last = rule["created_at_log_seq"]
        if rule.get("created_match") not in (None, r["match_id"]):
            raise ValueError(f"rule {rule['rule_id']}: created_match "
                             f"{rule['created_match']!r} is not {r['match_id']!r}")
        provenance(rule["rule_id"], rule["created_at_log_seq"], rule["source_request_id"],
                   rule["cwe"], r["match_id"])
        if hot_loaded:
            hl.add(checked)
    for x in rejections:
        provenance(x["rule_id"], x["created_at_log_seq"], x["source_request_id"], x["label"],
                   x["match_id"])

    lines = judged_lines(run_dir)
    for seq, line in enumerate(lines, start=1):
        v = by_seq.get(seq)
        if v is None:
            continue  # a missing row is fact 2's business (no_verdict), not a rule question
        if v["request_id"] != line["request_id"]:
            raise ValueError(f"verdict log_seq {seq} is for {v['request_id']}, but proxy "
                             f"line {seq} is {line['request_id']}")
        firing = hl.fire(engine.Request.from_log(line), seq)
        if firing.rule_ids:
            if v["source"] != "rule" or v["fired_rule_ids"] != firing.rule_ids \
                    or v["verdict"] != firing.cwe \
                    or v.get("rule_origin", "match") != firing.origin:
                raise ValueError(f"verdict log_seq {seq}: hot-loaded rules "
                                 f"{firing.rule_ids} fire (tie-break {firing.cwe}, origin "
                                 f"{firing.origin}), but the row says source "
                                 f"{v['source']!r}, fired {v['fired_rule_ids']}, verdict "
                                 f"{v['verdict']!r}, origin {v.get('rule_origin')!r}")
        elif v["source"] == "rule" or v["fired_rule_ids"]:
            raise ValueError(f"verdict log_seq {seq} claims rules {v['fired_rule_ids']} "
                             f"fired, but no hot-loaded rule fires on that line")
    extra = sorted(set(by_seq) - set(range(1, len(lines) + 1)))
    if any(by_seq[s]["source"] == "rule" for s in extra):
        raise ValueError(f"rule verdicts for log_seq {extra} beyond the proxy log")
