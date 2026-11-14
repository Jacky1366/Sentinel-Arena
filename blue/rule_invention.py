"""Blue rule invention, the body's half (Stage 5.5, D3, D4, D8, D9).

The AI proposes at most one rule per verdict and writes ONLY its `conditions`. This
module (code, never the AI) turns a proposal into a rule:

  rule_id             next id of a per-match sequence r-001, r-002, ...; a rejected
                      proposal uses up its id too, so every proposal has one
  cwe                 the label Blue gave the line (a proposal on a `benign` line is
                      rejected by the validator as cwe_benign)
  source_request_id   the line's request_id, from the local index (D8: the AI never
                      sees or writes a request_id)
  created_at_log_seq  the line it was proposed on (hot-load applies it from the
                      NEXT line only, D4)
  created_match       this match

then runs the shared validator (rules/validator.py) and the per-match cap.

  valid, under the cap  -> rules.jsonl            (hot-loaded iff mode "on")
  anything else         -> rule_rejections.jsonl  (every reason; never applied)

Modes (config agents.blue.rules.mode; designer decision, Stage 5.5):
  off     no proposals at all (prompt v1; this module is not used)
  shadow  proposals validated, recorded and scored, NEVER hot-loaded
  on      proposals hot-loaded: a later line a rule matches gets a rule verdict
          and no API call (D9)
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from rules import engine, hotload, validator

MODES = ("off", "shadow", "on")
DEFAULT_MAX_RULES = 10
PROPOSAL_KEYS = {"conditions"}  # all the AI may write; the body fills the rest
RULES, REJECTIONS = "rules.jsonl", "rule_rejections.jsonl"

_SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))


_REGISTRY = Registry().with_resources(
    [(s["$id"], Resource.from_contents(s)) for s in (_schema("rule"),)])
MATCH_RULE = Draft202012Validator(_schema("match_rule"), registry=_REGISTRY)
REJECTION = Draft202012Validator(_schema("rule_rejection"))


def _check(v: Draft202012Validator, row: dict) -> None:
    errors = [e.message for e in v.iter_errors(row)]
    if errors:  # a bug in this module, never the AI's fault
        raise ValueError(f"{row.get('rule_id') or row.get('rule', {}).get('rule_id')}: "
                         f"schema-invalid row: {'; '.join(errors)}")


class RuleBook:
    """Every proposal of one match, in order. Holds the hot-loaded set in mode 'on'."""

    def __init__(self, match_id: str, mode: str, max_rules: int = DEFAULT_MAX_RULES):
        if mode not in ("shadow", "on"):
            raise ValueError(f"RuleBook needs mode 'shadow' or 'on', not {mode!r}")
        if isinstance(max_rules, bool) or not isinstance(max_rules, int) or max_rules < 0:
            raise ValueError("max_rules must be a non-negative integer")
        self.match_id, self.mode, self.max_rules = match_id, mode, max_rules
        self.hot = hotload.HotLoad()
        self.rules: list[dict] = []        # rules.jsonl rows
        self.rejections: list[dict] = []   # rule_rejections.jsonl rows
        self._seen: set[str] = set()
        self._next = 1

    def fire(self, line: dict, log_seq: int) -> hotload.Firing:
        """Rules that fire on this line. Always empty in shadow mode (never applied)."""
        if self.mode != "on":
            return hotload.Firing([], None, False)
        return self.hot.fire(engine.Request.from_log(line), log_seq)

    def propose(self, proposal, label: str, log_seq: int, request_id: str) -> dict:
        """Turn one AI proposal into a stored rule or a rejection; returns the row."""
        rule_id = f"r-{self._next:03d}"
        self._next += 1
        pre: list[dict] = []
        rule = {"rule_id": rule_id, "cwe": label}
        if isinstance(proposal, dict):
            for k in sorted(set(proposal) - PROPOSAL_KEYS):
                pre.append({"code": "schema_error",
                            "detail": f"proposal has unknown key {k!r} (the AI writes only "
                                      f"'conditions'; the body fills the rest)"})
            if "conditions" in proposal:
                rule["conditions"] = proposal["conditions"]
        else:
            pre.append({"code": "schema_error", "detail": "proposal is not an object"})
        rule.update({"source_request_id": request_id, "created_at_log_seq": log_seq,
                     "created_match": self.match_id})
        checked = validator.validate_rule(len(self.rules) + len(self.rejections), rule,
                                          self._seen)
        reasons = pre + checked.reasons
        if not reasons and len(self.rules) >= self.max_rules:
            reasons = [{"code": "rule_cap_reached",
                        "detail": f"{len(self.rules)} rules already stored this match "
                                  f"(max_rules {self.max_rules})"}]
        if reasons:
            row = {"schema_version": "0.1", "match_id": self.match_id, "rule_id": rule_id,
                   "created_at_log_seq": log_seq, "source_request_id": request_id,
                   "label": label, "proposal": proposal, "reasons": reasons}
            _check(REJECTION, row)
            self.rejections.append(row)
            return row
        row = {"schema_version": "0.1", "match_id": self.match_id,
               "hot_loaded": self.mode == "on", "rule": rule}
        _check(MATCH_RULE, row)
        self.rules.append(row)
        if self.mode == "on":
            self.hot.add(checked)
        return row
