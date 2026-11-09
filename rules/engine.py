"""The rule engine (Stage 5.3, D3). PURE and deterministic: (validated rules, one
request) -> the rule_ids that fire, in rule order. No network, no file access, no
eval/exec: a rule is data, matched by fixed code.

A condition matches if it matches ANY normalized form of its field
(rules/normalize.py, the same forms scripted Blue matches). A rule fires if ALL its
conditions match. Regexes are RE2 (linear time). Each form is capped at FIELD_CAP
characters (nginx's client_max_body_size, so no request nginx accepts is ever
truncated; the cap only bounds the work for anything larger).
"""

from __future__ import annotations

from dataclasses import dataclass

from rules import normalize
from rules.validator import Validated

FIELD_CAP = 1 << 20


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: str
    body: str

    @classmethod
    def from_log(cls, line: dict) -> "Request":
        """A proxy-log line (or a fixture line). Only request-side fields are kept."""
        return cls(line.get("method", "") or "", line.get("path", "") or "",
                   line.get("query", "") or "", line.get("body", "") or "")


def forms(req: Request) -> dict[str, list[str]]:
    f = normalize.request_forms(req.path, req.query, req.body, req.method)
    return {k: [v[:FIELD_CAP] for v in vs] for k, vs in f.items()}


def _match(cond: dict, compiled, values: list[str]) -> bool:
    op, pat, ci = cond["op"], cond["pattern"], cond["case_insensitive"]
    if op == "regex":
        return any(compiled.search(v) is not None for v in values)
    if ci:
        pat = pat.lower()
        values = [v.lower() for v in values]
    if op == "contains":
        return any(pat in v for v in values)
    return any(pat == v for v in values)  # equals


def fires(rule: Validated, req_forms: dict[str, list[str]]) -> bool:
    if not rule.valid:
        raise ValueError("the engine only evaluates validated rules")
    return all(_match(c, comp, req_forms[c["field"]])
               for c, comp in zip(rule.rule["conditions"], rule.compiled))


def fire(rules: list[Validated], req: Request) -> list[str]:
    """rule_ids of the valid rules that fire on `req`, in rule order."""
    f = forms(req)
    return [r.rule_id for r in rules if r.valid and fires(r, f)]
