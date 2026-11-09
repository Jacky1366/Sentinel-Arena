"""Rule validator (Stage 5.3, D3): every rejection gets a machine-readable reason.

PURE: no files, no network, no eval. Regexes are compiled with RE2 (google-re2,
pinned), a linear-time engine: catastrophic backtracking is impossible by
construction, so no regex timeout is needed (D3, reworded 2026-11-09). Features
RE2 lacks (backreferences, lookaround) get their own reason.

Reason codes (contract §5): schema_error, condition_count, forbidden_field,
unknown_field, unknown_op, empty_pattern, pattern_too_long, cwe_benign,
cwe_unknown, duplicate_rule_id, regex_unsupported_feature, regex_compile_error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import re2

CWES = ("CWE-89", "CWE-79", "CWE-22")
FIELDS = ("method", "path", "query", "body")
OPS = ("contains", "equals", "regex")
MAX_PATTERN = 200
MIN_CONDITIONS, MAX_CONDITIONS = 1, 3
# Not part of the request itself: a rule must decide BEFORE any response exists
# (fact 3 asks whether it would have blocked the request), and response fields
# would allow shortcuts like "login 200 = attack".
FORBIDDEN_FIELDS = frozenset({
    "request_id", "x_arena_request_id", "timestamp", "time", "log_seq", "round", "status",
    "status_code", "bytes", "bytes_sent", "body_bytes_sent", "response", "response_size",
    "response_body", "latency", "client", "client_addr", "remote_addr", "ip"})
RULE_KEYS = {"rule_id", "cwe", "conditions", "source_request_id", "created_at_log_seq",
             "created_match", "note"}
REQUIRED = ("rule_id", "cwe", "conditions", "source_request_id", "created_at_log_seq")
CONDITION_KEYS = {"field", "op", "pattern", "case_insensitive"}
RULE_ID = re.compile(r"^r-[0-9]{3,}$")
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
MATCH_ID = re.compile(r"^(m[0-9]{3,}|[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4})$")
# RE2's own messages for the features it deliberately lacks.
_UNSUPPORTED = re.compile(r"invalid perl operator: \(\?(=|!|<=|<!)|"
                          r"invalid escape sequence: \\([1-9]|k|g)")


@dataclass
class Validated:
    index: int
    rule: object
    valid: bool
    reasons: list[dict] = field(default_factory=list)
    compiled: list = field(default_factory=list)  # per condition: re2 pattern or None

    @property
    def rule_id(self) -> str | None:
        rid = self.rule.get("rule_id") if isinstance(self.rule, dict) else None
        return rid if isinstance(rid, str) else None


def _reason(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


def compile_regex(pattern: str, case_insensitive: bool):
    opts = re2.Options()
    opts.case_sensitive = not case_insensitive
    opts.log_errors = False
    return re2.compile(pattern, opts)


def _regex_reason(pattern: str, case_insensitive: bool, where: str):
    try:
        return compile_regex(pattern, case_insensitive), None
    except re2.error as exc:
        msg = exc.args[0].decode() if exc.args and isinstance(exc.args[0], bytes) else str(exc)
        if _UNSUPPORTED.search(msg):
            return None, _reason("regex_unsupported_feature", f"{where}: {msg} "
                                 f"(RE2 has no backreferences or lookaround)")
        return None, _reason("regex_compile_error", f"{where}: {msg}")


def _check_condition(i: int, c, reasons: list[dict]):
    where = f"conditions[{i}]"
    if not isinstance(c, dict):
        reasons.append(_reason("schema_error", f"{where} is not an object"))
        return None
    for k in sorted(CONDITION_KEYS - set(c)):
        reasons.append(_reason("schema_error", f"{where} missing {k!r}"))
    for k in sorted(set(c) - CONDITION_KEYS):
        reasons.append(_reason("schema_error", f"{where} has unknown key {k!r}"))
    f, op, pat, ci = c.get("field"), c.get("op"), c.get("pattern"), c.get("case_insensitive")
    if "field" in c:
        if not isinstance(f, str):
            reasons.append(_reason("schema_error", f"{where}.field is not a string"))
        elif f.lower() in FORBIDDEN_FIELDS:
            reasons.append(_reason("forbidden_field", f"{where}.field {f!r} is not part of the "
                                   f"request (rules must decide before any response exists)"))
        elif f not in FIELDS:
            reasons.append(_reason("unknown_field", f"{where}.field {f!r} not in {list(FIELDS)}"))
    if "op" in c and op not in OPS:
        reasons.append(_reason("unknown_op", f"{where}.op {op!r} not in {list(OPS)}"))
    if "case_insensitive" in c and not isinstance(ci, bool):
        reasons.append(_reason("schema_error", f"{where}.case_insensitive is not a boolean"))
    if "pattern" in c:
        if not isinstance(pat, str):
            reasons.append(_reason("schema_error", f"{where}.pattern is not a string"))
        elif pat == "":
            reasons.append(_reason("empty_pattern", f"{where}.pattern is empty"))
        elif len(pat) > MAX_PATTERN:
            reasons.append(_reason("pattern_too_long",
                                   f"{where}.pattern has {len(pat)} chars (max {MAX_PATTERN})"))
        elif op == "regex" and isinstance(ci, bool):
            compiled, why = _regex_reason(pat, ci, where)
            if why:
                reasons.append(why)
            return compiled
    return None


def validate_rule(index: int, rule, seen_ids: set[str]) -> Validated:
    reasons: list[dict] = []
    compiled: list = []
    if not isinstance(rule, dict):
        return Validated(index, rule, False, [_reason("schema_error", "rule is not an object")])
    for k in REQUIRED:
        if k not in rule:
            reasons.append(_reason("schema_error", f"missing {k!r}"))
    for k in sorted(set(rule) - RULE_KEYS):
        reasons.append(_reason("schema_error", f"unknown key {k!r}"))
    rid = rule.get("rule_id")
    if "rule_id" in rule:
        if not isinstance(rid, str) or not RULE_ID.match(rid):
            reasons.append(_reason("schema_error", f"rule_id {rid!r} does not match r-NNN"))
        elif rid in seen_ids:
            reasons.append(_reason("duplicate_rule_id", f"rule_id {rid!r} already used by an "
                                   f"earlier rule"))
    if "cwe" in rule:
        cwe = rule["cwe"]
        if cwe == "benign":
            reasons.append(_reason("cwe_benign", "a rule detects an attack; 'benign' is meaningless"))
        elif cwe not in CWES:
            reasons.append(_reason("cwe_unknown", f"cwe {cwe!r} not in {list(CWES)}"))
    if "source_request_id" in rule and not (isinstance(rule["source_request_id"], str)
                                            and UUID4.match(rule["source_request_id"])):
        reasons.append(_reason("schema_error", "source_request_id is not a uuid4"))
    if "created_at_log_seq" in rule:
        s = rule["created_at_log_seq"]
        if isinstance(s, bool) or not isinstance(s, int) or s < 1:
            reasons.append(_reason("schema_error", "created_at_log_seq is not an integer >= 1"))
    if "created_match" in rule and not (isinstance(rule["created_match"], str)
                                        and MATCH_ID.match(rule["created_match"])):
        reasons.append(_reason("schema_error", "created_match is not a match_id"))
    if "note" in rule and not isinstance(rule["note"], str):
        reasons.append(_reason("schema_error", "note is not a string"))
    if "conditions" in rule:
        conds = rule["conditions"]
        if not isinstance(conds, list):
            reasons.append(_reason("schema_error", "conditions is not a list"))
        else:
            if not MIN_CONDITIONS <= len(conds) <= MAX_CONDITIONS:
                reasons.append(_reason("condition_count", f"{len(conds)} conditions "
                                       f"(need {MIN_CONDITIONS}-{MAX_CONDITIONS}, all must match)"))
            compiled = [_check_condition(i, c, reasons) for i, c in enumerate(conds)]
    if isinstance(rid, str):
        seen_ids.add(rid)
    return Validated(index, rule, not reasons, reasons, compiled if not reasons else [])


def validate_rules(rules: list) -> list[Validated]:
    """Validate every rule in order. The FIRST use of a rule_id may be valid;
    every later use is a duplicate."""
    seen: set[str] = set()
    return [validate_rule(i, r, seen) for i, r in enumerate(rules)]
