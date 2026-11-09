"""rules/validator.py: every rejection has its own machine-readable reason."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from rules import validator  # noqa: E402

RULES = json.loads((REPO / "tools" / "stage5_3_rules.json").read_text())["rules"]
EXPECTED = json.loads((REPO / "tools" / "stage5_3_expected.json").read_text())["rules"]
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "rule.schema.json").read_text()))
GOOD = RULES[0]


def codes(rule) -> list[str]:
    [v] = validator.validate_rules([rule])
    return [r["code"] for r in v.reasons]


def test_hand_rules_get_exactly_the_predicted_reasons():
    for v in validator.validate_rules(RULES):
        tag = v.rule["note"].split(" ")[0]
        assert [r["code"] for r in v.reasons] == EXPECTED[tag]["invalid_codes"], tag
        assert v.valid is EXPECTED[tag]["valid"], tag


def test_validator_never_accepts_what_the_schema_rejects():
    for v in validator.validate_rules(RULES):
        if v.valid:
            assert SCHEMA.is_valid(v.rule), v.rule["note"]
        if not SCHEMA.is_valid(v.rule):
            assert not v.valid, v.rule["note"]


def test_first_use_of_an_id_stays_valid_later_uses_are_duplicates():
    vs = validator.validate_rules([GOOD, GOOD, GOOD])
    assert [v.valid for v in vs] == [True, False, False]
    assert all(v.reasons[0]["code"] == "duplicate_rule_id" for v in vs[1:])


@pytest.mark.parametrize("field", ["request_id", "timestamp", "log_seq", "status", "bytes",
                                   "client_addr", "Status"])
def test_forbidden_fields(field):
    r = copy.deepcopy(GOOD)
    r["conditions"][0]["field"] = field
    assert codes(r) == ["forbidden_field"]


@pytest.mark.parametrize("pattern,code", [
    (r"(a)\1", "regex_unsupported_feature"), (r"(?=x)", "regex_unsupported_feature"),
    (r"(?!x)", "regex_unsupported_feature"), (r"(?<=x)y", "regex_unsupported_feature"),
    (r"(?<!x)y", "regex_unsupported_feature"), ("(unclosed", "regex_compile_error"),
    ("[z-a]", "regex_compile_error"), ("a{2,1}", "regex_compile_error"),
])
def test_regex_reasons(pattern, code):
    r = copy.deepcopy(GOOD)
    r["conditions"][0]["pattern"] = pattern
    assert codes(r) == [code]


def test_alternation_inside_one_regex_is_allowed():
    r = copy.deepcopy(GOOD)
    r["conditions"][0]["pattern"] = r"'\s*(or|and)\s+"
    assert codes(r) == []


def test_pattern_limits():
    r = copy.deepcopy(GOOD)
    r["conditions"][0].update(op="contains", pattern="x" * 200)
    assert codes(r) == []
    r["conditions"][0]["pattern"] = "x" * 201
    assert codes(r) == ["pattern_too_long"]


@pytest.mark.parametrize("mutate,code", [
    (lambda r: r.update(extra=1), "schema_error"),
    (lambda r: r.pop("cwe"), "schema_error"),
    (lambda r: r.update(rule_id="R1"), "schema_error"),
    (lambda r: r.update(source_request_id="not-a-uuid"), "schema_error"),
    (lambda r: r.update(created_at_log_seq=0), "schema_error"),
    (lambda r: r.update(created_at_log_seq=True), "schema_error"),
    (lambda r: r.update(created_match="nope"), "schema_error"),
    (lambda r: r.update(conditions="body"), "schema_error"),
    (lambda r: r["conditions"][0].update(case_insensitive="yes"), "schema_error"),
    (lambda r: r["conditions"][0].pop("op"), "schema_error"),
    (lambda r: r["conditions"][0].update(op="regex2"), "unknown_op"),
    (lambda r: r["conditions"][0].update(field="headers"), "unknown_field"),
    (lambda r: r.update(cwe="benign"), "cwe_benign"),
    (lambda r: r.update(cwe="CWE-78"), "cwe_unknown"),
])
def test_specific_reasons(mutate, code):
    r = copy.deepcopy(GOOD)
    mutate(r)
    assert codes(r) == [code]


def test_optional_fields_accepted():
    r = copy.deepcopy(GOOD)
    r["created_match"] = "20261109T021518Z-7d72"
    assert codes(r) == [] and SCHEMA.is_valid(r)


def test_not_an_object():
    [v] = validator.validate_rules(["r-001"])
    assert not v.valid and v.reasons[0]["code"] == "schema_error" and v.rule_id is None


def test_reasons_carry_a_human_detail():
    r = copy.deepcopy(GOOD)
    r["conditions"][0]["field"] = "status"
    [v] = validator.validate_rules([r])
    assert "status" in v.reasons[0]["detail"]
