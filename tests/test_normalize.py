"""rules/normalize.py: the ONE normalization (v2), shared by scripted Blue and the
rule engine. v2 is additive over v1, and scripted Blue's verdicts are unchanged."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from blue import signatures  # noqa: E402
from rules import normalize  # noqa: E402

GOLDEN = [REPO / "data" / "golden" / m for m in
          ("scripted-baseline-match", "scripted-baseline-benign-match")]


def v1_forms(value: str) -> list[str]:
    """What Stage 3 (normalization v1) yielded for a field."""
    d = normalize.decode_all(value)
    return [value] if d == value else [value, d]


def test_version():
    assert normalize.NORMALIZATION_VERSION == "2"


@pytest.mark.parametrize("field,value,expected", [
    ("query", "q=x%27%29%29+UNION+SELECT+id",
     ["q=x%27%29%29+UNION+SELECT+id", "q=x'))+UNION+SELECT+id", "q=x')) UNION SELECT id"]),
    ("path", "/ftp/package.json.bak%2500.md",
     ["/ftp/package.json.bak%2500.md", "/ftp/package.json.bak%00.md", "/ftp/package.json.bak\x00.md"]),
    ("query", "q=union+jack+t-shirt", ["q=union+jack+t-shirt", "q=union jack t-shirt"]),
    ("body", '{"a": "b+c"}', ['{"a": "b+c"}', '{"a": "b c"}']),
    ("path", "/a+b", ["/a+b"]),                 # '+' is literal in a path
    ("method", "G%45T", ["G%45T"]),             # method is never decoded
    ("query", "", [""]),
    ("query", None, [""]),
])
def test_forms(field, value, expected):
    assert normalize.field_forms(field, value) == expected


def test_at_most_three_decode_rounds():
    v = "%25252541"  # %252541 -> %2541 -> %41 -> A needs 4 rounds
    forms = normalize.field_forms("path", v)
    assert forms == [v, "%252541", "%2541", "%41"]


def test_content_type_agnostic_json_body_is_url_decoded():
    # Inherited from Stage 3 (contract §6.7 limitation): a literal %27 inside a
    # JSON value also yields a form containing a quote.
    assert "{\"q\": \"it's\"}" in normalize.field_forms("body", '{"q": "it%27s"}')


@pytest.mark.parametrize("value", [
    "q=apple", "q=x%27%29%29+UNION+SELECT", "/ftp/a.bak%2500.md", "%3Cscript%3E", "a+b%2Bc",
    "%25%32%35", "", "plain"])
@pytest.mark.parametrize("field", ["path", "query", "body"])
def test_v2_is_a_superset_of_v1(field, value):
    v2 = normalize.field_forms(field, value)
    assert all(f in v2 for f in v1_forms(value)) and v2[0] == value


def test_decode_all_is_v1_decoding():
    assert normalize.decode_all("%2500") == unquote(unquote("%2500"))


def test_gate_scripted_blue_verdicts_unchanged_on_both_golden_matches():
    # The Stage 5.3 gate: all 31 lines of both golden matches keep their verdict.
    n = 0
    for d in GOLDEN:
        golden = {v["request_id"]: v["verdict"]
                  for v in map(json.loads, (d / "verdicts.jsonl").read_text().splitlines())}
        for line in map(json.loads, (d / "proxy.jsonl").read_text().splitlines()):
            assert signatures.classify(line["path"], line["query"], line["body"]) == \
                golden[line["request_id"]], (d.name, line["request_id"])
            n += 1
    assert n == 31


def test_signatures_haystack_uses_the_shared_forms():
    h = signatures.haystack("/p%2500", "q=a+b", "")
    assert h.split("\n") == (normalize.field_forms("path", "/p%2500")
                             + normalize.field_forms("query", "q=a+b")
                             + normalize.field_forms("body", ""))
