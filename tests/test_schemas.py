"""Contract v0.1 schema tests.

For each schema: the schema itself is valid draft 2020-12, one valid example
passes, and at least two invalid examples fail. Also guards against drift
between config/taxonomy.json and the enums hardcoded in the schemas.
"""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"
CONFIG_DIR = ROOT / "config"

SCHEMA_NAMES = [
    "red_attack",
    "proxy_log",
    "verdict",
    "rule",
    "rules_file",
    "round_record",
]


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMAS = {name: _load(SCHEMA_DIR / f"{name}.schema.json") for name in SCHEMA_NAMES}

# Registry so rules_file.schema.json can $ref rule.schema.json by its $id.
REGISTRY = Registry().with_resources(
    (schema["$id"], Resource.from_contents(schema)) for schema in SCHEMAS.values()
)

TAXONOMY = _load(CONFIG_DIR / "taxonomy.json")
CWE_LABELS = [t for t in TAXONOMY if t != "benign"]


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(SCHEMAS[name], registry=REGISTRY)


# --------------------------------------------------------------------------
# Valid examples (taken from docs/contract.md)
# --------------------------------------------------------------------------

RID = "3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"

RULE = {
    "rule_id": "r-007",
    "label": "CWE-89",
    "field": "body",
    "match_type": "regex",
    "pattern": "'\\s*OR\\s+1=1",
    "created_match": "m001",
    "created_round": 7,
}

VALID = {
    "red_attack": {
        "schema_version": "0.1",
        "match_id": "m001",
        "round": 7,
        "request_id": RID,
        "label": "CWE-89",
        "payload": "' OR 1=1--",
        "endpoint": "/rest/user/login",
        "method": "POST",
        "timestamp": "2026-11-02T22:15:03Z",
    },
    "proxy_log": {
        "timestamp": "2026-11-02T22:15:03.412Z",
        "request_id": RID,
        "method": "POST",
        "path": "/rest/user/login",
        "query": "",
        "body": "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}",
        "status": 200,
    },
    "verdict": {
        "schema_version": "0.1",
        "match_id": "m001",
        "round": 7,
        "request_id": RID,
        "verdict": "CWE-89",
        "reason": "tautology in email field",
    },
    "rule": RULE,
    "rules_file": {"schema_version": "0.1", "rules": [RULE]},
    "round_record": {
        "schema_version": "0.1",
        "match_id": "m001",
        "round": 7,
        "request_id": RID,
        "label": "CWE-89",
        "verdict": "CWE-89",
        "landed": True,
        "detected": True,
        "type_correct": True,
        "replay_blocked": None,
        "benign_fp": None,
    },
}


# --------------------------------------------------------------------------
# Invalid mutations: (description, function(record) -> mutated record)
# --------------------------------------------------------------------------

def _set(key, value):
    def f(r):
        r[key] = value
        return r
    return f


def _drop(key):
    def f(r):
        del r[key]
        return r
    return f


INVALID = {
    "red_attack": [
        ("label not in taxonomy", _set("label", "CWE-78")),
        ("label benign (Red may not label benign)", _set("label", "benign")),
        ("missing request_id", _drop("request_id")),
        ("missing match_id", _drop("match_id")),
        ("request_id not uuid4", _set("request_id", "not-a-uuid")),
        ("timestamp not UTC Z", _set("timestamp", "2026-11-02T22:15:03+08:00")),
        ("extra property", _set("blue_hint", "x")),
        ("wrong schema_version", _set("schema_version", "0.2")),
    ],
    "proxy_log": [
        ("missing request_id (stray traffic)", _drop("request_id")),
        ("empty request_id (header absent)", _set("request_id", "")),
        ("status not integer", _set("status", "200")),
        ("leaks ground-truth label", _set("label", "CWE-89")),
    ],
    "verdict": [
        ("verdict not in taxonomy", _set("verdict", "SQLi")),
        ("missing request_id", _drop("request_id")),
        ("missing schema_version", _drop("schema_version")),
        ("extra property", _set("confidence", 0.9)),
    ],
    "rule": [
        ("label not in taxonomy", _set("label", "CWE-78")),
        ("label benign", _set("label", "benign")),
        ("field not allowed", _set("field", "headers")),
        ("match_type not regex", _set("match_type", "substring")),
        ("missing created_match", _drop("created_match")),
        ("per-rule match_id not allowed", _set("match_id", "m001")),
        ("per-rule schema_version not allowed", _set("schema_version", "0.1")),
    ],
    "rules_file": [
        ("missing schema_version", _drop("schema_version")),
        ("bare array instead of wrapper", lambda r: r["rules"]),
        ("nested rule invalid", lambda r: {**r, "rules": [{**RULE, "label": "benign"}]}),
        ("nested rule missing created_match",
         lambda r: {**r, "rules": [{k: v for k, v in RULE.items() if k != "created_match"}]}),
    ],
    "round_record": [
        ("label not in taxonomy", _set("label", "XSS")),
        ("verdict not in taxonomy", _set("verdict", "malicious")),
        ("missing request_id", _drop("request_id")),
        ("detected null", _set("detected", None)),
        ("replay_blocked string", _set("replay_blocked", "no")),
    ],
}


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_is_valid_draft_2020_12(name):
    assert SCHEMAS[name]["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMAS[name])


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_valid_example_passes(name):
    validator(name).validate(VALID[name])


@pytest.mark.parametrize(
    "name,desc,mutate",
    [(n, d, m) for n, cases in INVALID.items() for d, m in cases],
    ids=[f"{n}:{d}" for n, cases in INVALID.items() for d, _ in cases],
)
def test_invalid_example_fails(name, desc, mutate):
    bad = mutate(copy.deepcopy(VALID[name]))
    assert not validator(name).is_valid(bad), f"{name} accepted invalid record: {desc}"


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_every_schema_has_enough_invalid_cases(name):
    assert len(INVALID[name]) >= 2


def test_round_record_landed_may_be_null_pre_stage3():
    rec = {**VALID["round_record"], "landed": None}
    validator("round_record").validate(rec)


def test_rules_file_empty_rules_is_valid():
    validator("rules_file").validate({"schema_version": "0.1", "rules": []})


def test_record_schemas_require_version_and_match_id():
    for name in ("red_attack", "verdict", "round_record"):
        required = SCHEMAS[name]["required"]
        assert "schema_version" in required and "match_id" in required, name
    assert "schema_version" in SCHEMAS["rules_file"]["required"]


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_additional_properties_false(name):
    assert SCHEMAS[name]["additionalProperties"] is False


# ---- taxonomy drift guards ----

def test_taxonomy_contents():
    assert TAXONOMY == ["CWE-89", "CWE-79", "CWE-22", "benign"]


@pytest.mark.parametrize(
    "name,field",
    [("red_attack", "label"), ("rule", "label"), ("round_record", "label")],
)
def test_label_enums_match_taxonomy_cwes(name, field):
    assert sorted(SCHEMAS[name]["properties"][field]["enum"]) == sorted(CWE_LABELS)


@pytest.mark.parametrize("name", ["verdict", "round_record"])
def test_verdict_enums_match_full_taxonomy(name):
    assert sorted(SCHEMAS[name]["properties"]["verdict"]["enum"]) == sorted(TAXONOMY)


def test_challenge_map_keys_match_taxonomy_cwes():
    cmap = _load(CONFIG_DIR / "challenge_map.json")
    assert sorted(cmap) == sorted(CWE_LABELS)
    assert all(isinstance(v, list) and all(isinstance(s, str) for s in v) for v in cmap.values())
