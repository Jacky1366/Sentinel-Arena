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
    "challenge_snapshot",
    "verdict",
    "rule",
    "rules_file",
    "round_record",
    "landed_fact",
    "match_manifest_v0_1",
    "match_manifest",
    "api_call",
    "prices",
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
SHA = "a" * 64
IMAGE = {"image": "nginx:1.30.6-alpine", "image_id": "sha256:" + "b" * 64,
         "repo_digest": "nginx@sha256:" + "c" * 64}

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
        "log_seq": 7,
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
        "landed_reason": None,
        "newly_solved": ["User Credentials"],
        "detected": True,
        "type_correct": True,
        "detected_reason": None,
        "replay_blocked": None,
        "benign_fp": None,
    },
    "challenge_snapshot": {
        "request_id": RID,
        "before_solved": ["Login Admin"],
        "after_solved": ["Login Admin", "User Credentials"],
        "taken_at": "2026-11-04T01:02:03Z",
    },
    "landed_fact": {
        "schema_version": "0.1",
        "match_id": "m001",
        "round": 4,
        "request_id": RID,
        "label": "CWE-22",
        "landed": True,
        "landed_reason": None,
        "newly_solved": ["Poison Null Byte", "Forgotten Developer Backup"],
    },
    "match_manifest_v0_1": {
        "schema_version": "0.1",
        "match_id": "20261109T153012Z-a1b2",
        "started_at": "2026-11-09T15:30:12.001Z",
        "finished_at": "2026-11-09T15:31:40.512Z",
        "status": "completed",
        "failed_step": None,
        "error": None,
        "judge_version": "0.1.0",
        "blue_engine": "scripted",
        "red_source": {"path": "red/payloads.json", "sha256": SHA},
        "git": {"commit": "0" * 40, "dirty": False},
        "images": {"juice_shop": {**IMAGE, "image": "bkimminich/juice-shop:v20.3.0"},
                   "nginx": IMAGE},
        "artifacts": {"proxy.jsonl": {"sha256": SHA, "bytes": 1234}},
    },
}

LIMITS = {"red": {"max_calls": 60, "max_tokens": 400000, "max_usd": 0.25},
          "blue": {"max_calls": 100, "max_tokens": 300000, "max_usd": 0.25},
          "analyst": {"max_calls": 0, "max_tokens": 0, "max_usd": 0},
          "match": {"max_calls": None, "max_tokens": None, "max_usd": 0.5}}
TOKENS0 = {"input": 0, "cached_input": 0, "cache_write": 0, "output": 0}
VALID["match_manifest"] = {
    **VALID["match_manifest_v0_1"],
    "schema_version": "0.2",
    "models": {"red": None, "blue": None, "analyst": None},
    "budget": {"limits": LIMITS, "stopped_by": None},
    "price_table": {"path": "config/prices.json", "sha256": SHA, "as_of": "2026-11-08"},
    "cost": {"total_usd": 0.0, "failed_attempts_usd": 0.0, "cache_savings_usd": 0.0,
             "attempts": 0, "failed_attempts": 0, "refused": 0, "tokens": TOKENS0,
             "by_agent": {}, "by_model": {}, "lower_bound": False,
             "cached_at_input_price": False, "unpriced_usage": False,
             "prices_verified": None},
}
VALID["api_call"] = {
    "schema_version": "0.1", "match_id": "20261109T153012Z-a1b2",
    "timestamp": "2026-11-09T15:30:13.120Z", "agent": "blue", "provider": "anthropic",
    "model": "claude-haiku-5-5", "round": None, "log_seq_first": 1, "log_seq_last": 20,
    "attempt": 1, "ok": True, "error_type": None, "http_status": 200, "refusal": None,
    "input_tokens": 1200, "cached_input_tokens": 0, "cache_write_tokens": 0,
    "output_tokens": 300, "latency_ms": 812, "prompt_sha256": SHA,
}
VALID["prices"] = {
    "schema_version": "0.1", "as_of": "2026-11-08", "currency": "USD",
    "unit": "per_million_tokens",
    "models": {"m": {"provider": "anthropic", "as_of": "2026-11-08", "source": "x",
                     "verified": False,
                     "tiers": [{"max_prompt_tokens": 100000, "input": 0.1, "cached_input": 0.01,
                                "cache_write": None, "output": 0.5},
                               {"max_prompt_tokens": None, "input": 0.5, "cached_input": None,
                                "cache_write": None, "output": 2.5}]}},
    "placeholders": {},
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
        ("missing log_seq", _drop("log_seq")),
        ("legacy round field not allowed", _set("round", 7)),
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
        ("replay_blocked string", _set("replay_blocked", "no")),
        ("missing landed_reason", _drop("landed_reason")),
        ("missing newly_solved", _drop("newly_solved")),
        ("missing detected_reason", _drop("detected_reason")),
        ("newly_solved not array", _set("newly_solved", "Login Admin")),
        ("landed_reason not in enum", _set("landed_reason", "mystery")),
        ("detected_reason not in enum", _set("detected_reason", "lost")),
        # landed invariant
        ("landed null but reason null", lambda r: {**r, "landed": None, "landed_reason": None}),
        ("landed true but reason set", _set("landed_reason", "already_solved")),
        # detected invariant: detected true requires detected_reason null and bool type_correct
        ("detected true but reason no_verdict", _set("detected_reason", "no_verdict")),
        ("detected true but type_correct null", _set("type_correct", None)),
        # orphan shape: detected null requires reason orphan + type_correct null + verdict null
        ("detected null without orphan shape", _set("detected", None)),
        ("detected null but reason not orphan",
         lambda r: {**r, "detected": None, "type_correct": None, "verdict": None,
                    "detected_reason": "no_verdict"}),
        ("detected null but verdict present",
         lambda r: {**r, "detected": None, "type_correct": None,
                    "detected_reason": "orphan"}),
        # no_verdict shape: detected false, verdict null, type_correct null
        ("no_verdict but verdict present",
         lambda r: {**r, "detected": False, "type_correct": None,
                    "detected_reason": "no_verdict"}),
        # benign-verdict miss: detected false, reason null => verdict must be benign
        ("detected false reason null but verdict is a CWE",
         lambda r: {**r, "detected": False, "type_correct": None}),
    ],
    "challenge_snapshot": [
        ("missing request_id", _drop("request_id")),
        ("request_id not uuid4", _set("request_id", "nope")),
        ("before_solved not array", _set("before_solved", "Login Admin")),
        ("taken_at not UTC Z", _set("taken_at", "2026-11-04T01:02:03+00:00")),
        ("extra property", _set("match_id", "m001")),
    ],
    "landed_fact": [
        ("label not in taxonomy", _set("label", "CWE-78")),
        ("label benign", _set("label", "benign")),
        ("missing match_id", _drop("match_id")),
        ("newly_solved not array", _set("newly_solved", "x")),
        ("landed null but reason null", lambda r: {**r, "landed": None, "landed_reason": None}),
        ("landed true but reason set", _set("landed_reason", "not_measurable")),
        ("extra property", _set("verdict", "CWE-22")),
    ],
    "match_manifest_v0_1": [
        ("status not in enum", _set("status", "running")),
        ("stopped is 0.2 only", _set("status", "stopped")),
        ("0.2 fields not allowed in 0.1", _set("models", {"red": None})),
        ("completed but failed_step set", _set("failed_step", "red")),
        ("completed but error set", _set("error", "boom")),
        ("failed without failed_step",
         lambda r: {**r, "status": "failed", "error": "boom"}),
        ("failed without error",
         lambda r: {**r, "status": "failed", "failed_step": "red"}),
        ("failed_step not a step", lambda r: {**r, "status": "failed",
                                              "failed_step": "lunch", "error": "x"}),
        ("finished_at not UTC Z", _set("finished_at", "2026-11-09T15:31:40+00:00")),
        ("git commit not 40-hex", _set("git", {"commit": "abc", "dirty": False})),
        ("missing artifacts", _drop("artifacts")),
        ("artifacts lists match.json itself",
         _set("artifacts", {"match.json": {"sha256": SHA, "bytes": 1}})),
        ("artifact sha256 malformed",
         _set("artifacts", {"proxy.jsonl": {"sha256": "xyz", "bytes": 1}})),
        ("missing images", _drop("images")),
        ("bad match_id", _set("match_id", "2026-11-09")),
        ("extra property", _set("notes", "x")),
    ],
    "match_manifest": [
        ("schema_version 0.1", _set("schema_version", "0.1")),
        ("missing models", _drop("models")),
        ("missing budget", _drop("budget")),
        ("missing price_table", _drop("price_table")),
        ("missing cost", _drop("cost")),
        ("completed but stopped_by set",
         lambda r: {**r, "budget": {"limits": LIMITS,
                                    "stopped_by": {"scope": "red", "reason": "max_usd"}}}),
        ("stopped without stopped_by", _set("status", "stopped")),
        ("stopped with failed_step",
         lambda r: {**r, "status": "stopped", "failed_step": "red", "error": "x",
                    "budget": {"limits": LIMITS,
                               "stopped_by": {"scope": "red", "reason": "max_usd"}}}),
        ("per-agent cap null",
         lambda r: {**r, "budget": {"limits": {**LIMITS, "blue": {**LIMITS["blue"],
                                                                  "max_usd": None}},
                                    "stopped_by": None}}),
        ("missing analyst caps",
         lambda r: {**r, "budget": {"limits": {k: v for k, v in LIMITS.items()
                                               if k != "analyst"}, "stopped_by": None}}),
        ("stopped_by reason not in enum",
         lambda r: {**r, "status": "stopped",
                    "budget": {"limits": LIMITS,
                               "stopped_by": {"scope": "red", "reason": "tired"}}}),
        ("cost by_agent unknown agent",
         lambda r: {**r, "cost": {**r["cost"], "by_agent": {"judge": {}}}}),
        ("negative total_usd", lambda r: {**r, "cost": {**r["cost"], "total_usd": -1}}),
        ("status not in enum", _set("status", "running")),
        ("extra property", _set("notes", "x")),
    ],
    "api_call": [
        ("ok but error_type set", _set("error_type", "timeout")),
        ("ok with null tokens", _set("output_tokens", None)),
        ("blue with a round", _set("round", 3)),
        ("red with log_seq", lambda r: {**r, "agent": "red", "round": 1}),
        ("analyst with log_seq", _set("agent", "analyst")),
        ("refused without refusal",
         lambda r: {**r, "ok": False, "error_type": "refused", "http_status": None,
                    "input_tokens": 0, "output_tokens": 0, "latency_ms": 0}),
        ("refusal on a sent failure",
         lambda r: {**r, "ok": False, "error_type": "timeout",
                    "refusal": {"scope": "blue", "reason": "max_usd"}}),
        ("refused with tokens",
         lambda r: {**r, "ok": False, "error_type": "refused", "http_status": None,
                    "refusal": {"scope": "blue", "reason": "max_usd"}, "latency_ms": 0}),
        ("null provider", _set("provider", None)),
        ("null provider on a missing_price refusal",
         lambda r: {**r, "ok": False, "error_type": "refused", "http_status": None,
                    "provider": None, "refusal": {"scope": "blue", "reason": "missing_price"},
                    "input_tokens": 0, "cached_input_tokens": 0, "cache_write_tokens": 0,
                    "output_tokens": 0, "latency_ms": 0}),
        ("prompt text stored", _set("prompt", "hello")),
        ("api key field", _set("api_key", "x")),
        ("missing schema_version", _drop("schema_version")),
        ("bad match_id", _set("match_id", "x")),
    ],
    "prices": [
        ("negative price",
         lambda r: {**r, "models": {"m": {**r["models"]["m"], "tiers": [
             {**r["models"]["m"]["tiers"][0], "input": -1}]}}}),
        ("null input price",
         lambda r: {**r, "models": {"m": {**r["models"]["m"], "tiers": [
             {**r["models"]["m"]["tiers"][0], "input": None}]}}}),
        ("no tiers", lambda r: {**r, "models": {"m": {**r["models"]["m"], "tiers": []}}}),
        ("missing verified",
         lambda r: {**r, "models": {"m": {k: v for k, v in r["models"]["m"].items()
                                          if k != "verified"}}}),
        ("unit not per million", _set("unit", "per_token")),
        ("missing placeholders", _drop("placeholders")),
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


def test_round_record_landed_null_requires_reason():
    # landed null is allowed, but only paired with a non-null landed_reason.
    for reason in ("not_measurable", "already_solved", "snapshot_missing"):
        rec = {**VALID["round_record"], "landed": None, "landed_reason": reason}
        validator("round_record").validate(rec)


def test_round_record_snapshot_missing_shape_valid():
    # snapshot_missing: landing null/snapshot_missing, but detection scored normally.
    rec = {**VALID["round_record"], "landed": None, "landed_reason": "snapshot_missing",
           "newly_solved": [], "detected": True, "type_correct": True,
           "detected_reason": None, "verdict": "CWE-89"}
    validator("round_record").validate(rec)


def test_round_record_four_valid_detected_shapes():
    v = validator("round_record")
    base = VALID["round_record"]
    # 1. verdict present, flagged as attack (the base example).
    v.validate(base)
    # 2. verdict present, called benign -> a miss.
    v.validate({**base, "verdict": "benign", "detected": False,
                "type_correct": None, "detected_reason": None})
    # 3. logged request, no verdict.
    v.validate({**base, "verdict": None, "detected": False,
                "type_correct": None, "detected_reason": "no_verdict"})
    # 4. orphan (no proxy line); landed kept for audit but excluded from stats.
    v.validate({**base, "verdict": None, "detected": None,
                "type_correct": None, "detected_reason": "orphan"})


def test_match_manifest_failed_shape_valid():
    for name in ("match_manifest_v0_1", "match_manifest"):
        validator(name).validate({
            **VALID[name], "status": "failed", "failed_step": "blue",
            "error": "ValueError: duplicate verdict"})


def test_match_manifest_stopped_shape_valid():
    validator("match_manifest").validate({
        **VALID["match_manifest"], "status": "stopped",
        "budget": {"limits": LIMITS, "stopped_by": {"scope": "match", "reason": "unpriced_usage"}}})


def test_match_manifest_failed_may_record_stopped_by():
    # A match capped first and then failed later: status failed, the cap is still a fact.
    validator("match_manifest").validate({
        **VALID["match_manifest"], "status": "failed", "failed_step": "blue", "error": "x",
        "budget": {"limits": LIMITS, "stopped_by": {"scope": "red", "reason": "max_calls"}}})


def test_committed_scripted_baseline_validates_by_dispatch():
    import sys
    sys.path.insert(0, str(ROOT))
    import run_match
    m = _load(ROOT / "data" / "golden" / "scripted-baseline-match" / "match.json")
    assert m["schema_version"] == "0.1"
    assert run_match.validate_manifest(m) == []
    assert run_match.validate_manifest({**m, "schema_version": "9.9"}) != []


def test_api_call_refusal_and_failure_shapes_valid():
    v = validator("api_call")
    base = VALID["api_call"]
    v.validate({**base, "ok": False, "error_type": "timeout", "http_status": None,
                "input_tokens": None, "cached_input_tokens": None, "cache_write_tokens": None,
                "output_tokens": None})
    v.validate({**base, "ok": False, "error_type": "refused", "http_status": None,
                "refusal": {"scope": "match", "reason": "max_usd"}, "input_tokens": 0,
                "cached_input_tokens": 0, "cache_write_tokens": 0, "output_tokens": 0,
                "latency_ms": 0})
    v.validate({**base, "ok": False, "error_type": "refused", "http_status": None,
                "refusal": {"scope": "blue", "reason": "missing_price"},
                "input_tokens": 0, "cached_input_tokens": 0, "cache_write_tokens": 0,
                "output_tokens": 0, "latency_ms": 0})
    v.validate({**base, "agent": "red", "round": 4, "log_seq_first": None, "log_seq_last": None})
    v.validate({**base, "agent": "analyst", "log_seq_first": None, "log_seq_last": None})


def test_committed_price_table_is_valid_and_unverified():
    prices = _load(CONFIG_DIR / "prices.json")
    validator("prices").validate(prices)
    for name, entry in {**prices["models"], **prices["placeholders"]}.items():
        assert entry["verified"] is False, name
    assert "GPT-6 Luna" in prices["placeholders"] and "GPT-6 Luna" not in prices["models"]


@pytest.mark.parametrize("match_id,ok", [
    ("m001", True), ("m12345", True), ("20261109T153012Z-a1b2", True),
    ("m01", False), ("20261109T153012Z", False), ("20261109T153012Z-A1B2", False),
    ("20261109T153012-a1b2", False), ("x20261109T153012Z-a1b2", False),
])
def test_match_id_accepts_both_forms(match_id, ok):
    # Contract §0: legacy m+digits, or the run_match.py timestamp form.
    for name in ("red_attack", "verdict", "round_record", "landed_fact", "match_manifest_v0_1",
                 "match_manifest", "api_call"):
        rec = {**VALID[name], "match_id": match_id}
        assert validator(name).is_valid(rec) is ok, (name, match_id)
    rule = {**RULE, "created_match": match_id}
    assert validator("rule").is_valid(rule) is ok, ("rule", match_id)


def test_rules_file_empty_rules_is_valid():
    validator("rules_file").validate({"schema_version": "0.1", "rules": []})


def test_record_schemas_require_version_and_match_id():
    for name in ("red_attack", "verdict", "round_record", "landed_fact", "match_manifest_v0_1",
                 "match_manifest", "api_call"):
        required = SCHEMAS[name]["required"]
        assert "schema_version" in required and "match_id" in required, name
    assert "schema_version" in SCHEMAS["rules_file"]["required"]


def test_measurement_artifacts_have_no_version_or_match_id():
    # Proxy log and challenge snapshot are written outside the Judge/Red/Blue
    # flow; the run directory implies the match, so they omit both fields.
    for name in ("proxy_log", "challenge_snapshot"):
        props = SCHEMAS[name]["properties"]
        assert "schema_version" not in props and "match_id" not in props, name


def test_landed_null_invariant_round_trip():
    # landed null <-> reason non-null, for both schemas that carry the fields.
    for name in ("round_record", "landed_fact"):
        v = validator(name)
        ok = {**VALID[name], "landed": None, "landed_reason": "already_solved"}
        v.validate(ok)
        bad_reason = {**VALID[name], "landed": None, "landed_reason": None}
        assert not v.is_valid(bad_reason), name
        bad_bool = {**VALID[name], "landed": False, "landed_reason": "already_solved"}
        assert not v.is_valid(bad_bool), name


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_additional_properties_false(name):
    assert SCHEMAS[name]["additionalProperties"] is False


# ---- taxonomy drift guards ----

def test_taxonomy_contents():
    assert TAXONOMY == ["CWE-89", "CWE-79", "CWE-22", "benign"]


@pytest.mark.parametrize(
    "name,field",
    [("red_attack", "label"), ("rule", "label"), ("round_record", "label"),
     ("landed_fact", "label")],
)
def test_label_enums_match_taxonomy_cwes(name, field):
    assert sorted(SCHEMAS[name]["properties"][field]["enum"]) == sorted(CWE_LABELS)


def test_verdict_enum_matches_full_taxonomy():
    # Blue's verdict is always one of the four taxonomy values.
    assert sorted(SCHEMAS["verdict"]["properties"]["verdict"]["enum"]) == sorted(TAXONOMY)


def test_round_record_verdict_enum_is_taxonomy_plus_null():
    # The round record also allows null (no-verdict / orphan rounds, contract 6).
    enum = SCHEMAS["round_record"]["properties"]["verdict"]["enum"]
    assert None in enum
    assert sorted(v for v in enum if v is not None) == sorted(TAXONOMY)


def test_challenge_map_keys_match_taxonomy_cwes():
    cmap = _load(CONFIG_DIR / "challenge_map.json")
    assert sorted(cmap) == sorted(CWE_LABELS)
    assert all(isinstance(v, list) and all(isinstance(s, str) for s in v) for v in cmap.values())
