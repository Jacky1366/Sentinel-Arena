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
    "red_attack_v0_1",
    "red_unsent",
    "proxy_log",
    "challenge_snapshot",
    "verdict",
    "verdict_v0_1",
    "rule",
    "rules_file",
    "round_record",
    "round_record_v0_1",
    "landed_fact",
    "match_manifest_v0_1",
    "match_manifest_v0_2",
    "match_manifest_v0_3",
    "match_manifest_v0_4",
    "match_manifest",
    "api_call",
    "prices",
    "benign_set",
    "benign_request",
    "benign_result",
    "benign_result_v0_1",
    "anomaly",
    "rule_result",
    "rule_score",
    "benign_fixture",
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
    "cwe": "CWE-89",
    "conditions": [{"field": "body", "op": "regex", "pattern": "'\\s*OR\\s+1=1",
                    "case_insensitive": True}],
    "source_request_id": "3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c",
    "created_at_log_seq": 7,
    "created_match": "m001",
}

VALID = {
    "red_attack_v0_1": {
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
    "verdict_v0_1": {
        "schema_version": "0.1",
        "match_id": "m001",
        "log_seq": 7,
        "request_id": RID,
        "verdict": "CWE-89",
        "reason": "tautology in email field",
    },
    "rule": RULE,
    "rules_file": {"schema_version": "0.1", "rules": [RULE]},
    "round_record_v0_1": {
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
        "traffic": "red",
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
VALID["match_manifest_v0_2"] = {
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
VALID["match_manifest_v0_3"] = {
    **VALID["match_manifest_v0_2"],
    "schema_version": "0.3",
    "judge_version": "0.2.0",
    "traffic": {"seed": 5202, "seed_source": "cli",
                "benign_set": {"path": "benign/benign_set.json", "sha256": SHA,
                               "set_version": "1"},
                "schedule": ["benign:n01", "red:1", "red:2", "benign:h06"]},
}
BID_MATCH = "20261109T153012Z-a1b2"
VALID["benign_set"] = {
    "schema_version": "0.1", "set_version": "1",
    "entries": [
        {"benign_id": "n01", "category": "normal", "method": "GET",
         "endpoint": "/rest/products/search", "query_params": {"q": "apple"}, "note": "x"},
        {"benign_id": "h06", "category": "hard_negative", "method": "POST",
         "endpoint": "/rest/user/login", "json_body": {"email": "o'brien@example.com"},
         "expected_solves": ["Error Handling"], "requires": "n01", "note": "x"},
    ],
}
VALID["benign_request"] = {
    "schema_version": "0.1", "match_id": BID_MATCH, "request_id": RID, "benign_id": "h06",
    "category": "hard_negative", "expected_solves": ["Error Handling"],
    "sent_at": "2026-11-09T15:30:14.001Z"}
VALID["benign_result_v0_1"] = {
    "schema_version": "0.1", "match_id": BID_MATCH, "request_id": RID, "benign_id": "h06",
    "category": "hard_negative", "verdict": "CWE-89", "false_positive": True,
    "fp_reason": None}
# Stage 5.4: current versions (verdicts / rounds / benign results 0.2, match.json 0.4).
VALID["verdict"] = {
    "schema_version": "0.2", "match_id": "m001", "log_seq": 7, "request_id": RID,
    "verdict": "CWE-89", "source": "ai", "no_verdict_reason": None, "failure_detail": None,
    "rationale": "tautology in email field", "reason": "ai verdict"}
VALID["round_record"] = {
    **{k: v for k, v in VALID["round_record_v0_1"].items()
       if k not in ("replay_blocked", "benign_fp")},
    "schema_version": "0.2", "verdict_source": "ai"}
VALID["benign_result"] = {**VALID["benign_result_v0_1"], "schema_version": "0.2",
                          "verdict_source": "ai"}
VALID["match_manifest_v0_4"] = {**VALID["match_manifest_v0_3"], "schema_version": "0.4",
                                "judge_version": "0.4.0", "blue_params": None}
RED_PARAMS = {
    "provider": "openai", "model": "gpt-6-luna", "round_cap": 10, "prompt_version": "1",
    "system_prompt_sha256": SHA, "sdk": {"package": "openai", "version": "3.41.0"},
    "request": {"max_output_tokens": 2048, "reasoning_effort": "low",
                "output_format": "json_schema", "store": False,
                "prompt_caching": "disabled", "temperature": None, "temperature_note": "x"},
    "feedback_body_chars": 500,
    "guard": {"methods": ["GET", "POST"], "max_path_chars": 2048, "max_body_chars": 4096}}
VALID["match_manifest"] = {**VALID["match_manifest_v0_4"], "schema_version": "0.5",
                           "judge_version": "0.5.0", "red_engine": "scripted",
                           "red_params": None}
BLUE_PARAMS = {
    "provider": "anthropic", "model": "claude-haiku-5-5", "chunk_size": 1,
    "prompt_version": "1", "system_prompt_sha256": SHA,
    "sdk": {"package": "anthropic", "version": "2.3.0"},
    "request": {"max_output_tokens": 256, "thinking": "disabled", "effort": "low",
                "output_format": "json_schema", "temperature": None,
                "temperature_note": "not settable"}}
CLAUDE_MANIFEST = {**VALID["match_manifest"], "blue_engine": "claude",
                   "blue_params": BLUE_PARAMS,
                   "models": {"red": None, "blue": {"provider": "anthropic",
                                                    "model": "claude-haiku-5-5"},
                              "analyst": None}}
AI_RED_MANIFEST = {**VALID["match_manifest"], "red_engine": "ai", "red_params": RED_PARAMS,
                   "red_source": None,
                   "models": {"red": {"provider": "openai", "model": "gpt-6-luna"},
                              "blue": None, "analyst": None}}
VALID["red_attack"] = {
    "schema_version": "0.2", "match_id": "m001", "round": 7, "request_id": RID,
    "label": "CWE-89", "payload": "p", "endpoint": "/rest/user/login", "method": "POST",
    "timestamp": "2026-11-02T22:15:03Z", "source": "ai", "rationale": "login tautology"}
VALID["red_unsent"] = {
    "schema_version": "0.1", "match_id": BID_MATCH, "round": 3, "kind": "guard_block",
    "reason": "scope_violation", "detail": "path carries a scheme",
    "proposed": {"method": "GET", "path": "/x", "body": "", "label": "CWE-22",
                 "rationale": "traversal"},
    "timestamp": "2026-11-09T15:30:14.001Z"}
VALID["anomaly"] = {
    "schema_version": "0.1", "match_id": BID_MATCH, "kind": "benign_solved_challenge",
    "request_id": RID, "detail": {"benign_id": "n04", "newly_solved": ["Score Board"],
                                  "expected_solves": []}}
VALID["rule_result"] = {
    "schema_version": "0.1", "match_id": "20261109T021518Z-7d72", "rule_index": 0,
    "rule_id": "r-001", "valid": True, "invalid_reasons": [], "cwe": "CWE-89",
    "source_request_id": RID, "replay_fires": True, "replay_reason": None,
    "source_label": "CWE-89", "cwe_matches_source": True, "fixture_sha256": SHA,
    "fixture_fires": 0, "fixture_benign_ids": []}
VALID["rule_score"] = {
    "schema_version": "0.1", "match_id": "20261109T021518Z-7d72", "match_json_sha256": SHA,
    "rules": {"path": "tools/stage5_3_rules.json", "sha256": SHA, "count": 33},
    "fixture": {"path": "benign/fixture_v1.jsonl", "version": "1", "sha256": SHA, "entries": 17},
    "judge_version": "0.3.0", "normalization_version": "2", "re2_version": "1.1.20251105",
    "scored_at": "2026-11-09T00:00:00.000Z",
    "summary": {"valid": 18, "invalid": 15, "replay_fires": 13, "replay_misses": 3,
                "replay_null": 17, "rules_with_fixture_hits": 6, "anomalies": 1}}
VALID["benign_fixture"] = {
    "benign_id": "h06", "category": "hard_negative", "method": "POST",
    "path": "/rest/user/login", "query": "",
    "body": "{\"email\": \"sean.o'brien@example.com\", \"password\": \"shamrock\"}"}
VALID["api_call"] = {
    "schema_version": "0.1", "match_id": "20261109T153012Z-a1b2",
    "timestamp": "2026-11-09T15:30:13.120Z", "agent": "blue", "provider": "anthropic",
    "model": "claude-haiku-5-5", "round": None, "log_seq_first": 1, "log_seq_last": 20,
    "attempt": 1, "ok": True, "error_type": None, "http_status": 200, "refusal": None,
    "stop_reason": "end_turn", "input_tokens": 1200, "cached_input_tokens": 0, "cache_write_tokens": 0,
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
    "red_attack_v0_1": [
        ("label not in taxonomy", _set("label", "CWE-78")),
        ("label benign (Red may not label benign)", _set("label", "benign")),
        ("missing request_id", _drop("request_id")),
        ("source is 0.2 only", _set("source", "scripted")),
        ("wrong schema_version", _set("schema_version", "0.2")),
    ],
    "red_attack": [
        ("label not in taxonomy", _set("label", "CWE-78")),
        ("label benign (Red may not label benign)", _set("label", "benign")),
        ("missing source", _drop("source")),
        ("missing rationale", _drop("rationale")),
        ("ai without rationale", lambda r: {**r, "source": "ai", "rationale": None}),
        ("scripted with a rationale", _set("source", "scripted")),
        ("source not in enum", _set("source", "manual")),
        ("rationale over 500 chars", _set("rationale", "x" * 501)),
        ("schema_version 0.1", _set("schema_version", "0.1")),
        ("extra property", _set("blue_hint", "x")),
    ],
    "red_unsent": [
        ("kind not in enum", _set("kind", "mystery")),
        ("guard_block reason from brain set",
         lambda r: {**r, "kind": "guard_block", "reason": "refusal"}),
        ("guard_block without proposed", _set("proposed", None)),
        ("brain_failure with proposed",
         lambda r: {**r, "kind": "brain_failure", "reason": "invalid_json"}),
        ("instrument_failure reason from guard set",
         lambda r: {**r, "kind": "instrument_failure", "reason": "above_root",
                    "proposed": None}),
        ("reason not in any enum", _set("reason", "nope")),
        ("missing timestamp", _drop("timestamp")),
        ("extra property", _set("sent", True)),
    ],
    "proxy_log": [
        ("missing request_id (stray traffic)", _drop("request_id")),
        ("empty request_id (header absent)", _set("request_id", "")),
        ("status not integer", _set("status", "200")),
        ("leaks ground-truth label", _set("label", "CWE-89")),
    ],
    "verdict": [
        ("verdict not in taxonomy", _set("verdict", "SQLi")),
        ("schema_version 0.1", _set("schema_version", "0.1")),
        ("missing source", _drop("source")),
        ("missing no_verdict_reason", _drop("no_verdict_reason")),
        ("missing failure_detail", _drop("failure_detail")),
        ("source rule arrives in 5.5", _set("source", "rule")),
        ("verdict with a no_verdict_reason", _set("no_verdict_reason", "no_verdict")),
        ("verdict with a failure_detail", _set("failure_detail", "invalid_json")),
        ("verdict without source", _set("source", None)),
        ("null verdict with a source",
         lambda r: {k: v for k, v in {**r, "verdict": None, "no_verdict_reason": "no_verdict",
                                      "failure_detail": "invalid_json"}.items()
                    if k != "rationale"}),
        ("null verdict without reason",
         lambda r: {k: v for k, v in {**r, "verdict": None, "source": None,
                                      "failure_detail": "invalid_json"}.items()
                    if k != "rationale"}),
        ("null verdict without detail",
         lambda r: {k: v for k, v in {**r, "verdict": None, "source": None,
                                      "no_verdict_reason": "no_verdict"}.items()
                    if k != "rationale"}),
        ("no_verdict with an instrument detail",
         lambda r: {k: v for k, v in {**r, "verdict": None, "source": None,
                                      "no_verdict_reason": "no_verdict",
                                      "failure_detail": "api_error"}.items()
                    if k != "rationale"}),
        ("instrument_failure with a brain detail",
         lambda r: {k: v for k, v in {**r, "verdict": None, "source": None,
                                      "no_verdict_reason": "instrument_failure",
                                      "failure_detail": "model_refusal"}.items()
                    if k != "rationale"}),
        ("rationale on a row without a verdict",
         lambda r: {**r, "verdict": None, "source": None, "no_verdict_reason": "no_verdict",
                    "failure_detail": "invalid_json"}),
        ("rationale over 200 chars", _set("rationale", "x" * 201)),
        ("signature verdict with a rationale", _set("source", "signature")),
        ("failure_detail not in enum",
         lambda r: {k: v for k, v in {**r, "verdict": None, "source": None,
                                      "no_verdict_reason": "no_verdict",
                                      "failure_detail": "bored"}.items()
                    if k != "rationale"}),
        ("missing request_id", _drop("request_id")),
        ("missing schema_version", _drop("schema_version")),
        ("missing log_seq", _drop("log_seq")),
        ("legacy round field not allowed", _set("round", 7)),
        ("extra property", _set("confidence", 0.9)),
    ],
    "verdict_v0_1": [
        ("verdict not in taxonomy", _set("verdict", "SQLi")),
        ("verdict null is 0.2 only", _set("verdict", None)),
        ("source is 0.2 only", _set("source", "signature")),
        ("missing reason", _drop("reason")),
        ("schema_version 0.2", _set("schema_version", "0.2")),
    ],
    "rule": [
        ("cwe not in taxonomy", _set("cwe", "CWE-78")),
        ("cwe benign", _set("cwe", "benign")),
        ("Stage 0 label key", lambda r: {**r, "label": "CWE-89"}),
        ("field not allowed",
         lambda r: {**r, "conditions": [{**r["conditions"][0], "field": "headers"}]}),
        ("forbidden field status",
         lambda r: {**r, "conditions": [{**r["conditions"][0], "field": "status"}]}),
        ("op not allowed",
         lambda r: {**r, "conditions": [{**r["conditions"][0], "op": "startswith"}]}),
        ("empty pattern",
         lambda r: {**r, "conditions": [{**r["conditions"][0], "pattern": ""}]}),
        ("pattern over 200 chars",
         lambda r: {**r, "conditions": [{**r["conditions"][0], "pattern": "x" * 201}]}),
        ("no conditions", _set("conditions", [])),
        ("four conditions", lambda r: {**r, "conditions": r["conditions"] * 4}),
        ("missing source_request_id", _drop("source_request_id")),
        ("source_request_id not uuid4", _set("source_request_id", "abc")),
        ("missing created_at_log_seq", _drop("created_at_log_seq")),
        ("created_round is Stage 0", _set("created_round", 7)),
        ("per-rule match_id not allowed", _set("match_id", "m001")),
        ("per-rule schema_version not allowed", _set("schema_version", "0.1")),
    ],
    "rules_file": [
        ("missing schema_version", _drop("schema_version")),
        ("bare array instead of wrapper", lambda r: r["rules"]),
        ("nested rule invalid", lambda r: {**r, "rules": [{**RULE, "cwe": "benign"}]}),
        ("nested rule missing source_request_id",
         lambda r: {**r, "rules": [{k: v for k, v in RULE.items()
                                    if k != "source_request_id"}]}),
    ],
    "round_record": [
        ("label not in taxonomy", _set("label", "XSS")),
        ("verdict not in taxonomy", _set("verdict", "malicious")),
        ("missing request_id", _drop("request_id")),
        ("replay_blocked removed in 0.2", _set("replay_blocked", None)),
        ("benign_fp removed in 0.2", _set("benign_fp", None)),
        ("schema_version 0.1", _set("schema_version", "0.1")),
        ("missing verdict_source", _drop("verdict_source")),
        ("verdict_source null with a verdict", _set("verdict_source", None)),
        ("verdict_source not in enum", _set("verdict_source", "rule")),
        ("instrument_failure with detected false",
         lambda r: {**r, "detected": False, "type_correct": None, "verdict": None,
                    "verdict_source": None, "detected_reason": "instrument_failure"}),
        ("instrument_failure with a verdict",
         lambda r: {**r, "detected": None, "type_correct": None,
                    "detected_reason": "instrument_failure"}),
        ("verdict_source set on an orphan",
         lambda r: {**r, "detected": None, "type_correct": None, "verdict": None,
                    "detected_reason": "orphan"}),
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
    "round_record_v0_1": [
        ("label not in taxonomy", _set("label", "XSS")),
        ("instrument_failure is 0.2 only",
         lambda r: {**r, "detected": None, "type_correct": None, "verdict": None,
                    "detected_reason": "instrument_failure"}),
        ("verdict_source is 0.2 only", _set("verdict_source", "ai")),
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
    "match_manifest_v0_2": [
        ("schema_version 0.3", _set("schema_version", "0.3")),
        ("traffic is 0.3 only", _set("traffic", {})),
        ("missing cost", _drop("cost")),
    ],
    "match_manifest_v0_3": [
        ("schema_version 0.4", _set("schema_version", "0.4")),
        ("blue_params is 0.4 only", _set("blue_params", None)),
        ("claude engine is 0.4 only", _set("blue_engine", "claude")),
        ("missing traffic", _drop("traffic")),
    ],
    "match_manifest_v0_4": [
        ("schema_version 0.5", _set("schema_version", "0.5")),
        ("red_engine is 0.5 only", _set("red_engine", "scripted")),
        ("red_params is 0.5 only", _set("red_params", None)),
    ],
    "match_manifest": [
        ("schema_version 0.4", _set("schema_version", "0.4")),
        ("missing red_engine", _drop("red_engine")),
        ("missing red_params", _drop("red_params")),
        ("schema_version 0.3", _set("schema_version", "0.3")),
        ("missing blue_params", _drop("blue_params")),
        ("scripted with blue_params", _set("blue_params", BLUE_PARAMS)),
        ("scripted with a blue model",
         lambda r: {**r, "models": {**r["models"],
                                    "blue": {"provider": "anthropic", "model": "x"}}}),
        ("claude without blue_params", _set("blue_engine", "claude")),
        ("claude without a blue model",
         lambda r: {**r, "blue_engine": "claude", "blue_params": BLUE_PARAMS}),
        ("blue_params request with a sampling knob",
         lambda r: {**CLAUDE_MANIFEST, "blue_params": {
             **BLUE_PARAMS, "request": {**BLUE_PARAMS["request"], "top_p": 1}}}),
        ("blue_params effort not in enum",
         lambda r: {**CLAUDE_MANIFEST, "blue_params": {
             **BLUE_PARAMS, "request": {**BLUE_PARAMS["request"], "effort": "extreme"}}}),
        ("blue_params without prompt sha256",
         lambda r: {**CLAUDE_MANIFEST, "blue_params": {
             k: v for k, v in BLUE_PARAMS.items() if k != "system_prompt_sha256"}}),
        ("blue engine not in enum", _set("blue_engine", "gpt")),
        ("missing traffic", _drop("traffic")),
        ("failed_step red renamed to traffic",
         lambda r: {**r, "status": "failed", "failed_step": "red", "error": "x"}),
        ("seed negative", lambda r: {**r, "traffic": {**r["traffic"], "seed": -1}}),
        ("seed above 2^32-1", lambda r: {**r, "traffic": {**r["traffic"], "seed": 2**32}}),
        ("seed_source not in enum",
         lambda r: {**r, "traffic": {**r["traffic"], "seed_source": "guess"}}),
        ("schedule slot malformed",
         lambda r: {**r, "traffic": {**r["traffic"], "schedule": ["red:0"]}}),
        ("benign_set without sha256",
         lambda r: {**r, "traffic": {**r["traffic"], "benign_set": {"path": "x",
                                                                    "set_version": "1"}}}),
        ("missing models", _drop("models")),
        ("missing budget", _drop("budget")),
        ("missing price_table", _drop("price_table")),
        ("missing cost", _drop("cost")),
        ("completed but stopped_by set",
         lambda r: {**r, "budget": {"limits": LIMITS,
                                    "stopped_by": {"scope": "red", "reason": "max_usd"}}}),
        ("stopped without stopped_by", _set("status", "stopped")),
        ("stopped with failed_step",
         lambda r: {**r, "status": "stopped", "failed_step": "traffic", "error": "x",
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
    "benign_set": [
        ("hard negative with an n id",
         lambda r: {**r, "entries": [{**r["entries"][0], "category": "hard_negative"}]}),
        ("bad benign_id", lambda r: {**r, "entries": [{**r["entries"][0], "benign_id": "x1"}]}),
        ("entry without note", lambda r: {**r, "entries": [
            {k: v for k, v in r["entries"][0].items() if k != "note"}]}),
        ("expected_solves not a list", lambda r: {**r, "entries": [
            {**r["entries"][1], "expected_solves": "Error Handling"}]}),
        ("label field (benign is not Red)", lambda r: {**r, "entries": [
            {**r["entries"][0], "label": "benign"}]}),
        ("empty entries", _set("entries", [])),
    ],
    "benign_request": [
        ("missing request_id", _drop("request_id")),
        ("missing expected_solves", _drop("expected_solves")),
        ("category not in enum", _set("category", "attack")),
        ("carries a label", _set("label", "benign")),
        ("sent_at not UTC Z", _set("sent_at", "2026-11-09T15:30:14+00:00")),
    ],
    "benign_result_v0_1": [
        ("CWE verdict but not FP", _set("false_positive", False)),
        ("instrument_failure is 0.2 only",
         lambda r: {**r, "verdict": None, "false_positive": None,
                    "fp_reason": "instrument_failure"}),
        ("verdict_source is 0.2 only", _set("verdict_source", "ai")),
    ],
    "benign_result": [
        ("schema_version 0.1", _set("schema_version", "0.1")),
        ("missing verdict_source", _drop("verdict_source")),
        ("verdict_source null with a verdict", _set("verdict_source", None)),
        ("instrument_failure with a verdict",
         lambda r: {**r, "false_positive": None, "fp_reason": "instrument_failure"}),
        ("verdict_source on a no-verdict row",
         lambda r: {**r, "verdict": None, "false_positive": None,
                    "fp_reason": "instrument_failure"}),
        ("CWE verdict but not FP", _set("false_positive", False)),
        ("benign verdict but FP", lambda r: {**r, "verdict": "benign"}),
        ("no_verdict with a boolean",
         lambda r: {**r, "verdict": None, "fp_reason": "no_verdict"}),
        ("orphan with a verdict", _set("fp_reason", "orphan")),
        ("reason not in enum",
         lambda r: {**r, "verdict": None, "false_positive": None, "fp_reason": "skipped"}),
        ("verdict null without reason",
         lambda r: {**r, "verdict": None, "false_positive": None}),
    ],
    "anomaly": [
        ("kind not in enum", _set("kind", "spooky")),
        ("benign_solved without newly_solved",
         _set("detail", {"benign_id": "n04", "expected_solves": []})),
        ("unmatched_verdict without log_seq",
         lambda r: {**r, "kind": "unmatched_verdict", "detail": {"verdict": "benign"}}),
        ("missing match_id", _drop("match_id")),
    ],
    "rule_result": [
        ("valid with reasons", _set("invalid_reasons", [{"code": "schema_error", "detail": "x"}])),
        ("invalid but replayed", lambda r: {**r, "valid": False, "cwe": None,
            "invalid_reasons": [{"code": "schema_error", "detail": "x"}]}),
        ("reason code unknown", lambda r: {**r, "valid": False, "cwe": None,
            "invalid_reasons": [{"code": "bad", "detail": "x"}], "replay_fires": None,
            "replay_reason": "rule_invalid", "source_label": None, "cwe_matches_source": None,
            "fixture_fires": None}),
        ("replay null without reason", _set("replay_fires", None)),
        ("reason set but replay boolean", _set("replay_reason", "source_orphan")),
        ("valid rule with null fixture count", _set("fixture_fires", None)),
        ("source_label benign", _set("source_label", "benign")),
    ],
    "rule_score": [
        ("missing normalization_version", _drop("normalization_version")),
        ("judge_version not semver", _set("judge_version", "3")),
        ("missing summary", _drop("summary")),
    ],
    "benign_fixture": [
        ("carries request_id", _set("request_id", RID)),
        ("carries status", _set("status", 500)),
        ("bad benign_id", _set("benign_id", "x9")),
    ],
    "api_call": [
        ("ok but error_type set", _set("error_type", "timeout")),
        ("missing stop_reason", _drop("stop_reason")),
        ("stop_reason on a failed call",
         lambda r: {**r, "ok": False, "error_type": "timeout", "http_status": None,
                    "input_tokens": None, "cached_input_tokens": None,
                    "cache_write_tokens": None, "output_tokens": None}),
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
    for name in ("round_record", "round_record_v0_1"):
        for reason in ("not_measurable", "already_solved", "snapshot_missing"):
            rec = {**VALID[name], "landed": None, "landed_reason": reason}
            validator(name).validate(rec)


def test_round_record_snapshot_missing_shape_valid():
    # snapshot_missing: landing null/snapshot_missing, but detection scored normally.
    rec = {**VALID["round_record"], "landed": None, "landed_reason": "snapshot_missing",
           "newly_solved": [], "detected": True, "type_correct": True,
           "detected_reason": None, "verdict": "CWE-89"}
    validator("round_record").validate(rec)


def test_round_record_four_valid_detected_shapes():
    for name, extra in (("round_record_v0_1", {}), ("round_record", {"verdict_source": None})):
        v = validator(name)
        base = VALID[name]
        # 1. verdict present, flagged as attack (the base example).
        v.validate(base)
        # 2. verdict present, called benign -> a miss.
        v.validate({**base, "verdict": "benign", "detected": False,
                    "type_correct": None, "detected_reason": None})
        # 3. logged request, no verdict.
        v.validate({**base, **extra, "verdict": None, "detected": False,
                    "type_correct": None, "detected_reason": "no_verdict"})
        # 4. orphan (no proxy line); landed kept for audit but excluded from stats.
        v.validate({**base, **extra, "verdict": None, "detected": None,
                    "type_correct": None, "detected_reason": "orphan"})


def test_round_record_instrument_failure_shape_valid():
    # Stage 5.4 (D13): shaped like an orphan, excluded from detection stats.
    validator("round_record").validate({
        **VALID["round_record"], "verdict": None, "verdict_source": None, "detected": None,
        "type_correct": None, "detected_reason": "instrument_failure"})
    validator("round_record").validate({**VALID["round_record"], "verdict_source": "signature"})


def test_match_manifest_failed_shape_valid():
    for name in ("match_manifest_v0_1", "match_manifest_v0_2", "match_manifest_v0_3",
                 "match_manifest_v0_4", "match_manifest"):
        validator(name).validate({
            **VALID[name], "status": "failed", "failed_step": "blue",
            "error": "ValueError: duplicate verdict"})


def test_match_manifest_stopped_shape_valid():
    validator("match_manifest").validate({
        **VALID["match_manifest"], "status": "stopped",
        "budget": {"limits": LIMITS, "stopped_by": {"scope": "match", "reason": "unpriced_usage"}}})
    validator("match_manifest").validate({
        **CLAUDE_MANIFEST, "status": "stopped",
        "budget": {"limits": LIMITS, "stopped_by": {"scope": "blue",
                                                    "reason": "price_unverified"}}})


def test_match_manifest_claude_shape_valid():
    v = validator("match_manifest")
    v.validate(CLAUDE_MANIFEST)
    v.validate({**CLAUDE_MANIFEST, "blue_params": {**BLUE_PARAMS, "sdk": None}})  # fake


def test_match_manifest_ai_red_shape_valid():
    v = validator("match_manifest")
    v.validate(AI_RED_MANIFEST)
    v.validate({**AI_RED_MANIFEST, "red_params": {**RED_PARAMS, "sdk": None}})  # fake
    # scripted Red must not carry red_params or a red model; AI Red must not carry a payload file
    assert not v.is_valid({**VALID["match_manifest"], "red_params": RED_PARAMS})
    assert not v.is_valid({**AI_RED_MANIFEST, "red_source": {"path": "x", "sha256": SHA}})
    assert not v.is_valid({**AI_RED_MANIFEST, "red_params": None})
    both = {**AI_RED_MANIFEST, "blue_engine": "claude", "blue_params": BLUE_PARAMS,
            "models": {"red": {"provider": "openai", "model": "gpt-6-luna"},
                       "blue": {"provider": "anthropic", "model": "claude-haiku-5-5"},
                       "analyst": None}}
    v.validate(both)  # AI Red + AI Blue together


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
                "stop_reason": None, "input_tokens": None, "cached_input_tokens": None, "cache_write_tokens": None,
                "output_tokens": None})
    v.validate({**base, "ok": False, "error_type": "refused", "http_status": None,
                "refusal": {"scope": "match", "reason": "max_usd"}, "stop_reason": None,
                "input_tokens": 0,
                "cached_input_tokens": 0, "cache_write_tokens": 0, "output_tokens": 0,
                "latency_ms": 0})
    v.validate({**base, "ok": False, "error_type": "refused", "http_status": None,
                "refusal": {"scope": "blue", "reason": "missing_price"}, "stop_reason": None,
                "input_tokens": 0, "cached_input_tokens": 0, "cache_write_tokens": 0,
                "output_tokens": 0, "latency_ms": 0})
    v.validate({**base, "ok": False, "error_type": "refused", "http_status": None,
                "refusal": {"scope": "blue", "reason": "price_unverified"}, "stop_reason": None,
                "input_tokens": 0, "cached_input_tokens": 0, "cache_write_tokens": 0,
                "output_tokens": 0, "latency_ms": 0})
    # a safety refusal by the model is an ok reply with stop_reason "refusal"
    v.validate({**base, "stop_reason": "refusal"})
    v.validate({**base, "agent": "red", "round": 4, "log_seq_first": None, "log_seq_last": None})
    v.validate({**base, "agent": "analyst", "log_seq_first": None, "log_seq_last": None})


# Only the designer verifies a price (Stage 5.4: Haiku 5.5, Sonnet 5.5; Stage 5.6:
# gpt-6-luna — all checked 2026-11-12).
DESIGNER_VERIFIED = {"claude-haiku-5-5", "claude-sonnet-5-5", "gpt-6-luna"}


def test_committed_price_table_is_valid_and_only_designer_verified():
    prices = _load(CONFIG_DIR / "prices.json")
    validator("prices").validate(prices)
    for name, entry in {**prices["models"], **prices["placeholders"]}.items():
        assert entry["verified"] is (name in DESIGNER_VERIFIED), name
        if entry["verified"]:  # a verified entry names who verified it, when, and where
            assert entry["source"].startswith("designer-verified 2026-11-12 against "), name
    # Stage 5.6: luna is priced and designer-verified; placeholders is empty.
    assert prices["placeholders"] == {}
    luna = prices["models"]["gpt-6-luna"]
    assert [t["max_prompt_tokens"] for t in luna["tiers"]] == [272000, None]
    assert luna["tiers"][0]["cache_write"] == 0.125 and luna["tiers"][1]["output"] == 0.75


@pytest.mark.parametrize("match_id,ok", [
    ("m001", True), ("m12345", True), ("20261109T153012Z-a1b2", True),
    ("m01", False), ("20261109T153012Z", False), ("20261109T153012Z-A1B2", False),
    ("20261109T153012-a1b2", False), ("x20261109T153012Z-a1b2", False),
])
def test_match_id_accepts_both_forms(match_id, ok):
    # Contract §0: legacy m+digits, or the run_match.py timestamp form.
    for name in ("red_attack", "red_attack_v0_1", "red_unsent", "verdict", "verdict_v0_1",
                 "round_record", "round_record_v0_1", "landed_fact", "match_manifest_v0_1",
                 "match_manifest_v0_2", "match_manifest_v0_3", "match_manifest_v0_4",
                 "match_manifest", "api_call", "benign_request", "benign_result",
                 "benign_result_v0_1", "anomaly"):
        rec = {**VALID[name], "match_id": match_id}
        assert validator(name).is_valid(rec) is ok, (name, match_id)
    rule = {**RULE, "created_match": match_id}
    assert validator("rule").is_valid(rule) is ok, ("rule", match_id)


def test_rules_file_empty_rules_is_valid():
    validator("rules_file").validate({"schema_version": "0.1", "rules": []})


def test_record_schemas_require_version_and_match_id():
    for name in ("red_attack", "red_attack_v0_1", "red_unsent", "verdict", "verdict_v0_1",
                 "round_record", "round_record_v0_1", "landed_fact", "match_manifest_v0_1",
                 "match_manifest_v0_2", "match_manifest_v0_3", "match_manifest_v0_4",
                 "match_manifest", "api_call", "benign_request", "benign_result",
                 "benign_result_v0_1", "anomaly"):
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
    [("red_attack", "label"), ("rule", "cwe"), ("round_record", "label"),
     ("landed_fact", "label")],
)
def test_label_enums_match_taxonomy_cwes(name, field):
    assert sorted(SCHEMAS[name]["properties"][field]["enum"]) == sorted(CWE_LABELS)


def test_verdict_enum_matches_full_taxonomy():
    # Blue's verdict is one of the four taxonomy values (or null in 0.2: no verdict).
    assert sorted(SCHEMAS["verdict_v0_1"]["properties"]["verdict"]["enum"]) == sorted(TAXONOMY)
    enum = SCHEMAS["verdict"]["properties"]["verdict"]["enum"]
    assert None in enum and sorted(x for x in enum if x is not None) == sorted(TAXONOMY)


def test_verdict_0_2_shapes_valid():
    v = validator("verdict")
    base = {k: x for k, x in VALID["verdict"].items() if k != "rationale"}
    v.validate(base)
    v.validate({**base, "source": "signature", "reason": "signature matched"})
    for reason, details in (("no_verdict", ("invalid_json", "invalid_shape", "missing_index",
                                            "duplicate_index", "unknown_index",
                                            "unknown_label", "model_refusal", "max_tokens")),
                            ("instrument_failure", ("refused_by_body", "api_error"))):
        for d in details:
            v.validate({**base, "verdict": None, "source": None, "no_verdict_reason": reason,
                        "failure_detail": d})


def test_round_record_verdict_enum_is_taxonomy_plus_null():
    # The round record also allows null (no-verdict / orphan rounds, contract 6).
    enum = SCHEMAS["round_record"]["properties"]["verdict"]["enum"]
    assert None in enum
    assert sorted(v for v in enum if v is not None) == sorted(TAXONOMY)


def test_challenge_map_keys_match_taxonomy_cwes():
    cmap = _load(CONFIG_DIR / "challenge_map.json")
    assert sorted(cmap) == sorted(CWE_LABELS)
    assert all(isinstance(v, list) and all(isinstance(s, str) for s in v) for v in cmap.values())


def test_manifest_dispatch_covers_every_version():
    import sys
    sys.path.insert(0, str(ROOT))
    import run_match
    assert set(run_match.MANIFEST_SCHEMAS) == {"0.1", "0.2", "0.3", "0.4", "0.5"}
    assert run_match.MANIFEST_VERSION == "0.5"
    for name in ("match_manifest_v0_1", "match_manifest_v0_2", "match_manifest_v0_3",
                 "match_manifest_v0_4", "match_manifest"):
        assert run_match.validate_manifest(VALID[name]) == [], name


def test_snapshot_rows_mark_their_traffic():
    v = validator("challenge_snapshot")
    v.validate({**VALID["challenge_snapshot"], "traffic": "benign"})
    assert not v.is_valid({**VALID["challenge_snapshot"], "traffic": "probe"})
    bare = {k: x for k, x in VALID["challenge_snapshot"].items() if k != "traffic"}
    assert not v.is_valid(bare)  # new rows must say which traffic they belong to


def test_benign_result_four_shapes():
    for name, extra in (("benign_result_v0_1", {}), ("benign_result", {"verdict_source": None})):
        v = validator(name)
        base = VALID[name]
        v.validate(base)  # CWE verdict -> FP
        v.validate({**base, "verdict": "benign", "false_positive": False})
        for reason in ("no_verdict", "orphan"):
            v.validate({**base, **extra, "verdict": None, "false_positive": None,
                        "fp_reason": reason})
    validator("benign_result").validate({**VALID["benign_result"], "verdict": None,
                                         "verdict_source": None, "false_positive": None,
                                         "fp_reason": "instrument_failure"})


def test_anomaly_kinds_valid():
    v = validator("anomaly")
    base = VALID["anomaly"]
    v.validate({**base, "kind": "unmatched_verdict",
                "detail": {"log_seq": 3, "verdict": "CWE-89"}})
    v.validate({**base, "kind": "unmatched_verdict",  # a 0.2 row without a verdict
                "detail": {"log_seq": 3, "verdict": None}})
    v.validate({**base, "kind": "benign_snapshot_missing", "detail": {"benign_id": "n04"}})


def test_benign_verdict_enums_match_taxonomy():
    enum = SCHEMAS["benign_result"]["properties"]["verdict"]["enum"]
    assert sorted(x for x in enum if x is not None) == sorted(TAXONOMY)


def test_committed_benign_baseline_validates_and_is_clean():
    import sys
    sys.path.insert(0, str(ROOT))
    import run_match
    d = ROOT / "data" / "golden" / "scripted-baseline-benign-match"
    m = _load(d / "match.json")
    assert m["schema_version"] == "0.3" and m["status"] == "completed"
    assert m["git"]["dirty"] is False and m["traffic"]["seed"] == 5202
    assert run_match.validate_manifest(m) == []
    a = run_match.artifact_hashes(d)
    a.pop("README.md")
    assert a == m["artifacts"]
    for name, schema in (("benign_requests.jsonl", "benign_request"),
                         ("benign_results.jsonl", "benign_result_v0_1"),
                         ("verdicts.jsonl", "verdict_v0_1"),
                         ("rounds.jsonl", "round_record_v0_1"),
                         ("challenge_snapshots.jsonl", "challenge_snapshot")):
        for line in (d / name).read_text().splitlines():
            validator(schema).validate(json.loads(line))
    assert (d / "anomalies.jsonl").read_text() == ""


def test_committed_claude_blue_first_match_validates_and_is_clean():
    # Stage 5.4 Gate 2, run 1: the first AI Blue reference run (Haiku 5.5).
    import sys
    sys.path.insert(0, str(ROOT))
    import run_match
    from judge import fact4_benign, round_record
    d = ROOT / "data" / "golden" / "claude-blue-haiku-first-match"
    m = _load(d / "match.json")
    assert m["schema_version"] == "0.4" and m["status"] == "completed"
    assert m["git"] == {"commit": "af755e395ae921e1358c12de529996b95fb5920b", "dirty": False}
    assert m["traffic"]["seed"] == 5202 and m["blue_engine"] == "claude"
    assert m["models"]["blue"] == {"provider": "anthropic", "model": "claude-haiku-5-5"}
    p = m["blue_params"]
    assert (p["prompt_version"], p["chunk_size"], p["sdk"]["version"]) == ("1", 1, "2.3.0")
    assert p["request"]["max_output_tokens"] == 256
    assert run_match.validate_manifest(m) == []
    a = run_match.artifact_hashes(d)
    a.pop("README.md")
    assert a == m["artifacts"]
    for name, schema in (("benign_requests.jsonl", "benign_request"),
                         ("benign_results.jsonl", "benign_result"),
                         ("verdicts.jsonl", "verdict"),
                         ("rounds.jsonl", "round_record"),
                         ("api_calls.jsonl", "api_call"),
                         ("challenge_snapshots.jsonl", "challenge_snapshot")):
        rows = [json.loads(l) for l in (d / name).read_text().splitlines()]
        assert rows, name
        for row in rows:
            validator(schema).validate(row)
    calls = [json.loads(l) for l in (d / "api_calls.jsonl").read_text().splitlines()]
    assert len(calls) == 24 and all(c["ok"] and c["stop_reason"] == "end_turn" for c in calls)
    verdicts = [json.loads(l) for l in (d / "verdicts.jsonl").read_text().splitlines()]
    assert len(verdicts) == 24 and {v["source"] for v in verdicts} == {"ai"}
    assert (d / "anomalies.jsonl").read_text() == ""
    # The Judge re-scores the folder offline to exactly the committed outputs
    # (incl. the instrument_failure cross-check against api_calls.jsonl).
    assert round_record.build_round_records(d) == \
        [json.loads(l) for l in (d / "rounds.jsonl").read_text().splitlines()]
    assert fact4_benign.compute(d) == (
        [json.loads(l) for l in (d / "benign_results.jsonl").read_text().splitlines()], [])


def test_rule_result_invalid_and_null_shapes_valid():
    v = validator("rule_result")
    base = VALID["rule_result"]
    v.validate({**base, "valid": False, "cwe": None, "replay_fires": None,
                "invalid_reasons": [{"code": "regex_unsupported_feature", "detail": "x"}],
                "replay_reason": "rule_invalid", "source_label": None,
                "cwe_matches_source": None, "fixture_fires": None, "rule_id": None})
    for reason in ("source_not_found", "source_orphan", "source_benign"):
        v.validate({**base, "replay_fires": None, "replay_reason": reason,
                    "source_label": None, "cwe_matches_source": None,
                    "fixture_fires": 1, "fixture_benign_ids": ["h06"]})


def test_anomaly_rule_source_benign_valid():
    validator("anomaly").validate({**VALID["anomaly"], "kind": "rule_source_benign",
                                   "detail": {"rule_id": "r-016", "benign_id": "h06"}})
