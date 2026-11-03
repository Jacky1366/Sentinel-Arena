# Sentinel Arena — Data Contract v0 (schema_version "0.1")

This document is the **source of truth** for every artifact exchanged between
components. Components never call each other; they only read and write the files
below. The orchestrator (`run_match.py`, later) controls ordering.

Machine-checkable versions live in `schemas/*.schema.json` (JSON Schema draft
2020-12). If this document and a schema disagree, this document wins and the schema
is a bug. **Never change an artifact format without updating this contract and the
schemas first, and telling the designer.**

---

## 0. Common rules

| Rule | Rationale |
|---|---|
| Every record carries `"schema_version": "0.1"`. Exceptions: the proxy log (nginx writes it), and individual rules (versioning lives on the `rules.json` wrapper). | Lets loaders reject or migrate old artifacts instead of silently misreading them. |
| Every per-match record carries `match_id`. Format: `m` + ≥3 digits (e.g. `m001`). Exceptions: the proxy log and `rules.json` (cross-match). | Records stay self-describing when concatenated or copied out of their run directory. |
| Timestamps are ISO 8601 UTC with a `Z` suffix, optional fractional seconds (`2026-11-02T22:15:03Z`). | One clock convention; no timezone ambiguity when joining Red and proxy times. |
| One round = one attack = one HTTP request (v0 simplification). | Makes `request_id` a 1:1 join key and keeps scoring trivial to reason about. |
| `request_id` is a lowercase UUID v4. It is **the join key** across `red_attacks`, `proxy`, `verdicts`, and `rounds`. | Lets the Judge align ground truth with Blue's view without trusting timestamps or order. |
| All records use `additionalProperties: false`. | Prevents accidental leakage (e.g. a label slipping into the proxy log) and catches typos early. |

### Traffic rule (ground-truth leak prevention)

**ALL arena traffic, both attack and benign, carries `X-Arena-Request-Id` and is
sent by the same HTTP client. Otherwise header presence leaks ground truth to Blue.**

Proxy log lines without a valid `request_id` are **stray traffic**: loaders skip
and count them, and never crash.

---

## 1. Taxonomy — `config/taxonomy.json`

```json
["CWE-89", "CWE-79", "CWE-22", "benign"]
```

| Value | Meaning |
|---|---|
| `CWE-89` | SQL injection |
| `CWE-79` | Cross-site scripting |
| `CWE-22` | Path traversal |
| `benign` | Not an attack |

- Red `label` and rule `label` may be **only the three CWE values**.
- Blue `verdict` may be **any of the four**.

Rationale: the taxonomy restricts Red's *label vocabulary* so the Judge can score
exactly; it does not restrict Red's *attack techniques*. The schemas hardcode these
enums; `tests/test_schemas.py` fails if they drift from `taxonomy.json`.

---

## 2. Red attack record — `data/runs/<match_id>/red_attacks.jsonl`

> **Blue must NEVER read this file.** It is ground truth.

```json
{"schema_version":"0.1","match_id":"m001","round":7,"request_id":"<uuid4>",
 "label":"CWE-89","payload":"' OR 1=1--","endpoint":"/rest/user/login",
 "method":"POST","timestamp":"2026-11-02T22:15:03Z"}
```

Red sends `request_id` in the HTTP header `X-Arena-Request-Id`.

| Field | Type | Rationale |
|---|---|---|
| `schema_version` | `"0.1"` | Versioning. |
| `match_id` | string | Which match this attack belongs to. |
| `round` | int ≥ 1 | Ordering within the match; human-readable progress. |
| `request_id` | uuid4 | Join key; also sent as `X-Arena-Request-Id` so the proxy log can carry it. |
| `label` | CWE enum | Ground truth the Judge compares Blue's verdict against. |
| `payload` | string | The malicious input. For audit, replay, and later rule generation. |
| `endpoint` | string starting with `/` | Target path. For audit and replay. |
| `method` | HTTP method enum | Needed to replay the exact request. |
| `timestamp` | UTC ISO 8601 | When Red sent it; debugging and timeline views. |

---

## 3. Proxy log — `data/runs/<match_id>/proxy.jsonl`

Written by nginx. **Blue's ONLY input.**

```json
{"timestamp":"...","request_id":"<from header>","method":"POST",
 "path":"/rest/user/login","query":"","body":"...","status":200}
```

| Field | Type | Rationale |
|---|---|---|
| `timestamp` | UTC ISO 8601 | When the proxy saw the request. |
| `request_id` | uuid4 (required) | Copied from `X-Arena-Request-Id`; join key. Lines without a valid value are stray traffic (see Traffic rule). |
| `method` | HTTP method enum | Part of what Blue observes. |
| `path` | string starting with `/` | Rule field `path`. |
| `query` | string (may be empty) | Rule field `query`. |
| `body` | string (may be empty) | Rule field `body`. |
| `status` | int 100–599 | Upstream response code; a weak signal Blue may use. |

There is no `schema_version` or `match_id`, because nginx writes the line and the
run directory implies the match. We control the format, so the Target is swappable.
No label or other ground truth may ever appear here.

---

## 4. Blue verdict — `data/runs/<match_id>/verdicts.jsonl`

```json
{"schema_version":"0.1","match_id":"m001","round":7,"request_id":"<uuid4>",
 "verdict":"CWE-89","reason":"tautology in email field"}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` | `"0.1"` | Versioning. |
| `match_id` | string | Provenance. |
| `round` | int ≥ 1 | Ordering. |
| `request_id` | uuid4 | Join key back to the proxy line Blue judged. |
| `verdict` | taxonomy enum (4 values) | Blue's classification. The only field the Judge scores. |
| `reason` | string | **For humans only. The Judge never reads it.** |

---

## 5. Rules — `rules.json` (cross-match memory)

Output of one match, input to the next. The file is a versioned wrapper:

```json
{
  "schema_version": "0.1",
  "rules": [
    {"rule_id":"r-007","label":"CWE-89","field":"body","match_type":"regex",
     "pattern":"'\\s*OR\\s+1=1","created_match":"m001","created_round":7}
  ]
}
```

Schemas: `rules_file.schema.json` (whole file) and `rule.schema.json` (one rule).

| Field | Type | Rationale |
|---|---|---|
| *(file)* `schema_version` | `"0.1"` | This file lives across matches, so it needs versioning the most. |
| *(file)* `rules` | array of rules | Blue's accumulated detection knowledge. |
| `rule_id` | `r-` + ≥3 digits | Stable identifier for diffs and attribution. |
| `label` | CWE enum (3 values) | What the rule detects. A "benign" rule is meaningless. |
| `field` | `path` / `query` / `body` | Which proxy log field the pattern is applied to. |
| `match_type` | `regex` (v0 only) | Keeps v0 matching deterministic and simple. |
| `pattern` | non-empty string | The detection pattern. |
| `created_match` | match_id | Provenance; enables the Match 1 vs Match 50 comparison. |
| `created_round` | int ≥ 1 | Provenance within the creating match. |

Individual rules do **not** carry `schema_version` or `match_id`.

---

## 6. Round record — `data/runs/<match_id>/rounds.jsonl`

Judge output, append-only.

```json
{"schema_version":"0.1","match_id":"m001","round":7,"request_id":"<uuid4>",
 "label":"CWE-89","verdict":"CWE-89","landed":true,"detected":true,
 "type_correct":true,"replay_blocked":null,"benign_fp":null}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` | `"0.1"` | Versioning. |
| `match_id` | string | Provenance. |
| `round` | int ≥ 1 | Ordering. |
| `request_id` | uuid4 | Join key. |
| `label` | CWE enum | Copied from Red's record (ground truth). |
| `verdict` | taxonomy enum | Copied from Blue's record. |
| `landed` | bool \| null | Did the attack actually succeed against the Target (Juice Shop challenge solved)? **From Stage 3 onward the Judge must never write `null` for `landed`.** |
| `detected` | bool | `verdict != "benign"`. |
| `type_correct` | bool | `verdict == label`. |
| `replay_blocked` | bool \| null | Would Blue's rules block a replay of this request? Filled in a later stage. |
| `benign_fp` | bool \| null | Benign false-positive tracking. Filled in a later stage. |

The Judge is pure deterministic code. It never uses an LLM.

---

## 7. Challenge map — `config/challenge_map.json`

```json
{"CWE-89":["Login Admin"],"CWE-79":["DOM XSS"],"CWE-22":[]}
```

Maps each CWE label to the Juice Shop challenges whose solving proves an attack
landed. `CWE-22` is intentionally empty; it will be filled after querying
`/api/Challenges`.

**Note for later:** Juice Shop challenges stay solved. The Judge must diff challenge
state before and after each round to attribute `landed` to that round.

---

## 8. Producer → consumer table

| Artifact | Path | Producer | Consumers | Must NOT be read by |
|---|---|---|---|---|
| Taxonomy | `config/taxonomy.json` | Designer | Red, Blue, Judge, schemas/tests | — |
| Challenge map | `config/challenge_map.json` | Designer | Judge | Blue |
| Red attacks | `data/runs/<match_id>/red_attacks.jsonl` | Red | Judge, Dashboard | **Blue** |
| Proxy log | `data/runs/<match_id>/proxy.jsonl` | nginx proxy | Blue, Judge, Dashboard | — |
| Verdicts | `data/runs/<match_id>/verdicts.jsonl` | Blue | Judge, Dashboard | Red |
| Rules | `rules.json` | Blue (match N) | Blue (match N+1), Judge (replay), Dashboard | Red |
| Round records | `data/runs/<match_id>/rounds.jsonl` | Judge | Dashboard | Red, Blue |

Join key across red_attacks, proxy, verdicts, and rounds: **`request_id`**.
