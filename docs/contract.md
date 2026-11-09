# Sentinel Arena — Data Contract v0 (schema_version "0.1")

*Revised 2026-11-04 (Stage 2): added the challenge-snapshot and landed-fact
artifacts, and the round record's `landed_reason` / `newly_solved` fields. The
`schema_version` stays `"0.1"`: the changes are purely additive, and **no round
records exist yet** (the Judge has not run), so adding required fields breaks no
stored data.*

*Revised 2026-11-05 (Stage 3): the round record gains `detected_reason`, and
`detected` / `type_correct` / `verdict` become nullable to carry the no-verdict and
orphan cases (§6). The Blue verdict's ordering field is renamed `round → log_seq`
(§4) so it is never confused with the round record's `round`, which always comes
from Red. Orphan rounds are now excluded from **all** statistics (§6). Still
`schema_version "0.1"`: additive, and no round records or verdicts exist yet.*

*Revised 2026-11-05 (Stage 3, follow-up): a **snapshot-missing** round (a proxy line
exists but there is no snapshot) no longer makes the Judge raise. The round record is
emitted with `landed = null`, `landed_reason = "snapshot_missing"` (new value), and
is excluded from landing stats — but **detection is still scored normally**, because
Blue saw the proxy line. This **reverses the Stage-3 Step-0 decision** to raise on a
missing landed fact. Rationale: distinguish **ambiguous** data (duplicate verdicts,
schema-invalid records — the Judge must not guess, so it raises) from **incomplete**
data (a missing snapshot — record it with a reason and exclude only the affected
stat). Raising on incomplete data would discard the whole match, including the valid
detection results from every other round. A scripted run should never produce
`snapshot_missing`; `tools/stage3_check.py` fails if one appears (an alarm, §6.1).*

*Revised 2026-11-07 (Stage 4): the orchestrator `run_match.py` exists. New artifact
**`match.json`** (§6.2), the per-match manifest: status, provenance, and the sha256 +
size of every other file in the match directory. `match_id` additionally accepts the
timestamp form `20261109T153012Z-a1b2` that `run_match.py` generates (§0); the legacy
`m001` form stays valid. The proxy log is now **frozen** into the match directory
**before** Blue and the Judge run (§3), and Red / the runner write their artifacts
straight into `data/runs/<match_id>/` — only `proxy.jsonl` is staged in `live/`.
Deleting an **empty** proxy log on rotation is documented as the one deliberate
exception to "never delete raw evidence" (§3). Still `schema_version "0.1"`: every
change is additive or widening, and all existing records stay valid.*

*Revised 2026-11-08 (terminology only, no semantic change): the committed reference
match in `data/golden/scripted-baseline-match/` is called the **scripted baseline
run**. "Golden run" is reserved for the later recorded AI-vs-AI demo match. No
format, path or rule changes; `schema_version` stays `"0.1"`.*

*Revised 2026-11-08 (Stage 5.1): the AI body exists (`agents/llm_client.py`), no
real calls yet. New artifact **`api_calls.jsonl`** (§6.3): one line per API attempt
and per refused call. New config **`config/prices.json`** and **`config/llm.json`**
(§6.4). **`match.json` moves to `schema_version "0.2"`** (§6.2): new required fields
`models`, `budget`, `price_table`, `cost`, and a new status `"stopped"` (exit code 4).
This is the first version bump: a 0.2 manifest is not a superset of 0.1, so 0.1
manifests (e.g. the committed scripted baseline run) stay valid under the frozen
`schemas/match_manifest_v0_1.schema.json`, and validators dispatch on
`schema_version`. Every other artifact stays `"0.1"`.*

*Revised 2026-11-08 (Stage 5.1, designer review): `api_calls.jsonl` `provider` comes
from `config/llm.json` (new required `agents.<agent>.provider`) and is **never
`null`**, not even for a `missing_price` refusal (§6.3, §6.4). Refused lines are
excluded from every accumulated total (caps and the cost block's counts). Unpriced
usage also sets `cost.lower_bound` (§6.2). No version bump: no `api_calls.jsonl`
has been written by a real match yet.*

*Revised 2026-11-09 (Stage 5.2): benign traffic (D1 layer 1) and Judge fact 4a. New
artifacts: the benign set `benign/benign_set.json` and `benign_requests.jsonl`
(§2.1), `benign_results.jsonl` (§6.5), `anomalies.jsonl` (§6.6). Challenge snapshot
rows gain a required `traffic` field (§3.1). Fact 2 hands verdicts with no Red record
to fact 4a (§6); `benign_fp` in the round record stays, always `null`. **`match.json`
moves to `"0.3"`** (§6.2): new required `traffic` block (seed, benign set, schedule),
`failed_step` `red` → `traffic`, new step `judge_benign`. 0.2 manifests already exist,
so 0.2 is frozen (`schemas/match_manifest_v0_2.schema.json`) and validators dispatch
on version. `judge_version` 0.2.0. §9 gains a Target quirk (the `/ftp/` listing's short
body); §10's apostrophe note is revised (expected_solves).*

This document is the **source of truth** for every artifact exchanged between
components. Components never call each other; they only read and write the files
below. The orchestrator (`run_match.py`) controls ordering.

Machine-checkable versions live in `schemas/*.schema.json` (JSON Schema draft
2020-12). If this document and a schema disagree, this document wins and the schema
is a bug. **Never change an artifact format without updating this contract and the
schemas first, and telling the designer.**

---

## 0. Common rules

| Rule | Rationale |
|---|---|
| Every record carries `"schema_version": "0.1"`, except `match.json`, which is `"0.3"` from Stage 5.2 (§6.2; older manifests stay `"0.1"` / `"0.2"` and are validated by the matching schema). Exceptions (no `schema_version`): the proxy log (nginx writes it), the challenge snapshot (measurement artifact, §3.1), and individual rules (versioning lives on the `rules.json` wrapper). | Lets loaders reject or migrate old artifacts instead of silently misreading them. |
| Every per-match record carries `match_id`. Format: UTC timestamp + `-` + 4 lowercase hex chars (e.g. `20261109T153012Z-a1b2`, generated by `run_match.py`), or the legacy `m` + ≥3 digits (e.g. `m001`, manual component runs). Exceptions: the proxy log, the challenge snapshot (§3.1), and `rules.json` (cross-match). | Records stay self-describing when concatenated or copied out of their run directory. |
| Timestamps are ISO 8601 UTC with a `Z` suffix, optional fractional seconds (`2026-11-02T22:15:03Z`). | One clock convention; no timezone ambiguity when joining Red and proxy times. |
| One round = one attack = one HTTP request (v0 simplification). | Makes `request_id` a 1:1 join key and keeps scoring trivial to reason about. |
| **Red labels must be truthful.** Every `red_attacks` record is a genuine attack of its stated CWE. Benign traffic is never a Red record — it belongs to the Stage 5 benign set. A label is ground truth, so a mislabel (e.g. labeling a non-attack `CWE-89`) would make the Judge score a correct Blue `benign` verdict as a false negative. | Ground truth must be trustworthy for every downstream score to mean anything. |
| `request_id` is a lowercase UUID v4. It is **the join key** across `red_attacks`, `proxy`, `verdicts`, and `rounds`. | Lets the Judge align ground truth with Blue's view without trusting timestamps or order. |
| All records use `additionalProperties: false`. | Prevents accidental leakage (e.g. a label slipping into the proxy log) and catches typos early. |

### Traffic rule (ground-truth leak prevention)

**ALL arena traffic, both attack and benign, carries `X-Arena-Request-Id` and is
sent by the same HTTP client. Otherwise header presence leaks ground truth to Blue.**

A proxy log line whose `request_id` is **missing or empty** is **stray traffic**:
loaders skip and count it, and never crash. Any other `request_id` that does not
match the uuid4 pattern makes the line **invalid**. A malformed id means a bug in
our own client, so it must fail loudly instead of being silently skipped.

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

## 2.1 Benign traffic — `benign/benign_set.json`, `data/runs/<match_id>/benign_requests.jsonl`

> **Blue must NEVER read either file.** They are ground truth.

**The benign set** (`benign/benign_set.json`, schema `benign_set.schema.json`) is a
fixed, versioned, **designer-approved** list of normal requests to the same endpoints
Red attacks (login, product search, `/ftp`, order tracking), plus registration (so a
successful benign login exists and "login 200 = attack" is no shortcut). About one
third are **hard negatives**: harmless requests a naive signature might flag. Each
entry: `benign_id` (`n..` normal, `h..` hard negative), `category`, `method`,
`endpoint`, optional `query_params` / `json_body`, optional `expected_solves`
(default `[]`), optional `requires` (an earlier entry it depends on), and a `note`.

- **Benign is the sender's intent**, not the server's reaction (§10): a person named
  O'Brien logging in is benign even if the server breaks on the apostrophe.
- `expected_solves` lists the challenges an entry is known to solve. The validator
  (`benign/send_benign.validate_set`) only allows challenges **not** in
  `config/challenge_map.json`, so a benign request can never change any Red round's
  landing. Every entry is verified empirically on a freshly reset Target
  (`tools/verify_benign_set.py` → `benign/verification.json`).
- The set and Blue's signatures are never tuned against each other.

**Benign request record** (`benign_requests.jsonl`, schema
`benign_request.schema.json`): one line per benign request, written **before** the
request is sent (same rule as Red). Benign requests are never Red records.

```json
{"schema_version":"0.1","match_id":"20261109T153012Z-a1b2","request_id":"<uuid4>",
 "benign_id":"h06","category":"hard_negative","expected_solves":["Error Handling"],
 "sent_at":"2026-11-09T15:30:14.001Z"}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` / `match_id` | as §0 | Versioning, provenance. |
| `request_id` | uuid4 | Join key; sent as `X-Arena-Request-Id` by the **same client** as Red. |
| `benign_id` | `^[nh][0-9]{2}$` | Which set entry (the set's sha256 is in `match.json`). |
| `category` | `normal` \| `hard_negative` | For the hard-negative FP rate. |
| `expected_solves` | array of strings | Copied from the entry, so the Judge needs nothing else. |
| `sent_at` | UTC ISO 8601 | Written just before sending. |

**Sending and schedule.** Red and benign requests are interleaved by a **seeded
shuffle that decides only the interleaving**: Red's attacks keep their order and
benign entries keep the set's order (so `n10` register always precedes `n11` log in;
`requires` is a second guarantee checked by the validator). The orchestrator drives
one slot at a time (one Red attack or one benign request), so Red is callable one
step at a time (needed for AI Red, Stage 5.6). Every request gets its own
before/after challenge snapshot (§3.1). `--seed` reproduces a match's schedule; the
seed and the planned schedule are recorded in `match.json` (§6.2). Neither Red nor
benign traffic sends a User-Agent; the header profile is identical by construction
(`runner/arena_client.py`) and by test.

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
| `request_id` | uuid4 (required) | Copied from `X-Arena-Request-Id`; join key. Missing or empty = stray traffic; any other non-matching value = invalid (see Traffic rule). |
| `method` | HTTP method enum | Part of what Blue observes. |
| `path` | string starting with `/` | Rule field `path`. |
| `query` | string (may be empty) | Rule field `query`. |
| `body` | string (may be empty) | Rule field `body`. |
| `status` | int 100–599 | Upstream response code; a weak signal Blue may use. |

**Location.** nginx always writes to `data/runs/live/proxy.jsonl` (staging); it
never knows about matches. The line format is identical in both places.

- **Rotate (start of a match).** The orchestrator moves a non-empty
  `live/proxy.jsonl` to `live/archive/proxy-<ts>.jsonl`, then runs `nginx -s
  reopen` and waits for nginx to create a fresh `live/proxy.jsonl`; if it does not
  appear, the match fails. An **empty** log is deleted instead of archived: this is
  the **one deliberate exception** to "never delete raw evidence", because an empty
  file holds no evidence.
- **Freeze (after Red, before Blue and the Judge).** The orchestrator moves
  `live/proxy.jsonl` to `data/runs/<match_id>/proxy.jsonl`, then `nginx -s reopen`,
  then confirms a fresh `live/proxy.jsonl` exists. Blue and the Judge read **only the
  frozen copy**, which can no longer change.
- **Why reopen is mandatory.** nginx keeps its log file descriptor open, so after a
  move — even out of the bind-mounted directory — it **keeps appending to the moved
  file** until it reopens (verified empirically, Stage 4, Docker Desktop / macOS bind
  mount). A moved log is final only once the fresh live file exists.
- **Live directory between matches** holds only `proxy.jsonl`, `archive/`, and,
  while a match runs, `match.lock`. The orchestrator refuses to start if anything
  else is there, and refuses if `match.lock` exists (a stale lock from a crash is
  removed by a human, never automatically).

There is no `schema_version` or `match_id`, because nginx writes the line and the
run directory implies the match. We control the format, so the Target is swappable.
No label or other ground truth may ever appear here.

---

## 3.1 Challenge snapshot — `data/runs/<match_id>/challenge_snapshots.jsonl`

Written by the **measurement runner** (not the Judge), one line per request (Red
attack or, from Stage 5.2, benign request). It captures which Juice Shop challenges
were solved immediately **before** and **after** the request, so the Judge can
attribute `landed` to that one round (§6.1), and check a benign request's solves
against its `expected_solves` (§6.6), by pure computation without network access.

```json
{"request_id":"<uuid4>","traffic":"red","before_solved":["Login Admin"],
 "after_solved":["Login Admin","User Credentials"],"taken_at":"2026-11-04T01:02:03Z"}
```

| Field | Type | Rationale |
|---|---|---|
| `request_id` | uuid4 (required) | Join key to the Red or benign record and the proxy line. |
| `traffic` | `"red"` \| `"benign"` (required from Stage 5.2) | Which traffic the row belongs to. Fact 1 reads only `red` rows; fact 4a only `benign` rows. Rows written before Stage 5.2 have no `traffic` field and are all Red. |
| `before_solved` | array of strings | Exact challenge `name`s solved just before the attack fired. |
| `after_solved` | array of strings | Exact challenge `name`s solved just after. `newly_solved = after − before`. |
| `taken_at` | UTC ISO 8601 | When the *after* snapshot was taken; debugging and timeline. |

Like the proxy log, this has **no `schema_version` or `match_id`**: it is an
internal measurement artifact, keyed by `request_id`, and the run directory implies
the match. The snapshots are read **only through the Judge's admin path** (nginx
`:8081`, `access_log off`), so measuring challenge state never adds a line to
`proxy.jsonl` — the measurement must not disturb what it measures. **Blue must
never read this file.**

---

## 4. Blue verdict — `data/runs/<match_id>/verdicts.jsonl`

```json
{"schema_version":"0.1","match_id":"m001","log_seq":7,"request_id":"<uuid4>",
 "verdict":"CWE-89","reason":"tautology in email field"}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` | `"0.1"` | Versioning. |
| `match_id` | string | Provenance. Supplied to Blue as a parameter; the proxy log does not carry it. |
| `log_seq` | int ≥ 1 | Blue's own 1-based index into the proxy log it read. **Not** the round: the Judge joins on `request_id` only and takes `round` from Red. Named distinctly so the two orderings are never confused. |
| `request_id` | uuid4 | Join key back to the proxy line Blue judged. |
| `verdict` | taxonomy enum (4 values) | Blue's classification. The only field the Judge scores. |
| `reason` | string | **For humans only. The Judge never reads it.** |

Blue reads **only** the proxy log. `match_id` is provenance (a constant passed in),
never a classification feature; `request_id` is copied through as the join key and
is never used to classify.

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
 "label":"CWE-89","verdict":"CWE-89","landed":true,"landed_reason":null,
 "newly_solved":["User Credentials"],"detected":true,"type_correct":true,
 "detected_reason":null,"replay_blocked":null,"benign_fp":null}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` | `"0.1"` | Versioning. |
| `match_id` | string | Provenance. |
| `round` | int ≥ 1 | Ordering. Always from Red's record (the spine). |
| `request_id` | uuid4 | Join key. |
| `label` | CWE enum | Copied from Red's record (ground truth). |
| `verdict` | taxonomy enum \| null | Copied from Blue's verdict. **`null`** when there is no Blue verdict for this request (no-verdict or orphan, see `detected_reason`). |
| `landed` | bool \| null | Did the attack actually succeed against the Target? **The Judge writes `null` only in the not-measurable (§11), already-solved (§6.1), and snapshot-missing (§6.1) cases.** An orphan keeps whatever fact 1 computed, but is excluded from landing stats (see below). |
| `landed_reason` | `null` \| `"not_measurable"` \| `"already_solved"` \| `"snapshot_missing"` | Why `landed` is `null`. `"snapshot_missing"` is a runtime measurement failure (no snapshot), synthesized by the round-record join when a proxy line exists but there is no snapshot (fact 1 never emits it) — distinct from `"not_measurable"`, which is a by-design limitation (e.g. XSS, §11). **Invariant: `landed` is `null` iff `landed_reason` is non-null.** |
| `newly_solved` | array of strings | Challenge `name`s that flipped `false → true` this round (`after − before`, §3.1). Evidence for `landed`. |
| `detected` | bool \| null | `verdict != "benign"` when a verdict exists; `false` when the request was logged but got no verdict; **`null`** for an orphan (Blue never saw it). |
| `type_correct` | bool \| null | `verdict == label`, but **only meaningful when `detected` is `true`**. `null` whenever `detected` is not `true` (benign verdict, no-verdict, or orphan). |
| `detected_reason` | `null` \| `"no_verdict"` \| `"orphan"` | Why `detected` is not a normal boolean-from-verdict. `null` when a verdict exists. **Invariant: `detected` is `null` iff `detected_reason == "orphan"`.** `"no_verdict"` pairs with `detected == false`. |
| `replay_blocked` | bool \| null | Would Blue's rules block a replay of this request? Filled in a later stage. |
| `benign_fp` | null | **Always `null`.** Round records are Red-only; benign false positives live in `benign_results.jsonl` (§6.5). Kept so round records need no version bump. |

The Judge is pure deterministic code. It never uses an LLM.

**Field relationships (the Judge enforces these; the schema enforces the null
pairings).**

| Case | `verdict` | `detected` | `type_correct` | `detected_reason` |
|---|---|---|---|---|
| Verdict present, flagged as attack | a CWE | `true` | `true` / `false` | `null` |
| Verdict present, called benign | `benign` | `false` | `null` | `null` |
| Logged request, no verdict | `null` | `false` | `null` | `"no_verdict"` |
| Orphan (no proxy line) | `null` | `null` | `null` | `"orphan"` |

**Verdicts with no Red record** (Stage 5.2): fact 2 does not score them. Fact 4a
matches them against benign records (§6.5); a verdict matching neither is never
scored and is recorded as an `unmatched_verdict` anomaly (§6.6).

**Challenge scope.** The Judge considers only challenges listed in
`config/challenge_map.json`; all other solved challenges are ignored.

### Orphan rounds

A Red record with **no proxy line carrying the same `request_id`** is an **orphan
round** — this is the single authoritative definition of orphan. It happens when a
request never produced a logged `request_id`: the send failed, or nginx rejected it
before reading headers (§9). (Fact 1's separate "no snapshot line" case is called
**snapshot-missing**, not orphan — §6.1 — and does not arise in a normal run, where the
runner snapshots every attack.)

- The Judge marks the round orphan: `detected = null`, `type_correct = null`,
  `detected_reason = "orphan"`, `verdict = null`.
- **Orphans are excluded from ALL statistics — detection AND landing**, not just
  detection. A send failure is an *infrastructure* failure, not an attack failure,
  so a fact-1 `landed = false` on an orphan must never lower Red's landing rate, and
  Blue never saw the request so it is never a false negative. This is enforced at
  the **statistics layer** (fact 1 itself is unchanged and may still carry a
  `landed` value for the row); the round record keeps that value for audit, but any
  rate computation drops orphan rows first.
- The Judge reports the **orphan count per match**.

---

## 6.1 Landed fact — `data/runs/<match_id>/landed.jsonl`

An **internal Judge intermediate**, produced in Stage 2, one line per attack. It
carries only the fact the Judge can know before Blue exists: did the attack land?
Stage 3 joins it with the Blue verdicts to build the full round record (§6); it is
**not** a downstream artifact and the Dashboard never reads it (§8). The round
record stays the single source of truth for every downstream reader.

```json
{"schema_version":"0.1","match_id":"m001","round":4,"request_id":"<uuid4>",
 "label":"CWE-22","landed":true,"landed_reason":null,
 "newly_solved":["Poison Null Byte","Forgotten Developer Backup"]}
```

Fields are a subset of the round record: `schema_version`, `match_id`, `round`,
`request_id`, `label`, `landed`, `landed_reason`, `newly_solved`, with the same
`landed` / `landed_reason` invariant.

**Computation (pure, deterministic).** For each attack with a snapshot line (§3.1),
let `mapped = challenge_map[label]` and `newly_solved = after_solved − before_solved`:

| Condition | `landed` | `landed_reason` |
|---|---|---|
| `mapped` is empty | `null` | `"not_measurable"` |
| every name in `mapped` is already in `before_solved` | `null` | `"already_solved"` |
| `newly_solved ∩ mapped` is non-empty | `true` | `null` |
| otherwise | `false` | `null` |

Only challenges in the label's mapping count toward `landed`; a solved challenge
outside the mapping is recorded in `newly_solved` as evidence but never flips
`landed` (§6, Challenge scope). The full `newly_solved` list is stored regardless.

A Red record with **no snapshot line** is **snapshot-missing**: fact 1 cannot measure
landing for it and emits no landed fact. This is distinct from an **orphan** (§6, no
proxy line). In a normal run the runner snapshots every attack, so the
snapshot-missing case does not arise; it is a defensive guard against incomplete
artifacts (a runtime measurement failure, not a by-design limitation like §11).

When the round-record join meets a snapshot-missing Red record, it **does not raise**
(this is *incomplete* data, not *ambiguous* data — contrast duplicate verdicts or
schema-invalid records, where the Judge must not guess and raises). It emits the
round record with `landed = null`, `landed_reason = "snapshot_missing"`,
`newly_solved = []`, and that row is **excluded from landing stats**. Detection is
scored **normally** from the proxy line and verdict (fact 2): the attack *was* on
Blue's input, so whether Blue caught it is a real result even though its landing is
unknown. (If the record is also an orphan — no proxy line — detection takes the
orphan shape, §6.)

Because a scripted run should never drop a snapshot, `tools/stage3_check.py`
**fails** if any round record has `landed_reason == "snapshot_missing"`: it is an
alarm that the measurement harness misbehaved, not an acceptable outcome.

---

## 6.2 Match manifest — `data/runs/<match_id>/match.json`

Written by the **orchestrator** (`run_match.py`) as the **last** file of **every**
match, completed, failed or stopped. One JSON object (not JSONL). Schema:
`schemas/match_manifest.schema.json` (`schema_version "0.3"`, Stage 5.2 on).
Manifests written earlier are `"0.1"` (no `models` / `budget` / `price_table` /
`cost`, no `"stopped"` status; frozen `schemas/match_manifest_v0_1.schema.json`) or
`"0.2"` (no `traffic`, `failed_step` `red`; frozen
`schemas/match_manifest_v0_2.schema.json`); validators dispatch on `schema_version`
(`run_match.validate_manifest`).

```json
{"schema_version":"0.3","match_id":"20261109T153012Z-a1b2",
 "started_at":"2026-11-09T15:30:12.001Z","finished_at":"2026-11-09T15:30:40.512Z",
 "status":"completed","failed_step":null,"error":null,"judge_version":"0.2.0",
 "blue_engine":"scripted",
 "red_source":{"path":"red/payloads.json","sha256":"<64 hex>"},
 "git":{"commit":"<40 hex>","dirty":false},
 "traffic":{"seed":5202,"seed_source":"cli",
            "benign_set":{"path":"benign/benign_set.json","sha256":"<64 hex>","set_version":"1"},
            "schedule":["benign:n01","benign:n02","red:1", … ,"benign:h06"]},
 "images":{"juice_shop":{"image":"bkimminich/juice-shop:v20.3.0","image_id":"sha256:<64 hex>","repo_digest":"bkimminich/juice-shop@sha256:<64 hex>"},
           "nginx":{"image":"nginx:1.30.6-alpine","image_id":"sha256:<64 hex>","repo_digest":"nginx@sha256:<64 hex>"}},
 "models":{"red":null,"blue":null,"analyst":null},
 "budget":{"limits":{"red":{"max_calls":60,"max_tokens":400000,"max_usd":0.25},
                     "blue":{"max_calls":100,"max_tokens":300000,"max_usd":0.25},
                     "analyst":{"max_calls":0,"max_tokens":0,"max_usd":0},
                     "match":{"max_calls":null,"max_tokens":null,"max_usd":0.5}},
           "stopped_by":null},
 "price_table":{"path":"config/prices.json","sha256":"<64 hex>","as_of":"2026-11-08"},
 "cost":{"total_usd":0.0,"failed_attempts_usd":0.0,"cache_savings_usd":0.0,"attempts":0,
         "failed_attempts":0,"refused":0,
         "tokens":{"input":0,"cached_input":0,"cache_write":0,"output":0},
         "by_agent":{},"by_model":{},"lower_bound":false,"cached_at_input_price":false,
         "unpriced_usage":false,"prices_verified":null},
 "artifacts":{"proxy.jsonl":{"sha256":"<64 hex>","bytes":1563}}}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` | `"0.3"` | Versioning (`"0.1"` before Stage 5.1, `"0.2"` in Stage 5.1, see above). |
| `match_id` | match_id (§0) | Equals the directory name; self-describing when copied out. |
| `started_at` / `finished_at` | UTC ISO 8601 | Wall-clock span of the match. |
| `status` | `"completed"` \| `"failed"` \| `"stopped"` | `failed`: a step raised. `stopped`: every step ran, but the AI body refused a call or saw usage it cannot price (`budget.stopped_by`). `completed`: neither. A failure wins over a stop. |
| `failed_step` | `null` \| `reset` \| `rotate` \| `traffic` \| `freeze` \| `judge_fact1` \| `blue` \| `judge_rounds` \| `judge_benign` | Where it failed (`traffic` was `red` in 0.2). **`null` iff `status != "failed"`.** |
| `error` | `null` \| string | Exception text (key values redacted), plus any finalize problem. **`null` iff `status != "failed"`.** |
| `judge_version` | semver string | `judge.JUDGE_VERSION` that scored `rounds.jsonl`. Bumped on any Judge logic change, so results scored by older logic are identifiable. |
| `blue_engine` | `"scripted"` | Which Blue engine produced `verdicts.jsonl`. |
| `red_source` | `{path, sha256}` | The exact attack set fired. |
| `git` | `{commit, dirty}` | Code provenance. `dirty` counts untracked files too. A committed reference run (the scripted baseline run, and later the golden run) must say `false`. |
| `traffic` | `{seed, seed_source, benign_set, schedule}` | `seed`: 0..2³²−1; `seed_source`: `cli` (`--seed`) or `generated`. `benign_set`: `{path, sha256, set_version}`. `schedule`: the **planned** slot order from the seed, `red:<round>` / `benign:<benign_id>` (§2.1). Same seed + same set + same payloads → same schedule. |
| `images` | `{juice_shop, nginx}`: `{image, image_id, repo_digest}` | Read from the **running** containers (`docker inspect`), not the compose file. `repo_digest` is `null` for a locally built image. |
| `models` | `{red, blue, analyst}`: each `null` \| `{provider, model}` | The model each agent actually used. `null` for a scripted component or an unused agent. |
| `budget.limits` | `{red, blue, analyst, match}`: each `{max_calls, max_tokens, max_usd}` | The caps in force (`config/llm.json`). Per-agent caps are **required numbers**; the match-level total may leave a field `null` (no match-level limit on it). |
| `budget.stopped_by` | `null` \| `{scope, reason}` | The **first** refusal in `api_calls.jsonl` (§6.3), or `{scope: "match", reason: "unpriced_usage"}` if usage could not be priced. `scope` ∈ red / blue / analyst / match; `reason` ∈ `max_calls` / `max_tokens` / `max_usd` / `unpriced_usage` / `missing_price` / `missing_key`. **Non-null whenever `status == "stopped"`, `null` when `completed`**; a failed match may carry one (both are facts). |
| `price_table` | `{path, sha256, as_of}` | The price table the dollar snapshot below was computed with. |
| `cost` | object | Dollar **snapshot** derived by `stats/cost.py` from `api_calls.jsonl` and that price table (D10: tokens are the evidence; dollars can be recomputed against any later table). `total_usd` includes failed attempts; `failed_attempts_usd` is that subset. `cache_savings_usd` is **net** of the cache-write premium and may be negative. `attempts` counts sent attempts; `refused` counts refusals (never sent, $0; they add nothing to `attempts`, tokens or dollars, here or in any cap total). `by_agent` / `by_model` break it down. Flags: `lower_bound` (`total_usd` is an undercount: an attempt reported no usage, e.g. a timeout the provider may still bill, or usage was unpriced), `cached_at_input_price` (cached tokens of a model with no cached price, charged at the input price), `unpriced_usage` (cache writes with no cache-write price; not included in `total_usd`, so `lower_bound` is `true` too). `prices_verified`: `null` if no calls, else whether every model used has `verified: true`. A scripted match: all zeros, no `api_calls.jsonl`. |
| `artifacts` | `{name: {sha256, bytes}}` | Every other file in the match directory (never `match.json` itself). Lets anyone verify the frozen files were not changed afterwards. |

**Failure handling.** If a step from `reset` on fails, the match is still
finalized: everything **this match produced** is in the match directory,
`match.json` says `"failed"` with `failed_step` and `error`, the lock is released,
and the exit code is non-zero. The proxy log counts as this match's only once it was
rotated; before that, `live/proxy.jsonl` is earlier traffic and is left for the next
rotation to archive. If the **freeze** itself fails, finalize retries it; if that
also fails, it moves the log into the match directory with a plain rename and makes
**one best-effort `nginx -s reopen`** (confirmed by a fresh live log). Only if that
reopen also fails does `error` mark the log **NOT FROZEN** (nginx may keep appending
to it until the next rotation). The Judge **raising** on ambiguous data (duplicate verdicts,
schema-invalid records) is a failure; **incomplete** data (`snapshot_missing`, §6.1)
is not. Preflight and lock refusals happen before a match exists: non-zero exit, no
match directory, no `match.json`.

**Stopped.** A budget refusal is not a failure: the agent that was refused stops
calling, every remaining step still runs, and the match is finalized with
`status: "stopped"`. Under D13 (`docs/stage5_decisions.md`) a refusal is an
**instrument** failure, never a subject failure; the round-record field that keeps
refused requests out of the detection stats arrives in Stage 5.4. Exit codes: 0
completed, 1 failed, 2 preflight refused, 3 lock held, 4 stopped (`docs/ops.md`).

---

## 6.3 API call log — `data/runs/<match_id>/api_calls.jsonl`

Written by **`agents/llm_client.py`**, the single exit for every AI call (Red, Blue,
the future analyst). One line per **attempt** — successes, failures and retries —
plus one line per call the body **refused** before sending. Schema:
`schemas/api_call.schema.json`. It is **raw evidence** (D10): token counts as the
provider reported them. Dollars are derived from it (§6.4), never stored in it.
The file is also the budget's only state: before each attempt the client re-reads
it, so separate steps share one budget without sharing memory. A scripted match
makes no calls and has no `api_calls.jsonl`.

```json
{"schema_version":"0.1","match_id":"20261109T153012Z-a1b2",
 "timestamp":"2026-11-09T15:30:13.120Z","agent":"blue","provider":"anthropic",
 "model":"claude-haiku-5-5","round":null,"log_seq_first":1,"log_seq_last":20,
 "attempt":1,"ok":true,"error_type":null,"http_status":200,"refusal":null,
 "input_tokens":1200,"cached_input_tokens":0,"cache_write_tokens":0,
 "output_tokens":300,"latency_ms":812,"prompt_sha256":"<64 hex>"}
```

| Field | Type | Rationale |
|---|---|---|
| `schema_version` / `match_id` | `"0.1"` / match_id | §0 common rules. |
| `timestamp` | UTC ISO 8601 | When the attempt started. |
| `agent` | `red` \| `blue` \| `analyst` | Which component asked. |
| `provider` | `openai` \| `anthropic` \| `gemini` \| `fake` | From `config/llm.json` (`agents.<agent>.provider`), never from the price table, so it is **never `null`**, even for a `missing_price` refusal. A model whose price entry names another provider is a config error (the call raises, nothing is written). `fake` appears only in tests. |
| `model` | string | The requested model id (from config / CLI, never hardcoded in agent logic). |
| `round` | int ≥ 1 \| null | **Red only**: the Red round. `null` for Blue and the analyst (Blue never sees Red rounds, §4). |
| `log_seq_first` / `log_seq_last` | int ≥ 1 \| null | **Blue only**: the chunk of proxy-log lines this call covers. `null` for Red and the analyst. |
| `attempt` | int ≥ 1 | 1 for the first try, +1 per retry. A refusal carries the number the attempt would have had. |
| `ok` | bool | The provider returned a reply. A reply that is not valid JSON is still `ok` at this level (it was billed); the agent handles it. |
| `error_type` | `null` \| `timeout` \| `rate_limit` \| `server_error` \| `connection` \| `auth` \| `bad_request` \| `other` \| `refused` | `null` iff `ok`. `timeout`, `rate_limit` (429), `server_error` (5xx) and `connection` are retried with exponential backoff (honouring Retry-After); the rest fail fast. `refused`: never sent. |
| `http_status` | int \| null | When the provider gave one. |
| `refusal` | `null` \| `{scope, reason}` | Set iff `error_type == "refused"`. Same vocabulary as `budget.stopped_by` (§6.2). |
| `input_tokens` | int \| null | **Full-price input only.** The whole prompt is `input + cached_input + cache_write` (OpenAI's `prompt_tokens` includes cached tokens, so the adapter subtracts them; Anthropic's `input_tokens` already excludes them — to be verified at the first real call). |
| `cached_input_tokens` / `cache_write_tokens` / `output_tokens` | int \| null | Cache reads, cache writes, output (incl. reasoning tokens). **`null`** = the provider reported no usage (e.g. a timeout), distinct from 0. Integers whenever `ok`; all `0` for a refusal. |
| `latency_ms` | int ≥ 0 | Wall time of the attempt; `0` for a refusal. |
| `prompt_sha256` | 64 hex | sha256 of the canonical JSON of `{model, system, messages}`. The prompt text itself is **never** stored. |

Never stored: API keys, prompt text, response text, error messages (only
`error_type` and `http_status`).

**Refusals** (checked before every attempt, in this order; a refusal writes a line
and sends nothing): the model has no price entry (`missing_price`; a placeholder
entry never counts) → its provider's `ARENA_*` key is missing (`missing_key`) → an
earlier call left usage that cannot be priced (`unpriced_usage`) → the worst case
does not fit a cap (`max_calls`, `max_tokens`, `max_usd`; the agent's own caps first,
then the match total). **Refused lines never count toward any cap total**: nothing
was sent, so a refusal can never make a cap trigger earlier. Worst case = input estimated from the built prompt at 1 token
per `chars_per_token` (3) characters, plus `max_output_tokens`, priced at the
applicable tier. Retries count toward `max_calls`. If a reply is much larger than
the estimate, the cap can be exceeded by **at most that one call**; the next call is
refused.

---

## 6.4 Price table and LLM config — `config/prices.json`, `config/llm.json`

**`config/prices.json`** (schema `schemas/prices.schema.json`), maintained by the
designer: USD **per million tokens** for `input`, `cached_input`, `cache_write`,
`output`, per model id, with `provider`, `as_of`, `source` and `verified` per entry
and a file-level `as_of`. A `null` price means unknown. Prices may be **tiered by
prompt size**: a call uses the first tier whose `max_prompt_tokens` is `null` or ≥ its
prompt tokens (`input + cached_input + cache_write`; designer to verify this
definition against the provider's pricing page). Only entries under `models` are
callable; entries under `placeholders` (e.g. a model whose id is not confirmed) are
never matched. Dollars per call:

```
usd     = (input·p.input + cached_input·p.cached_input + cache_write·p.cache_write + output·p.output) / 1e6
savings = cached_input·(p.input − p.cached_input) − cache_write·(p.cache_write − p.input)   (net, may be < 0)
```

A `null` `cached_input` price charges cached tokens at the input price (flagged
`cached_at_input_price`). A `null` `cache_write` price with cache-write tokens > 0 is
**unpriced usage**: left out of `usd`, flagged (`unpriced_usage` and `lower_bound`: the
total is an undercount), and it stops further calls
(`stopped_by` reason `unpriced_usage`, never `max_usd`).

**`config/llm.json`**: per agent the `provider` (`openai` / `anthropic` / `gemini`;
`null` only while the agent has no model, and the client refuses to run such an
agent) and the default `model` (`null` = no AI for that agent yet), `timeout_s`, `max_retries`, `backoff_base_s`, `backoff_max_s`,
`max_output_tokens`, `chars_per_token`, `provider_caching` (must be `false` until
Stage 5.7, D11), and `caps` for `red`, `blue`, `analyst` (all three fields required)
and `match` (fields may be `null`). `run_match.py` refuses at preflight (exit 2) if
either file is invalid.

---

## 6.5 Benign results (Judge fact 4a) — `data/runs/<match_id>/benign_results.jsonl`

Judge output (`judge/fact4_benign.py`, pure, no network), one line per benign record,
schema-validated before anything is written.

```json
{"schema_version":"0.1","match_id":"…","request_id":"<uuid4>","benign_id":"h01",
 "category":"hard_negative","verdict":"benign","false_positive":false,"fp_reason":null}
```

| Case | `verdict` | `false_positive` | `fp_reason` |
|---|---|---|---|
| Verdict is a CWE | the CWE | `true` | `null` |
| Verdict is `benign` | `benign` | `false` | `null` |
| Logged, no verdict | `null` | `null` | `"no_verdict"` |
| No proxy line (orphan) | `null` | `null` | `"orphan"` |

Both `null` cases are **excluded from the FP denominator**; `no_verdict` counts in
the benign no-verdict rate. Not a loophole: Blue cannot tell which lines are benign,
so skipping lines is punished on the attack side (a no-verdict Red round is a miss).
Duplicate verdicts raise (ambiguous data). Round records stay Red-only.

**Statistics** (`stats/match_stats.py`): FP rate = `false_positive` true / benign
with a verdict (overall, and hard negatives only); precision = detected attacks /
(detected attacks + false positives), always printed with its traffic mix; benign
no-verdict rate. **The detection rate is never printed without the FP rate next to
it.** The FP denominator is the benign set only: Red's negative control (round 1, a
genuine CWE-89 attempt that fails to land) is a Red round, never benign.

---

## 6.6 Anomalies — `data/runs/<match_id>/anomalies.jsonl`

Harness self-checks that tripped, written by the Judge (fact 4a step), schema
`anomaly.schema.json`. **Never silently ignored**: every anomaly is shown in the
terminal summary, and a scripted stage check fails on any. The affected request is
still scored where that is meaningful. The file always exists (possibly empty).

```json
{"schema_version":"0.1","match_id":"…","kind":"benign_solved_challenge",
 "request_id":"<uuid4>","detail":{"benign_id":"n04","newly_solved":["Score Board"],
 "expected_solves":[]}}
```

| `kind` | When | `detail` |
|---|---|---|
| `benign_solved_challenge` | A benign request's `newly_solved` differs **in any way** from its `expected_solves` (exact set equality: an unexpected solve, a missing expected solve, or both) | `{benign_id, newly_solved, expected_solves}` |
| `benign_snapshot_missing` | A benign request has no `traffic: "benign"` snapshot row, so its solves cannot be checked | `{benign_id}` |
| `unmatched_verdict` | A verdict whose `request_id` is neither a Red nor a benign record | `{log_seq, verdict}` |

---

## 7. Challenge map — `config/challenge_map.json`

```json
{"CWE-89":["Login Admin","User Credentials"],
 "CWE-79":[],
 "CWE-22":["Poison Null Byte","Forgotten Developer Backup"]}
```

Maps each CWE label to the exact Juice Shop challenge `name` string(s) whose solving
proves an attack of that type landed. Names were verified against this version's
`GET /api/Challenges`, each by sending one attack request and observing which
challenge flipped to solved (one round = one request).

**Multiple challenges per label.** An entry may list more than one name, and one
request may solve several. The Judge marks `landed = true` if **any** mapped
challenge for that label flips `false → true` across the round. (`Poison Null Byte`
and `Forgotten Developer Backup` both flip from the one null-byte `/ftp` request.)

`CWE-79` is **empty on purpose** (see §11): no XSS challenge can be both triggered by
one HTTP request and observed by the proxy in this Docker deployment.

**Note for later:** Juice Shop challenges stay solved. The Judge must diff challenge
state before and after each round to attribute `landed` to that round, and must
ignore any solved challenge whose name is not in this map (§6, Challenge scope).

**Known item: an attack can solve a challenge outside the map (recorded 2026-11-07,
not yet acted on).** In the Stage 4 scripted baseline run (`data/golden/scripted-baseline-match/`),
round 5 (CWE-22, `GET /ftp/coupons_2013.md.bak%2500.md`) produced
`landed = null, landed_reason = "already_solved"` (both mapped CWE-22 challenges were
solved by round 4), yet `newly_solved = ["Forgotten Sales Backup"]`, a challenge
that is **not** in the CWE-22 entry. The Judge behaved as designed: only mapped
challenges are credited, and the unmapped solve is kept as raw evidence in
`newly_solved`. The consequence is that landing is slightly **under-counted**: a real
traversal that did something new is scored as unmeasurable. The map, the Stage 3
expectations, and the scripted baseline run are deliberately **left unchanged** for now; revisit
when variant attacks are designed. This is exactly the planned "`newly_solved`
outside the map" tripwire (`docs/progress.md`, Stage 6 tripwires).

---

## 8. Producer → consumer table

| Artifact | Path | Producer | Consumers | Must NOT be read by |
|---|---|---|---|---|
| Taxonomy | `config/taxonomy.json` | Designer | Red, Blue, Judge, schemas/tests | — |
| Challenge map | `config/challenge_map.json` | Designer | Judge | Blue |
| Red attacks | `data/runs/<match_id>/red_attacks.jsonl` | Red | Judge, Dashboard | **Blue** |
| Proxy log | `data/runs/<match_id>/proxy.jsonl` | nginx proxy | Blue, Judge, Dashboard | — |
| Challenge snapshots | `data/runs/<match_id>/challenge_snapshots.jsonl` | Measurement runner | Judge | **Blue** |
| Landed fact | `data/runs/<match_id>/landed.jsonl` | Judge (Stage 2) | Judge (Stage 3 join) | Red, Blue, Dashboard |
| Verdicts | `data/runs/<match_id>/verdicts.jsonl` | Blue | Judge, Dashboard | Red |
| Rules | `rules.json` | Blue (match N) | Blue (match N+1), Judge (replay), Dashboard | Red |
| Round records | `data/runs/<match_id>/rounds.jsonl` | Judge | Dashboard | Red, Blue |
| Match manifest | `data/runs/<match_id>/match.json` | Orchestrator | Dashboard, stage checks, humans | Red, Blue |
| API call log | `data/runs/<match_id>/api_calls.jsonl` | `agents/llm_client.py` (on behalf of Red, Blue, analyst) | `llm_client` (budget), `stats/cost.py`, orchestrator, Dashboard | Red, Blue (D6: Red sees only its HTTP responses) |
| Benign set | `benign/benign_set.json` | Designer (verified by `tools/verify_benign_set.py`) | Orchestrator, stage checks | **Blue** |
| Benign requests | `data/runs/<match_id>/benign_requests.jsonl` | Benign sender (orchestrator) | Judge (fact 4a), Dashboard | **Blue** |
| Benign results | `data/runs/<match_id>/benign_results.jsonl` | Judge (fact 4a) | Stats, Dashboard | Red, **Blue** |
| Anomalies | `data/runs/<match_id>/anomalies.jsonl` | Judge (fact 4a) | Stats, stage checks, humans | Red, **Blue** |
| Price table | `config/prices.json` | Designer | `llm_client`, `stats/cost.py`, orchestrator | — |
| LLM config | `config/llm.json` | Designer | `llm_client`, orchestrator | — |

Join key across red_attacks, benign_requests, proxy, verdicts, rounds and
benign_results: **`request_id`**.

The proxy log is staged at `data/runs/live/proxy.jsonl` during a match and frozen
into the match directory before Blue and the Judge run (see §3). Every other per-match
artifact is written directly into `data/runs/<match_id>/`.

---

## 9. Known limitations

### Requests that climb above the web root are invisible

nginx percent-decodes and normalizes the request URI while it parses the request
line, before it reads any headers and before any configuration applies. A path
whose dot-segments climb above the root (for example `/ftp/..%2f..%2fetc/passwd`,
which decodes to `/ftp/../../etc/passwd`) is rejected with **400** at that point
and never forwarded to the Target.

Because the headers were never read, the line is logged with an **empty
`request_id` and an empty `path`**:

```json
{"timestamp":"...","request_id":"","method":"GET","path":"","query":"","body":"","status":400}
```

- The line is **stray** (Traffic rule, §0), so it is **invisible to Blue and the
  Judge**. The Red record it belongs to becomes an orphan round (§6).
- **Red must never send requests that climb above the web root.** CWE-22 payloads
  must target Juice Shop's own traversal challenges (for example the `/ftp`
  directory and its null-byte tricks), which stay inside the root.
- Traversal that stays inside the root (for example `/ftp/..%2fftp/legal.md`) is
  forwarded unchanged and logged with its raw path.

### Target quirk: the `/ftp/` listing's body is 59 bytes short

Juice Shop's `/ftp/` directory listing declares `Content-Length: 11343` but sends
11284 bytes (recorded 2026-11-09, v20.3.0). Reproduced inside the Docker network
without nginx (wget from the nginx container straight to `juice-shop:3000`) and with
curl through the proxy (curl exit 18). It is the Target's bug. The request is logged
normally (status 200), so Blue sees it. The shared arena client tolerates **only**
this case: status line and headers fully received, body shorter than its
Content-Length → the status is returned with `body_incomplete: true`. A connection
closed before the headers, a timeout, a truncated chunked body or any malformed
response is still an error. Benign entry `n08` hits it every match
(`benign/verification.json`, `known_target_quirks`).

---

## 10. Notes for later stages

### Stage 5: apostrophes in benign login traffic return 500

Juice Shop's login query is deliberately SQL-injectable, so a benign login whose
email contains an apostrophe (e.g. `O'Brien`) makes it return **500**. That 500
**solves the "Error Handling" challenge** (verified on v20.3.0). It solves no
challenge in `config/challenge_map.json`, so it cannot make a round `landed`, but
the Judge's before/after challenge diff will see it.

**Do not remove them from the benign set.** They are a deliberate false-positive
test: a quote character and a 500 status look like SQL injection, but the request
is benign, and Blue should still classify it as `benign`.

*Revised 2026-11-09 (Stage 5.2): kept, with a mechanism.* Ground truth labels the
**sender's intent**, not the server's reaction: the server breaking is the server's
bug. The request is benign entry **`h06`** (`sean.o'brien@example.com`, verified: 500,
newly_solved `["Error Handling"]`). Benign entries may declare `expected_solves`
(only challenges outside `config/challenge_map.json`, so no Red round can be
affected); `h06` declares `["Error Handling"]` and its 500 is expected and documented.
The `benign_solved_challenge` tripwire (§6.6) fires when a benign request's
`newly_solved` differs from its `expected_solves` in any way. Entry `h04` keeps a
quote and `--` in the **password**, which is hashed before the query (not
injectable), so it returns a plain 401.

---

## 11. Not-measurable `landed`

For any CWE whose `config/challenge_map.json` entry is **empty** (currently
`CWE-79`), landing cannot be measured. For a round with such a label the Judge
records `landed` as the **not-measurable state (`null`), not `false`**.

- These rounds are **excluded** from `landed` and landing-rate statistics (a `null`
  is neither a success nor a failure).
- They are **included normally** in detection statistics (`detected`,
  `type_correct`, FP/FN). Blue is still fully scored on whether it spots the attack
  in the log; only "did it actually succeed against the Target" is unanswerable.

This is one of the two cases where the Judge writes `null` for `landed` from
Stage 3 onward (`landed_reason: "not_measurable"`). The other is `already_solved`
(§6.1): a mapped challenge a prior round already solved cannot be re-attributed to
this round, so landing is unmeasurable here too and is likewise excluded from
landing stats while counting normally in detection stats.

**Why `CWE-79` is empty.** In this Docker deployment every XSS challenge that a
single HTTP request could trigger is marked `disabledEnv: "Docker"` (API-only,
Reflected, HTTP-Header, Server-side, Client-side, and Video XSS) — the server
sanitizes the payload instead of solving. The only XSS challenge enabled here,
**DOM XSS**, is solved by a websocket event (`verifyLocalXssChallenge`), which a
single HTTP request cannot send and the proxy HTTP log cannot observe. So no XSS
challenge is both HTTP-triggerable and proxy-observable, and CWE-79 landing is
not measurable without changing the deployment.

---

## 12. Future work

- **Measuring CWE-79 (XSS) landing.** It would require either running Juice Shop
  **outside Docker** (so the `disabledEnv: "Docker"` XSS challenges become solvable),
  or driving a **websocket client** to trigger DOM XSS. The first breaks target
  isolation (design principle 6); the second puts a non-HTTP channel outside the
  proxy, breaking the proxy-log-only model (design principle 3) since the solve
  would never appear in `proxy.jsonl`. Both are **out of scope for v0**; CWE-79
  landing stays not-measurable (§11).
