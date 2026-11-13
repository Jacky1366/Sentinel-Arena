# Stage 5 — Locked decisions

*Recorded 2026-11-08 (Stage 5.1); D14 added 2026-11-12 (Stage 5.4); D15 added 2026-11-13
(Stage 5.6). These are decided. Later stage prompts refer to them by number (D1–D15) instead of repeating them. Changing one is a designer
decision and is recorded here with a date. Where a decision touches an artifact
format, `docs/contract.md` remains the source of truth.*

## Sub-stage map

| Sub-stage | Scope |
|---|---|
| 5.1 | Repo safety, these decisions, LLM client wrapper + cost tracking (no real API calls) |
| 5.2 | Benign traffic + fact 4a |
| 5.3 | Rule engine + facts 3 / 4b |
| 5.4 | AI Blue — first real call (Anthropic; pinned SDK added here) |
| 5.5 | Blue rule invention |
| 5.6 | AI Red (OpenAI; pinned SDK added here; GPT-6 Luna model id confirmed before this) |
| 5.7 | Integration + provider-side caching |

## Decisions

**D1 — Benign traffic has two layers.** Benign requests are interleaved through the
proxy during a match (verdict-level false positives), plus a fixed benign fixture
(rule-level false positives).

**D2 — Fact 3 is an offline replay.** A rule is evaluated against the frozen
recorded request. The Judge never touches the network.

**D3 — A rule is declarative data, never code.** AI-written code is never executed.
Regexes run on a linear-time engine (RE2): no backtracking features, and a
per-field size cap.
*Reworded 2026-11-09 (Stage 5.3, designer decision). Was: "Every regex runs with a
timeout (ReDoS)." RE2 makes catastrophic backtracking impossible by construction
instead of interrupting it; patterns that need backtracking features
(backreferences, lookaround) are rejected by the validator with their own reason.*

**D4 — Freeze-then-Blue stays.** Blue processes the log in `log_seq` order and code
guarantees no look-ahead. A new rule applies only to later lines ("hot-load").

**D5 — AI Red's label must be a taxonomy enum value.** Label truthfulness is a
measurement limitation, checked by a `label_mismatch` tripwire and a manual audit
sample.

**D6 — Red's only feedback is its own HTTP responses.** It never sees Judge or Blue
output. Red's prompt never mentions port 8081.

**D7 — Red has no cross-match memory** (controlled variable). Blue's cross-match
memory is Stage 6.

**D8 — No AI ever sees a `request_id`.** Blue sees a local index; the body maps
index → `request_id`.

**D9 — Verdicts gain `source: "rule" | "ai"`.** The rule engine runs first; the AI is
asked only when no rule fires.
*Implemented 2026-11-12 (Stage 5.4): `source` is `"signature" | "ai" | null` in
verdicts 0.2 (scripted Blue's signatures are `"signature"`; `null` iff there is no
verdict). `"rule"` is added in 5.5.*

**D10 — Cost tracking comes before caching.** Token counts are raw evidence; dollars
are derived later from a dated price table.

**D11 — Prompts are built stable-prefix-first from the start.** Provider-side prompt
caching is enabled only after the agent loop is stable (Stage 5.7).

**D12 — Development uses the cheapest current-generation model per provider.**
Stronger models are only for flagship tests and the golden run.

**D13 — A call refused by the body is an instrument failure, not a subject
failure.** A refusal (cap reached, missing price, missing key, unpriced usage) says
nothing about Red's or Blue's skill. Requests left without a verdict for this reason
will get a distinct reason (e.g. `budget_exhausted`) and be **excluded from detection
stats like orphans, never counted as a miss**. The rule is recorded now; the
contract field is added in Stage 5.4, when Blue first makes real calls.
*Implemented 2026-11-12 (Stage 5.4, designer-approved plan). The reason is named
`instrument_failure` (not `budget_exhausted`), because it also covers an API failure
after the retries, not only a body refusal. Verdict rows carry `no_verdict_reason`
`no_verdict` (brain failure: invalid / incomplete reply, model safety refusal,
`max_tokens`; a miss on attacks) or `instrument_failure` (body refusal or API failure;
excluded from detection and FP stats, shown as its own rate). The Judge cross-checks
every `instrument_failure` against `api_calls.jsonl` and raises on any mismatch in
either direction (contract §4).*

**D14 — What AI Blue sees, and how it is asked.** Per proxy line only `method`,
`path`, `query` and `body`, raw and exactly as logged, plus a local `index`; never
`request_id`, `timestamp`, `log_seq`, `status`, byte counts, the client address or any
response field (contract §4.1). One stateless call per line, in `log_seq` order
(fixed system prompt + that line); `chunk_size > 1` only for unscored runs. The prompt
is kept neutral: it names the four labels, says values may be percent-encoded, and
gives no decoding instructions and no hints aimed at the benign set (never tuned
against it). Its output example is schematic, not a real label, so it cannot anchor
the model. **Thinking, effort, the output format and the output-token cap are part of
the Blue configuration and must be held constant within any comparison** (recorded in
`match.json` `blue_params`). Temperature cannot be set (Haiku 5.5, API version
`2026-10-21`), so run-to-run variation is measured, not suppressed.
*Recorded 2026-11-12 (Stage 5.4).*

**D15 — Red's scope is enforced structurally, and its feedback is HTTP-only.** AI Red
supplies only the method, the path (with any query string) and the body; the body fixes
the scheme, host and headers and sends through the shared client (contract §2.2). Before
anything is sent the body guards the proposed request; a failed guard sends nothing,
records a `red_guard.jsonl` line, consumes the slot, and tells Red next turn that its
request was blocked and why (rules of engagement, never Judge information). Guard reasons:
`scope_violation`, `method_not_allowed` (allowlist GET/POST for dev), `invalid_encoding`,
`above_root` (matches nginx limitation #1; `tools/verify_red_guard.py` checks it),
`invalid_label`, `path_too_large`, `body_too_large`. Red's only feedback is its own HTTP
result — the status code and a response body truncated to 500 chars, delimited as
untrusted data — plus that rules-of-engagement text; never Judge facts, snapshots, Blue
verdicts, or anything about other traffic (D6). *Recorded 2026-11-13 (Stage 5.6).*

## Implementation notes (Stage 5.1)

- One exit for every AI call: `agents/llm_client.py`. Every attempt and every
  refusal is a line in `api_calls.jsonl` (contract §6.3).
- Caps are required per agent (red, blue, analyst) plus a match total
  (`config/llm.json`); Red can never spend Blue's share. Before each attempt the
  worst case (input estimated at 1 token per 3 characters of the built prompt, plus
  `max_output_tokens`, priced at the applicable tier) must fit every cap. If a reply
  is far larger than the estimate, the overshoot is at most that one call.
- Retries count toward `max_calls`.
- A null `cached_input` price is charged at the full input price and flagged. Cache
  writes with a null `cache_write` price stop the match with `stopped_by` reason
  `unpriced_usage` (never `max_usd`: the manifest must not claim a budget was hit
  when it was not).
- Dollars stored in `match.json` are a snapshot tied to the price table's sha256;
  `stats/cost.py` can recompute them against any later table.
- Keys come only from `ARENA_*_API_KEY` and are passed explicitly to each SDK
  (`docs/ops.md`).

## Implementation notes (Stage 5.2, D1 layer 1)

Designer decisions recorded 2026-11-09:

- **Benign is the sender's intent**, not the server's reaction. `h06` (O'Brien logs
  in) stays although the server answers 500 and solves "Error Handling"; contract
  §10 is kept and revised, not superseded.
- **`expected_solves`** (optional, default `[]`) per benign entry, only challenges
  outside `config/challenge_map.json`. The `benign_solved_challenge` tripwire fires
  on ANY difference between a benign request's `newly_solved` and its
  `expected_solves`.
- **A successful benign login exists** (`n10` register → `n11` log in, 200), so
  "login 200 = attack" is not a shortcut an AI Blue could learn.
- **The schedule preserves the internal order of BOTH sequences**; the seeded
  shuffle decides only the interleaving. `requires` in the set is a second
  guarantee checked by the validator, not the mechanism.
- **FP denominator = the benign set only.** Red's negative control (round 1) stays a
  Red round: a fact-1 control and a detection true positive.
- **Scripted Blue's signatures are never tuned against the benign set** (and the set
  is never tuned against them): its FP rate is a measurement.
- **One shared sender** (`runner/arena_client.py`) for Red, benign and probes; no
  User-Agent for anyone. It tolerates only a body shorter than its Content-Length
  (Juice Shop's `/ftp/` listing quirk, contract §9) and nothing else.
- **Expectations are hand-predicted before the first run**
  (`tools/stage5_2_expected.json`); any mismatch is reported to the designer before
  that file changes.
- `match.json` 0.3 (0.2 frozen), `failed_step` `red` → `traffic`, `JUDGE_VERSION`
  0.2.0, `benign_fp` kept as always-null, precision printed with its traffic mix,
  `anomalies.jsonl` created now (the Stage 6 tripwire log, first two kinds).

## Implementation notes (Stage 5.3, D1 layer 2, D2, D3)

Designer decisions recorded 2026-11-09:

- **Rule format** (contract §5): `cwe` + 1–3 AND-ed conditions on request-side
  fields only (`method`, `path`, `query`, `body`); `contains` / `equals` / `regex`;
  pattern ≤ 200 chars. No OR between conditions (several rules instead);
  alternation `|` inside one regex is allowed. `created_match` stays optional; Stage
  6 decides.
- **Neutral `rules/` package** (normalization, validator, RE2 engine), imported by
  Blue and the Judge. The Judge never imports `blue/`. Any behaviour change in
  `rules/` is governed by `JUDGE_VERSION` (0.3.0 from this step).
- **Normalization v2**, fixed now, before 5.4 produces any AI data (changing it
  later would make AI runs before and after incomparable): additive, every decode
  step plus `+`-decoding for query/body. Gate passed: scripted Blue's 31 golden
  verdicts are identical. Decoding stays content-type agnostic (recorded, not
  changed). Blue's cross-field matching (its joined haystack) is not changed.
- **Facts 3 and 4b** are per rule (`rule_results.jsonl`); `replay_blocked` and
  `benign_fp` in round records stay always null and go at the next round-record
  version bump. `source_label` / `cwe_matches_source` are kept; rule results are
  Red ground truth, so Blue never reads them. Rule retention (Stage 6) is decided
  by code from Judge facts.
- **The fact-4b fixture is the golden benign lines, verbatim, and is not held
  out.** A second, never-sent benign set is planned before Stage 6.

## Implementation notes (Stage 5.4, D13, D14)

Designer decisions recorded 2026-11-12:

- **SDK `anthropic==2.3.0`** (newest release at least 14 days old). The adapter passes
  `api_key` and `base_url="https://api.anthropic.com"` explicitly and disables the
  SDK's OpenTelemetry tracing, so no `ANTHROPIC_*` variable or profile can change the
  key or the host (tested with a mock transport).
- **Prices:** Haiku 5.5 and Sonnet 5.5 designer-verified 2026-11-12; Opus 5.5 stays
  unverified. A real provider's unverified price is refused (`price_unverified`).
- **Blue 5.4 configuration** (D12, cheapest): `max_output_tokens` 256, thinking
  disabled, effort low, structured outputs on (a JSON schema with the label enum). Part
  D validation still runs on every reply: we measure security judgment, not JSON
  compliance. Any `max_tokens` stop in Gate 2 is reported: at 256 it means our cap is
  wrong, not the model.
- **`model_refusal` and `max_tokens` are brain failures** (`no_verdict`). The
  `model_refusal` count is also printed separately, split by attack and benign lines.
- **After the first body refusal Blue stops calling**; every remaining line is
  `instrument_failure` without a call. An API failure after retries affects only that
  call's lines.
- `verdicts`, `rounds`, `benign_results` 0.2; `match.json` 0.4; `api_calls.jsonl`
  stays 0.1 (`stop_reason`, `price_unverified`); `JUDGE_VERSION` 0.4.0.
- Two gates, each only after the designer's explicit GO: Gate 1
  (`tools/stage5_4_smoke.py`, one real call) and Gate 2 (`tools/stage5_4_check.py`, 3
  seeded `--blue claude` matches).

## Implementation notes (Stage 5.6, D5, D6, D7, D13, D14, D15)

Designer decisions recorded 2026-11-13:

- **SDK `openai==3.41.0`** (newest release ≥ 14 days old), **Responses API**: it gives
  `reasoning.effort`, structured output (`text.format` json_schema strict),
  `max_output_tokens`, `store=false`, and clean brain-failure signals (`status`
  incomplete → `max_output_tokens`; a refusal output item). Dev model **gpt-6-luna**
  (D12; id confirmed from the pinned SDK's model list), reasoning effort **low**,
  `max_output_tokens` **2048** (reasoning tokens count toward it), round cap **10**.
- **OpenAI env isolation:** the adapter scrubs every `OPENAI_*` variable from the
  environment while constructing the client and passes `api_key` and `base_url`
  explicitly, so no env value can change the key, host, organization, project or
  headers. The test keeps sentinel `OPENAI_*` values set *during the request* and
  asserts only our key and host go out (per request, not only at construction).
- **Prices:** `gpt-6-luna` moved from `placeholders` into `models` (two tiers;
  `verified: false` until the designer confirms). Caching off (D11): the adapter sends
  `prompt_cache_options` with the implicit breakpoint disabled.
- **D13 for Red:** a body refusal or an API failure after retries is an
  `instrument_failure` slot (counted, never a subject failure); a model refusal,
  truncation or invalid output is a `brain_failure` slot. Both are `red_guard.jsonl`
  lines; neither crashes the match; Red is never re-asked within a slot.
- **label_mismatch (D5)** lives in `judge/red_facts.py` (a separate module; it shares
  `judge/anomalies.py` with fact 4a, which stays about benign traffic). It appends to
  `anomalies.jsonl` after the benign step.
- **Formats:** `red_attacks.jsonl` 0.2 (source + rationale; v0_1 frozen); new
  `red_guard.jsonl`; `match.json` 0.5 (red_engine, red_params, nullable red_source,
  `judge_red` step; v0_4 frozen); `anomaly` gains `label_mismatch`; `JUDGE_VERSION`
  0.5.0. The scripted Red path is unchanged (the 5.2 stage check still passes).
- **Gates, each only after the designer's explicit GO:** Gate 1
  (`tools/stage5_6_smoke.py --real-call`, one generation, nothing sent) and Gate 2
  (`tools/stage5_6_check.py --real-calls`, 3 seeded `--red ai --blue scripted` matches,
  every attack printed for the D5 label audit). `tools/verify_red_guard.py` (zero-token)
  checks the guard against the real nginx before Gate 1.
