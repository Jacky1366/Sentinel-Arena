# Stage 5 — Locked decisions

*Recorded 2026-11-08 (Stage 5.1). These are decided. Later stage prompts refer to
them by number (D1–D13) instead of repeating them. Changing one is a designer
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
