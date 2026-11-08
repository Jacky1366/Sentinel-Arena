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
Every regex runs with a timeout (ReDoS).

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
