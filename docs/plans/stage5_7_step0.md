# Stage 5.7 — Step 0 plan: prompt caching + first AI-vs-AI matches

Written before any code, for the designer's OK. Branch `stage5.7-caching-ai-vs-ai`
(from `main` at `ed53b79`). Real calls only at Gates 1–3, each after a separate GO.

## 1. Facts this plan rests on (checked in the code and the pinned SDKs)

- **Blue prompt sizes.** Prompt v1 (off) is 1,334 characters plus a 372-character
  output schema. Prompt v2 (shadow/on) is 3,430 characters plus an 857-character
  schema. In the committed gate-5.5 runs, the total input per call was 843–909 tokens
  for v1 and 1,859–1,925 for v2; the per-line part varies by about 70 tokens.
  - My estimate is about 350–400 tokens for the v1 system text and about 900 for v2.
  - **v2 clears Haiku 5.5's 512-token minimum. v1 probably does not**, unless the
    structured-output schema counts toward the cached prefix. The docs don't say.
    See conflict C1.
- **Anthropic.** `cache_control` goes on content blocks. The render order is tools →
  system → messages, and a breakpoint on the last system block caches everything
  before it. The 5-minute TTL is written `{"type": "ephemeral", "ttl": "5m"}`.
  - The usage fields `cache_read_input_tokens` and `cache_creation_input_tokens` are
    separate from `input_tokens`.
  - `usage.cache_creation` splits writes into `ephemeral_5m_input_tokens` and
    `ephemeral_1h_input_tokens`.
  - A prefix below the minimum is silently not cached: there is no error, and the
    write count is 0.
- **OpenAI (`openai==3.41.0`).**
  - `prompt_cache_options = {mode: implicit|explicit, ttl: "30m"}`.
  - Explicit breakpoints go on input content blocks as
    `prompt_cache_breakpoint: {mode: "explicit", ttl?: "30m"|"12h"}`.
  - With `explicit` mode there is no implicit breakpoint. A request writes up to its 4
    latest breakpoints, and matching looks at the latest 80, with no lookback limit.
  - Usage has only `input_tokens_details.cached_tokens` and `.cache_write_tokens`.
    **There is no split by TTL.** See C4.
  - 5.6 sends `{mode: "explicit"}` with no breakpoints, which is why caching is off
    today.
- **Red prompt sizes.** The first turn is 357 input tokens and each turn adds about
  300 (golden match1: 357, 605, 897, 1192, 1510, …). See C2.
- **Cost math (`stats/cost.py`).** Savings are already net of the write premium and
  can be negative: `cached × (in − cached_price) − write × (write_price − in)`. Today
  only the match total is printed.

## 2. Plan: files

Each file below is changed or added. New files are marked **NEW**.

| File | Change |
|---|---|
| `config/llm.json` | `agents.blue.caching` and `agents.red.caching`: `"off"` (default). The global `provider_caching: false` key is removed (C3). Notes updated. |
| `agents/llm_client.py` | Validates `caching` per agent. `Adapter.call(..., cache: bool)`. The Anthropic adapter sends `system` as one text block with `cache_control` when caching is on. The OpenAI adapter sends `prompt_cache_options {mode: explicit, ttl: 30m}` plus breakpoints on user turns when on. Off sends exactly what is sent today. Both adapters also map `unpriced_cache_write_tokens` (C4). The "STILL TO VERIFY" comments stay until Gate 1 is signed off. |
| `agents/prompting.py` | No change. The history is already append-only, and the adapter adds the markers. |
| `blue/claude_engine.py` | Passes the agent's caching setting to `complete()`. `blue_params` gains `caching: {mode, ttl}`. The prompts and their hashes are unchanged. |
| `red/ai_red.py` | Same for Red. `red_params.request.prompt_caching` (a free-text string today) becomes `caching: {mode, ttl}`. `RED_PROMPT_VERSION` stays `"1"`: the text is unchanged, and caching is recorded separately. |
| `stats/cost.py` | Cost line printed per agent: `blue $x (calls n; cache read r / write w tok; net savings $s)`. The total and its flags stay. A negative net is printed as negative. `unpriced_cache_write_tokens > 0` sets `unpriced_usage` and `lower_bound`, so the match stops (existing path). |
| `run_match.py` | `--blue-caching off\|on` and `--red-caching off\|on` (the default comes from config). MANIFEST 0.7. `--red ai --blue claude` with a rules mode and caching on both is supported end to end (only a wiring test is needed; the loop exists). The summary prints the four-facts result. |
| `tools/replay_blue.py` | `--caching off\|on`. replay.json 0.2 carries the new `blue_params`. |
| `tools/four_facts.py` **NEW** | `check(match_dir)`: facts 1 and 2 in `rounds.jsonl` (`landed` and `detected` fields present on every non-orphan row, at least one row), facts 3 and 4b in `rule_results.jsonl` (at least one row, `replay_fires` and `fixture_fires` present), fact 4a in `benign_results.jsonl` (at least one row). Returns per-fact pass/fail with a reason. It has a CLI and is used by run_match's summary and Gate 3. |
| `tools/stage5_7_gate1.py` **NEW** | Gate 1. Refuses without `--real-calls` or on a dirty tree. Blue: 2 calls with prompt v2, caching on, on two different golden lines (same prefix). Red: a dry-run generation of N turns (C2) with caching on and fixed synthetic feedback (`"dry run: request not sent"`); nothing is sent, and the run goes through `ai_red.RedBrain` and `llm_client`. Prints the raw usage objects, the `api_calls.jsonl` lines and the cost per call. Writes to `data/replays/gate1-5.7-<id>/` (git-ignored). |
| `tools/stage5_7_check.py` **NEW** | `--gate 2`: 4 replays, rules mode on with caching on, against the committed `data/golden/replays/gate-5.5/*-on`. Per source it prints cost with caching vs the committed cost, the uncached counterfactual from the same `api_calls` (C5), cache read/write tokens, and net savings. `--gate 3`: 3 live `--red ai --blue claude` matches, Blue rules on, caching on for both, same seed. It prints the Gate 3 report, runs the four-facts check, scaffolds the D16 audit files and generates the audit sheets. Both refuse without `--real-calls` or on a dirty tree. |
| `tools/audit_match.py` | No logic change expected; Gate 3 calls its scaffold and sheet functions. (If needed, an `--all-in` option for several matches.) |
| `tools/stage4_check.py` | Expects manifest 0.7. |
| Schemas | See §3. |
| Docs | `docs/contract.md` (§3), `docs/stage5_decisions.md` (D18 caching; D11 marked done), `docs/progress.md`, `CLAUDE.md`, `README.md`, `docs/ops.md` (cache flag note). |

### Tests (fake provider and mock transports only)

- `tests/test_caching.py` **NEW**
  - Caching off: the Anthropic and OpenAI request bodies are byte-identical to
    today's, captured with the existing mock transports against a stored golden body.
  - Caching on: the diff from the off body is only the markers. For Anthropic that is
    `system` turned into one block with `cache_control {ephemeral, 5m}`. For OpenAI it
    is `prompt_cache_options` plus `prompt_cache_breakpoint` on user turns, with
    content in block form.
  - The prefix sent is byte-identical across Blue calls (same system block) and
    across Red turns: request N+1 starts with request N's input items, markers
    included.
  - Usage mapping: an Anthropic read or write maps to `cached_input_tokens` /
    `cache_write_tokens`, with `input_tokens` untouched. An OpenAI read or write is
    subtracted from `input_tokens`.
  - An Anthropic `ephemeral_1h_input_tokens > 0`, an OpenAI 12h breakpoint in the
    request, or an unknown non-zero write-detail field each gives
    `unpriced_cache_write_tokens`, which leads to `unpriced_usage`, a stopped match and
    a refused next call.
- `tests/test_cost.py`: per-agent lines; cost with reads and writes; a negative net
  (writes only, no reads); an unpriced write.
- `tests/test_four_facts.py` **NEW**: passes on a complete fixture. Fails, naming the
  fact, on a missing or empty `rule_results.jsonl` (rules mode off), an empty
  `benign_results.jsonl`, or rounds without `landed`.
- `tests/test_run_match_ai_vs_ai.py` **NEW**: `--red ai --blue claude
  --blue-rules-mode on`, caching on for both. Fake Ops and the fake provider. Checks
  the cache flags reach both clients, manifest 0.7 records them, and the four-facts
  check passes.
- Updated: `test_schemas` (new versions + frozen copies), `test_llm_client` (the
  `caching` key, removal of `provider_caching`), `test_anthropic_adapter`,
  `test_openai_adapter`, `test_blue_claude` / `test_ai_red` (params), `test_run_match_*`,
  `test_replay_blue`, `test_key_hygiene` (cache paths).
- Unchanged and required to pass: scripted paths, the 5.5 gate-evidence re-score,
  and the 5.2 stage check against the live stack.

## 3. Contract and schema diff (the 5.1 rule: bump + frozen copy)

| Schema | Version | Change |
|---|---|---|
| `api_call` | 0.1 → **0.2** | Adds required `unpriced_cache_write_tokens` (int ≥ 0, or null when there was no usage; 0 on refusals): cache-write tokens whose TTL has no price in `config/prices.json` (Anthropic 1h, OpenAI 12h, or an unknown write breakdown). `cache_write_tokens` keeps counting all writes. The frozen copy is `api_call_v0_1`, and `cost.py` reads both. |
| `match_manifest` | 0.6 → **0.7** | `blue_params.caching` and `red_params.caching`: `{mode: "off"\|"on", ttl: "5m"\|"30m"\|null}` (`ttl` is null iff mode is off). `red_params.request.prompt_caching` (free text) is removed. The frozen copy is `match_manifest_v0_6`. |
| `replay_manifest` | 0.1 → **0.2** | `blue_params` carries `caching` (same shape). The frozen copy is `replay_manifest_v0_1`, and the committed gate-5.5 `replay.json` files stay valid against it. |
| `config/llm.json` (contract §6.4) | — | `agents.<a>.caching`; `provider_caching` removed. |

Contract text:
- §6.4 config.
- The api_call table: the field above, and the "verify" notes rewritten after Gate 1.
- §6.5 the per-agent cost line.
- §6.6 red_params.
- A new §6.10 on caching: what is cached per agent, the TTLs, and the rule that
  caching is held constant within a comparison.
- A new §6.11 on the four-facts check.

`JUDGE_VERSION` is unchanged, because no Judge or `rules/` logic changes.

## 4. Where each cache breakpoint goes, and why

**Blue (Anthropic, Haiku 5.5): one explicit breakpoint, on the system block.**
- Every Blue call is stateless (D14): the system prompt, the output schema (as
  `output_config.format`), then a single user message holding one proxy line. Only
  the user message changes.
- A marker on the system text block caches everything up to and including the system
  prompt, so each call after the first reads it.
- Automatic (top-level) caching would put the breakpoint on the last block, which is
  the unique user message. Every call would then pay the write premium on bytes never
  read again, a pure surcharge. So the marker is explicit.
- Whether the structured-output schema is inside the cached prefix isn't documented.
  Gate 1 shows it: `cache_creation_input_tokens` on call 1 is the size of the cached
  prefix exactly.
- **TTL: 5 minutes** (`ttl: "5m"`, the only write price in `prices.json`). Blue's calls
  run back to back after Red has finished (and in replays), seconds apart, so a
  5-minute entry stays warm. Each read resets the timer.
- v1 and v2 are different prefixes, so they are separate cache entries. Within a
  mode the prefix never changes. The rule-first flow skips calls but doesn't touch the
  prefix.

**Red (OpenAI, gpt-6-luna): explicit mode, one breakpoint at the end of each user
turn, kept on every earlier user turn.**
- A Red request is `instructions` (the system prompt, a top-level string that can't
  carry a breakpoint), then the append-only history: user₁, assistant₁, user₂, …, userₙ.
- On call n:
  - every user turn carries `prompt_cache_breakpoint {mode: explicit}`, with the TTL
    inherited from `prompt_cache_options.ttl = "30m"`;
  - the latest marker (end of userₙ) writes the whole prompt;
  - the marker at the end of userₙ₋₁, written by call n−1, is the read point. **Cached
    on call n: instructions + user₁ … userₙ₋₁ (with the assistant turns between).**
  - **Uncached on call n: assistantₙ₋₁ + userₙ**, about 300 tokens per turn;
  - call 1 reads nothing and writes everything.
- Markers stay on earlier turns because the history must stay byte-identical. Removing
  a marker from userₙ₋₁ on call n+1 would change bytes in the prefix. With markers on
  every user turn, each request is an exact extension of the previous one. A request
  writes its 4 latest markers; at most 10 user turns, well under the 80 used for
  matching.
- `mode: explicit` (not implicit) makes the cache points ours: deterministic and
  testable. It is also the mode 5.6 already uses, so caching off simply means no
  markers.
- **TTL: 30 minutes.** It is sent explicitly in `prompt_cache_options` and never on a
  breakpoint. A 12h TTL is never sent. If one is ever present in a request, or the
  usage reports a write we can't price, the call's writes count as unpriced and the
  match stops (C4).
- A brain-failure retry (`propose()` keeps history unchanged) sends the same prefix
  again, which is a cache read.

## 5. Gates (each after a separate GO, from a clean committed tree)

- **Gate 1.**
  - Blue: 2 calls, v2 + caching on. Expected: call 1 shows a write about the prefix
    size and 0 reads; call 2 shows that prefix as a read. Plus 1 call with v1 + caching
    on, so we learn whether v1 caches at all (C1). That is 3 Blue calls, about
    $0.0006.
  - Red: a dry run of N turns (C2), about $0.001.
  - I report the raw usage, the `api_calls` lines and the cost for your dashboard
    comparison. The verify flags are removed only after you confirm both dashboards.
- **Gate 2.** 4 replays (mode on, caching on). About 90 Blue calls, about $0.012
  expected, about $0.02 at most.
- **Gate 3.** 3 live AI-vs-AI matches. About 10 Red and about 25 Blue calls each,
  roughly $0.01 per match, about $0.03 total (each match under the $0.50 match cap).
  The audit files are scaffolded and the sheet is generated; the audited numbers count
  only after your audit.

## 6. Conflicts / decisions for the designer

- **C1. Blue v1 is probably below Haiku 5.5's 512-token cache minimum.** It is about
  350–400 tokens of system text; it clears 512 only if the schema overhead counts.
  If it doesn't, caching on is a silent no-op in rules mode off (0 reads, 0 writes,
  cost unchanged). That is harmless and honest.
  - **Recommendation:** accept it, measure it at Gate 1 (the extra v1 call), and
    record the outcome. Do **not** pad the prompt: that would change the brain and the
    v1 hash, which must stay identical to 5.4.
  - Gate 2 uses v2, which caches either way.
- **C2. Red's early turns may be below OpenAI's cache minimum.** The pinned SDK says
  the boundary "is not rounded to a token block", but it doesn't state a minimum for
  gpt-6-luna. OpenAI's minimum has historically been 1,024 tokens. Turns 1–3 are about
  357, 605 and 897 tokens, so a 3-turn dry run might show no cache read at all.
  - **Recommendation:** make the Gate 1 Red dry run **5 turns** (turn 4 ≈ 1,190, turn
    5 ≈ 1,510), about $0.001 more. Otherwise keep 3 turns, as written in the brief,
    and accept that the gate may only verify "no cache below the minimum".
- **C3. `provider_caching: false` is a global key the client requires to be false.**
  - **Recommendation:** remove it in favour of the per-agent `caching` switch the brief
    asks for (default off, same effect). Keeping both would create two switches for
    one thing.
- **C4. OpenAI usage has no TTL split**, so a 12-hour write can't be seen in the usage
  alone.
  - **Recommendation:** detect it on the request side. Any breakpoint or option with a
    TTL other than 30m in the request we sent makes all of that call's
    `cache_write_tokens` unpriced. An unknown non-zero write-detail field in the raw
    usage does the same. Anthropic is symmetric: `ephemeral_1h_input_tokens` is
    unpriced.
  - This needs the new `api_call` field `unpriced_cache_write_tokens` (§3). The other
    fields' meaning doesn't change.
  - Our code only ever sends 30m and 5m, and a test forces the 12h path.
- **C5. Gate 2 vs the committed gate-5.5 "on" numbers is not perfectly clean.** The
  inputs are the same (D17), but AI output varies run to run. The number of lines
  answered by rules, and so the call count, can differ, so "cost with vs without
  caching" mixes the caching effect with run-to-run variation.
  - **Recommendation:** report both:
    - (a) this run's cost vs the committed run's cost, as asked;
    - (b) the same-run counterfactual (the same `api_calls` priced as if uncached =
      cost + net savings), which isolates caching exactly;
    - plus cost per AI call for both runs.
- **C6. The Gate 3 "same seed" fixes only the schedule.** The seed fixes the benign
  interleaving. AI Red's proposals are not seeded (temperature can't be set), so the
  three matches differ in their attacks; the seed holds the benign traffic and its
  slots constant. Recorded as such.
- **C7. The four-facts check fails when Blue stores no rule.** With
  `rule_results.jsonl` absent or empty, the check fails, which is correct per the
  definition. A Gate 3 match where Blue invents no rule is reported as "four facts:
  FAIL (no rules)", not hidden.
- **C8. Gate 3 audits.** The 3 matches are dev runs (`data/runs/`, git-ignored), so
  their audit files go to `data/audits/<match_id>.jsonl` (git-ignored, the existing
  rule) and the sheets to `docs/audits/` (committed).
  - **Question:** should these 3 matches be committed as golden evidence after your
    audit (like gate-5.5)? My recommendation is yes, since AI output isn't
    reproducible. That would be done later, only on your word.
