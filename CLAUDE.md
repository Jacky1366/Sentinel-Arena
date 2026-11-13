# CLAUDE.md — Sentinel Arena

## Project summary

Sentinel Arena is a closed-loop evaluation harness for AI defenders. A **Red** AI
attacks OWASP Juice Shop through an nginx reverse proxy. A **Blue** AI reads only the
proxy log, outputs verdicts, and invents detection rules. A pure-code **Judge** scores
every round. Components do NOT call
each other; they communicate only through file artifacts (JSON / JSONL) defined in
`docs/contract.md`. An orchestrator (`run_match.py`, later) controls the order.

Roles: the user is the **designer**; Claude is the **implementer**.

## THE RULE

**`docs/contract.md` is the source of truth. Never change an artifact format without
updating the contract and schemas first, and tell the designer.**

## Design principles

1. The proxy has NO defenses (no WAF, rate limit, auth). It only logs and forwards.
   All defense lives in Blue so the Judge can measure it.
2. We control the log format, so the Target is swappable.
3. Blue only reads the log. It is never on the live traffic path.
4. The Judge is pure deterministic code. Never use an LLM to judge.
5. The taxonomy limits Red's label vocabulary, not its attack techniques.
6. Only attack our own isolated Target. Juice Shop is never exposed outside the proxy.
7. Never commit secrets. API keys live only in `.env`.
8. ALL arena traffic, both attack and benign, carries `X-Arena-Request-Id` and is
   sent by the same HTTP client. Otherwise header presence leaks ground truth to Blue.
   Log lines with a missing or empty `request_id` are stray traffic: loaders skip
   and count them, never crash. Any other non-matching `request_id` is invalid.

## Directory map

```
CLAUDE.md               this file
README.md               overview, architecture diagram, how to run tests and the stack
docker-compose.yml      Juice Shop (internal only) + nginx (arena :8080, admin :8081)
docs/contract.md        data contract v0 (SOURCE OF TRUTH)
docs/progress.md        human-readable build progress (not authoritative)
docs/stage5_decisions.md  locked Stage 5 decisions D1–D16 + sub-stage map
docs/ops.md             keys (ARENA_* names), gitleaks hook, key-leak playbook, exit codes
.githooks/pre-commit    gitleaks scan of staged changes (enable: git config core.hooksPath .githooks)
.claude/settings.json   Claude Code deny rules: never read .env / .env.* (docs/ops.md)
schemas/                JSON Schema (draft 2020-12) per artifact
  red_attack.schema.json          Red ground truth, schema_version 0.2 (source + rationale; Blue never reads)
  red_attack_v0_1.schema.json     frozen 0.1 Red attack schema
  red_unsent.schema.json           red_unsent.jsonl: AI-Red slots with no sent attack (Blue never reads)
  match_audit.schema.json         D16 designer label audit, one line per Red round (never read by Red/Blue)
  proxy_log.schema.json           nginx log line (Blue's only input)
  challenge_snapshot.schema.json  before/after solved state (measurement)
  verdict.schema.json             Blue verdict, schema_version 0.2 (verdict or no_verdict_reason)
  verdict_v0_1.schema.json        frozen 0.1 verdict schema (golden folders; readers dispatch on version)
  rule.schema.json                single Blue rule (Stage 5.3 format: cwe + 1-3 AND-ed conditions)
  rules_file.schema.json          rules.json wrapper (cross-match memory)
  rule_result.schema.json         facts 3 + 4b per rule (Blue never reads)
  rule_score.schema.json          rule scoring manifest
  benign_fixture.schema.json      one fact-4b fixture line
  round_record.schema.json        Judge output, schema_version 0.2 (instrument_failure, verdict_source)
  round_record_v0_1.schema.json   frozen 0.1 round-record schema
  match_manifest.schema.json      match.json (orchestrator manifest), schema_version 0.5 (red_engine, red_params)
  match_manifest_v0_1.schema.json frozen 0.1 manifest schema (validators dispatch on version)
  match_manifest_v0_2.schema.json frozen 0.2 manifest schema
  match_manifest_v0_3.schema.json frozen 0.3 manifest schema
  match_manifest_v0_4.schema.json frozen 0.4 manifest schema
  api_call.schema.json            one api_calls.jsonl line (attempt or refusal)
  prices.schema.json              config/prices.json
  benign_set.schema.json          benign/benign_set.json
  benign_request.schema.json      benign ground truth (Blue never reads)
  benign_result.schema.json       Judge fact 4a output, schema_version 0.2
  benign_result_v0_1.schema.json  frozen 0.1 benign-result schema
  anomaly.schema.json             anomalies.jsonl (harness self-checks)
  landed_fact.schema.json         Judge fact-1 intermediate (Stage 2)
config/
  taxonomy.json         ["CWE-89","CWE-79","CWE-22","benign"]
  challenge_map.json    CWE -> Juice Shop challenge names
  prices.json           USD per million tokens per model (designer-maintained, dated)
  llm.json              models per agent, timeouts/retries, required per-agent + match caps
rules/                  NEUTRAL rule machinery (Blue AND the Judge import it; governed by JUDGE_VERSION)
  normalize.py          THE request normalization (v2): raw + every decode step + '+'-decoding
  validator.py          rule validator: machine-readable reason per rejection; RE2 compile
  engine.py             pure rule engine: (validated rules, request) -> firing rule_ids
agents/llm_client.py    the single exit for every AI call: retries, caps, api_calls.jsonl
agents/prompting.py     stable-prefix-first prompt builder + safe JSON parsing
proxy/nginx.conf        nginx: log+forward arena :8080, admin :8081 (access_log off)
red/payloads.json       scripted-Red attack set (data, verified empirically)
benign/benign_set.json  designer-approved benign set (normal + hard negatives, expected_solves)
benign/send_benign.py   load/validate the set; write benign record, then send one request
benign/verification.json  empirical verification record of the set (fresh Target per entry)
benign/fixture_v1.jsonl fact-4b fixture: golden benign proxy lines, verbatim (+ .meta.json sha256)
runner/arena_client.py  THE shared HTTP sender (Red, benign, probes): same headers, no UA
runner/schedule.py      seeded interleaving; preserves Red order AND benign order
run_match.py            orchestrator: one complete match -> frozen data/runs/<match_id>/
red/scripted_red.py     write labeled record, then fire one attack (one step at a time); write_and_send shared with AI Red
red/ai_red.py           AI Red (5.6): fixed prompt (RED_PROMPT_VERSION), one proposal per slot, reply validation (OpenAI)
red/red_guard.py        rules of engagement (D15): scope/method/encoding/above-root/label/size guards, run by the body
runner/match_ops.py     the ONE code path for preflight/lock/reset/rotate/snapshot/freeze
stats/match_stats.py    pure counts + rates over rounds.jsonl (terminal summary)
stats/cost.py           pure cost over api_calls.jsonl + price table
blue/signatures.py      generic OWASP-style CWE signatures (no payload-file peeking)
blue/run_blue.py        Blue: classify proxy-log requests (--engine scripted | claude)
blue/claude_engine.py   AI Blue (5.4): fixed prompt (PROMPT_VERSION), one stateless call per line, reply validation
judge/fact1_landed.py   pure landed computation over artifacts (no network)
judge/fact2_detected.py pure detected/type_correct computation; 0.1/0.2 verdicts; instrument_failure cross-check vs api_calls.jsonl
judge/round_record.py   join fact 1 + fact 2 -> rounds.jsonl (validated)
judge/fact4_benign.py   fact 4a: benign false positives -> benign_results.jsonl + anomalies.jsonl
judge/red_facts.py      label_mismatch tripwire (D5): AI-Red attack solving a cross-CWE challenge
judge/anomalies.py      shared anomaly validator/writer (fact 4a and red_facts)
judge/rule_facts.py     facts 3 (offline replay) + 4b (benign fixture) per rule (uses rules/, never blue/)
tools/validate_log.py   classify proxy log lines: valid / stray / invalid
tools/smoke_test.sh     Stage 1 end-to-end check of the running stack
tools/stage2_check.py   Stage 2 end-to-end check (runner + Judge vs expected)
tools/stage3_check.py   Stage 3 end-to-end check (full pipeline vs expected)
tools/stage3_expected.json  reasoned Stage 3 expectations (not observed output)
tools/stage4_check.py   Stage 4 end-to-end check (run_match + frozen match dir)
tools/stage5_2_check.py Stage 5.2 check: two seeded matches, benign results, reproducibility
tools/stage5_2_expected.json  hand-predicted benign results for scripted Blue
tools/verify_benign_set.py    verify each benign entry on a freshly reset Target
tools/score_rules.py    score a rules file against a frozen match (never writes into a match folder)
tools/build_benign_fixture.py build / --check the fact-4b fixture from the golden match
tools/expressiveness_check.py Part F report: scripted Blue's signatures as rules
tools/stage5_3_rules.json     hand-written test rules; tools/stage5_3_expected.json their predictions
tools/stage5_4_smoke.py       Gate 1: ONE real Blue call on one golden line (--real-call; designer GO only)
tools/stage5_4_check.py       Gate 2: 3 seeded --blue claude matches, format + coverage (--real-calls; GO only)
tools/verify_red_guard.py     zero-token probe: the above_root guard matches real nginx (contract 9)
tools/audit_match.py          D16 label audit: scaffold / validate / apply (raw vs audited, --json) / sheet
tools/stage5_6_smoke.py       Gate 1 (5.6): ONE AI-Red generation, nothing sent (--real-call; GO only)
tools/stage5_6_check.py       Gate 2 (5.6): 3 seeded --red ai matches, prints every attack (--real-calls; GO only)
dashboard/              results viewer (not yet implemented)
data/runs/live/         nginx stages proxy.jsonl here (+ archive/, match.lock); git-ignored
data/runs/<match_id>/   frozen match output incl. match.json (git-ignored)
data/golden/scripted-baseline-match/  committed scripted baseline run, Stage 4 (see its README)
data/golden/scripted-baseline-benign-match/  scripted baseline run with benign traffic, Stage 5.2
data/golden/claude-blue-haiku-first-match/  first AI Blue run (Haiku 5.5, Stage 5.4 Gate 2 run 1; see its README)
data/golden/ai-red-luna-gate2-match{1,2,3}/  first audited AI-Red batch (5.6 Gate 2; held-out candidate set)
data/audits/<match_id>.jsonl  D16 designer label audits for dev matches (git-ignored)
data/golden/audits/     D16 label audits of committed golden matches (committed)
docs/audits/            generated, read-only label-audit sheets (never edit; regenerate)
tests/conftest.py           autouse guard: no ARENA_* key and no .env in any test (docs/ops.md)
tests/test_schemas.py       schema + taxonomy-drift tests
tests/test_validate_log.py  validate_log.py classification tests
tests/test_fact1_landed.py  Judge fact-1 unit tests (no Docker)
tests/test_snapshot_stability.py  runner snapshot stability (no Docker)
tests/test_fact2_detected.py  Judge fact-2 + round-record join (no Docker)
tests/test_blue_scripted.py   Blue decoding + information-wall tests (no Docker)
tests/test_match_stats.py     summary stats denominators (no Docker)
tests/test_run_match_failure.py  orchestrator failure/lock/rotate/freeze (no Docker)
tests/test_stage3_tripwire.py snapshot_missing tripwire (no Docker)
tests/llm_fakes.py          fake provider / prices / config for the LLM tests
tests/test_llm_client.py    retries, caps, refusals, usage per attempt (fake provider)
tests/test_prompting.py     byte-identical prompt prefix, JSON helper
tests/test_cost.py          cost math, tiers, net cache savings
tests/test_key_hygiene.py   a sentinel key never reaches any output
tests/test_arena_client.py  shared sender: short-body tolerance only; Red/benign header identity
tests/test_schedule.py      seeded schedule keeps both orders; one slot at a time
tests/test_fact4_benign.py  fact 4a shapes + anomalies (no Docker)
tests/test_benign_set.py    benign set + validator + verification record
tests/test_normalize.py     normalization v2 (additive) + the 31-verdict gate
tests/test_rule_validator.py  one reason per rejection; validator vs schema
tests/test_rule_engine.py   ops, any-form matching, RE2 speed, Part F
tests/test_rule_facts.py    facts 3 / 4b vs the hand predictions (incl. orphan source)
tests/test_score_rules.py   never writes into a match folder; deterministic
tests/test_benign_fixture.py  fixture is verbatim golden proxy lines
tests/test_anthropic_adapter.py  Anthropic adapter vs a mock transport: key/host, request settings, usage
tests/test_blue_claude.py   AI Blue engine: prompt, information wall (D14), validation, refusals
tests/test_instrument_failure.py  Judge cross-check, rounds/benign 0.2, stats denominators
tests/test_run_match_blue.py  --blue claude wiring with fake Ops + fake provider
tests/test_openai_adapter.py  OpenAI Responses adapter vs a mock transport: key/host/env, settings, usage
tests/test_red_guard.py     the rules-of-engagement guards (D15)
tests/test_ai_red.py        AI Red engine: prompt, validation, history, feedback, info wall
tests/test_run_match_red.py --red ai driver loop + wiring (fake Ops + fake provider)
tests/test_audit.py         D16: audit schema, audited view, audit-first flag, audit_match tool
```

## How to run the stack

```bash
docker compose up -d --wait     # starts Juice Shop + nginx; returns once healthy
tools/smoke_test.sh             # Stage 1: expects 4 valid, 2 stray, 0 invalid
.venv/bin/python tools/stage2_check.py   # Stage 2: runner + Judge, all PASS
.venv/bin/python tools/stage3_check.py   # Stage 3: full pipeline (Blue + round record)
.venv/bin/python run_match.py            # one complete match -> data/runs/<match_id>/
.venv/bin/python run_match.py --blue claude  # AI Blue: REAL, PAID calls (needs ARENA_ANTHROPIC_API_KEY)
.venv/bin/python run_match.py --red ai       # AI Red: REAL, PAID calls (needs ARENA_OPENAI_API_KEY)
.venv/bin/python tools/stage4_check.py   # Stage 4: run_match + frozen-dir checks
.venv/bin/python tools/stage5_2_check.py # Stage 5.2: 2 seeded matches, benign + reproducibility
.venv/bin/python tools/verify_benign_set.py  # re-verify the benign set (after any set change)
.venv/bin/python tools/validate_log.py   # validate the whole live log
docker compose down             # stop (the log in data/runs/live/ is kept)
```

- The arena proxy is at `http://127.0.0.1:8080` (Blue's input, logged). The Judge's
  admin path is `http://127.0.0.1:8081/api/Challenges` (measurement, `access_log
  off`). Both loopback only; Juice Shop has no host port.
- nginx appends to `data/runs/live/proxy.jsonl`. Each match rotates that log at the
  start (previous log archived to `data/runs/live/archive/`, never deleted; only an
  empty log is deleted) and freezes it into `data/runs/<match_id>/` after Red, both
  via `nginx -s reopen`. nginx keeps appending to a moved file until it reopens, so
  both steps raise if the fresh live log does not appear (contract §3).
- `run_match.py` refuses to start if `data/runs/live/` holds anything but
  `proxy.jsonl` and `archive/`, or if `match.lock` exists (stale lock after a crash:
  remove it by hand, never automatically). Every check tool (stage2/3/4) runs a full
  match, which resets the Target.
- Known limitation: nginx rejects paths that climb above the web root while
  parsing the request line, so they log as stray (empty `request_id` and path) and
  are invisible to Blue and the Judge. Red must never send them (contract §9).
- The smoke test's request (f) may solve a challenge. `run_match.py` resets the
  Target itself and refuses to run unless 0 challenges are solved.

## Working notes

- Python 3.11+. Always run Python via the project venv: `.venv/bin/python`
  (e.g. `.venv/bin/python -m pip install -r requirements.txt`,
  `.venv/bin/python -m pytest`). Never use the system `python3`.
- Schemas hardcode taxonomy enums. If `config/taxonomy.json` changes, update the
  schemas and contract too. Tests catch drift.
- `rules_file.schema.json` `$ref`s `rule.schema.json` by `$id`. Validators need a
  `referencing.Registry` that contains both (see `tests/test_schemas.py`).
- Stage 5.6 (AI Red, OpenAI): Gates 1–2 passed and the first D16 label audit is done
  (Nov 13); branch `stage5.6-ai-red`, not merged. Stage 5.4 (AI Blue) is done (Gates passed Nov 12).
  Before that: Stages 1–4, 5.1, 5.2 and 5.3 are implemented (Target + proxy; scripted Red + Judge
  fact 1; Blue v0 + Judge fact 2 + round record; `run_match.py` orchestrator +
  `match.json`; the AI body `agents/llm_client.py` + cost tracking, no real calls
  yet; benign traffic + Judge fact 4a; the rule format, RE2 rule engine and Judge
  facts 3 / 4b, tested with hand-written rules; not yet in the match pipeline). Follow the
  sub-stage map in `docs/stage5_decisions.md`; do not start a sub-stage until the
  designer asks.
- Keep the project out of iCloud-synced folders (Desktop / Documents): `.env` holds
  keys (`docs/ops.md`). The working copy lives in `~/dev/Sentinel-Arena`.
- Every AI call goes through `agents/llm_client.py`. API keys only from
  `ARENA_*_API_KEY`, passed explicitly; never rely on an SDK's default variable
  (`docs/ops.md`). Model ids come from config / CLI, never hardcoded in agent logic.
- Never read `.env` / `.env.*` or dump the environment (denied in
  `.claude/settings.json`); keys must never enter a session transcript.
- The pre-commit hook must stay enabled (`git config core.hooksPath .githooks`).
  Test fixtures must never contain key-shaped strings (build them at runtime).
- Bump `judge.JUDGE_VERSION` on any change to Judge logic, and on any behaviour
  change in `rules/` (shared by Blue and the Judge; the Judge never imports `blue/`).
- Never change `rules/normalize.py` behaviour without a new NORMALIZATION_VERSION
  and the 31-verdict gate (`tests/test_normalize.py`).
- ALL arena traffic goes through `runner/arena_client.py`. Never tune Blue's
  signatures and the benign set against each other. A change to
  `benign/benign_set.json` needs a re-run of `tools/verify_benign_set.py` (a test
  checks the verification record's sha256 matches the set).
- Test fakes for `run_match.Ops` must override every network step
  (`test_fake_ops_override_every_network_step`): a fake that falls through sends
  live traffic to the Target.
