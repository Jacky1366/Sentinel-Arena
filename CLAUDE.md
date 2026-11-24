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
docs/stage5_decisions.md  locked Stage 5 decisions D1–D18 + sub-stage map
docs/stage6_decisions.md  Stage 6 decisions D19, S6-1..S6-3, D20–D41 (+ D24 amendment, criterion d′; D34 amendment; D15 amendment, D41)
docs/stage7_decisions.md  Stage 7 decisions D45–D59 (live demo, compare view, analyst report; plan in docs/plans/stage7_plan.md)
docs/plans/             stage plans (Step 0) as written before building
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
  verdict.schema.json             Blue verdict, schema_version 0.4 (rule_origin library|match; only with a rule library)
  verdict_v0_3.schema.json        frozen 0.3 verdict schema (source "rule" + fired_rule_ids; rules shadow/on, no library)
  verdict_v0_2.schema.json        frozen 0.2 verdict schema (scripted Blue and rules mode off still write 0.2)
  verdict_v0_1.schema.json        frozen 0.1 verdict schema (golden folders; readers dispatch on version)
  rule.schema.json                single Blue rule (Stage 5.3 format: cwe + 1-3 AND-ed conditions)
  rules_file.schema.json          rules.json wrapper (hand-written rules for tools/score_rules.py; D20)
  rule_library.schema.json        rule library file data/library/rule_library_vNNNN.json (cross-match memory, 6.1)
  variant.schema.json             one variants.jsonl line (judge/variants.py; Blue never reads)
  retention_row.schema.json       one retention.jsonl line (judge/retention.py; Blue never reads)
  retention_manifest.schema.json  retention.json (tools/promote_rules.py, written last)
  benign_holdout.schema.json      one line of benign/holdout_v1.jsonl or fixture_v2_offline.jsonl
  benign_offline_draft.schema.json  benign/*.draft.json (offline benign drafts)
  test_set.schema.json            config/test_set.json
  free_play_audit.schema.json     free-play binary audit row (attack attempt yes/no, D41)
  analyst_summary.schema.json     analyst summary.json (contract 6.15, #16): figures + sources + D60 confidence
  analyst_draft.schema.json       the AI analyst's draft (contract 6.16): prose with {{placeholders}}, no confidence / recommendation field
  grounding_result.schema.json    grounding check result (contract 6.17)
  autonomy_table.schema.json      the autonomy table JSON (contract 6.13)
  dashboard_bundle.schema.json    one dashboard bundle (contract 6.14)
  rule_result.schema.json         facts 3 + 4b per rule (Blue never reads)
  rule_score.schema.json          rule scoring manifest
  match_rule.schema.json          one rules.jsonl line (a rule Blue invented in a match, 5.5)
  rule_rejection.schema.json      one rule_rejections.jsonl line (a rejected proposal + reasons)
  replay_manifest.schema.json     replay.json (tools/replay_blue.py, D17), schema_version 0.3 (blue_params.library)
  replay_manifest_v0_2.schema.json frozen 0.2 replay schema (the committed gate-5.7 replays)
  replay_manifest_v0_1.schema.json frozen 0.1 replay schema (the committed gate-5.5 replays)
  benign_fixture.schema.json      one fact-4b fixture line
  round_record.schema.json        Judge output, schema_version 0.3 (verdict_source may be "rule")
  round_record_v0_2.schema.json   frozen 0.2 round-record schema
  round_record_v0_1.schema.json   frozen 0.1 round-record schema
  match_manifest.schema.json      match.json (orchestrator manifest), schema_version 0.8 (purpose, blue_params.library)
  match_manifest_v0_7.schema.json frozen 0.7 manifest schema
  match_manifest_v0_6.schema.json frozen 0.6 manifest schema
  match_manifest_v0_5.schema.json frozen 0.5 manifest schema
  match_manifest_v0_1.schema.json frozen 0.1 manifest schema (validators dispatch on version)
  match_manifest_v0_2.schema.json frozen 0.2 manifest schema
  match_manifest_v0_3.schema.json frozen 0.3 manifest schema
  match_manifest_v0_4.schema.json frozen 0.4 manifest schema
  api_call.schema.json            one api_calls.jsonl line, schema_version 0.2 (unpriced_cache_write_tokens, 5.7)
  api_call_v0_1.schema.json       frozen 0.1 api_call schema
  prices.schema.json              config/prices.json
  benign_set.schema.json          benign/benign_set.json
  benign_request.schema.json      benign ground truth (Blue never reads)
  benign_result.schema.json       Judge fact 4a output, schema_version 0.3
  benign_result_v0_2.schema.json  frozen 0.2 benign-result schema
  benign_result_v0_1.schema.json  frozen 0.1 benign-result schema
  anomaly.schema.json             anomalies.jsonl (harness self-checks)
  landed_fact.schema.json         Judge fact-1 intermediate (Stage 2)
config/
  taxonomy.json         ["CWE-89","CWE-79","CWE-22","benign"]
  challenge_map.json    CWE -> Juice Shop challenge names
  test_set.json         TEST data registry (S6-1): the 6 audited AI-Red golden match ids + the 12 Stage 6.3 eval ids (Gate B, B-deepseek, B-evasion, B-freeplay), test_purposes [eval], sealed offline benign hashes
  prices.json           USD per million tokens per model (designer-maintained, dated)
  llm.json              models per agent, timeouts/retries, required per-agent + match caps; agents.blue.rules (mode off|shadow|on, max_rules); agents.<agent>.caching (off|on, 5.7)
rules/                  NEUTRAL rule machinery (Blue AND the Judge import it; governed by JUDGE_VERSION)
  normalize.py          THE request normalization (v2): raw + every decode step + '+'-decoding
  validator.py          rule validator: machine-readable reason per rejection; RE2 compile
  engine.py             pure rule engine: (validated rules, request) -> firing rule_ids
  hotload.py            hot-loaded rule set: only earlier-line rules fire; earliest wins tie-break (Blue + Judge); library rules preloaded first (6.1)
  library.py            READ-ONLY rule library reader + canonical form (no write path; Blue + Judge)
  paths.py              the ONE above-root predicate (red guard + variant mutator, D32)
library/writer.py       the ONE rule library writer (imported only by tools/promote_rules.py, D26)
agents/llm_client.py    the single exit for every AI call: retries, caps, api_calls.jsonl; prompt caching markers + unpriced cache lifetimes (5.7); DeepSeek adapter + off-peak guard (6.3)
agents/prompting.py     stable-prefix-first prompt builder + safe JSON parsing
proxy/nginx.conf        nginx: log+forward arena :8080, admin :8081 (access_log off)
red/payloads.json       scripted-Red attack set (data, verified empirically)
benign/benign_set.json  designer-approved benign set (normal + hard negatives, expected_solves)
benign/send_benign.py   load/validate the set; write benign record, then send one request
benign/verification.json  empirical verification record of the set (fresh Target per entry)
benign/fixture_v1.jsonl fact-4b fixture: golden benign proxy lines, verbatim (+ .meta.json sha256)
benign/holdout_v1.draft.json  TEST holdout draft (40); sealed as holdout_v1.jsonl at Gate 0 (never sent in a match)
benign/holdout_v1.jsonl       TEST holdout, sealed Nov 18 (+ .meta.json; sha256 in config/test_set.json)
benign/fixture_v2_offline.draft.json  TRAIN offline CWE-22 look-alikes (6, D31); sealed with the holdout
benign/fixture_v2_offline.jsonl  TRAIN offline fixture, sealed Nov 18 (+ .meta.json)
runner/arena_client.py  THE shared HTTP sender (Red, benign, probes): same headers, no UA
runner/schedule.py      seeded interleaving; preserves Red order AND benign order
runner/go_token.py      the GO token: gate tools need ARENA_GO=<gate id>; any real AI client a well-formed token (6.1b)
run_match.py            orchestrator: one complete match -> frozen data/runs/<match_id>/
red/scripted_red.py     write labeled record, then fire one attack (one step at a time); write_and_send shared with AI Red
red/ai_red.py           AI Red (5.6): versioned prompts (v1; v2 = D40 evasion; v3 = D41 free-play: any attack + other/technique/headers), one proposal per slot, reply validation
red/red_guard.py        rules of engagement (D15; D41 free-play mode: label other + Cookie/Authorization headers): scope/method/encoding/above-root/label/header/size guards
runner/match_ops.py     the ONE code path for preflight/lock/reset/rotate/snapshot/freeze
stats/match_stats.py    pure counts + rates over rounds.jsonl (terminal summary); rule vs AI split, rules block (5.5)
stats/cost.py           pure cost over api_calls.jsonl + price table
stats/autonomy.py       autonomy table (M6): per-CWE detection / FP / rule coverage by origin / calls / cost; CP bound for 0/n
analyst/confidence.py   D60 (a) as code: figure / finding confidence; exact Clopper-Pearson 95%
analyst/summary.py      #16: summary.json from frozen evidence via the existing stats (no payloads, D53)
analyst/grounding.py    #16: grounding check (placeholders, bare numbers, number words, refs, recommendation; D55, D60 b)
liveserver/             Stage 7 #12: read-only live server (stdlib, 127.0.0.1, SSE) + tailer; `python -m liveserver` (README)
stats/test_data.py      D59: is a folder TEST data? by manifest (match_id, purpose, replay source), never by name; scannable() for any folder scan
stats/free_play.py      free-play measurement (D41): landing = any solve (+ category), detection binary over audited attempts; pure stats layer over the Judge
blue/signatures.py      generic OWASP-style CWE signatures (no payload-file peeking)
blue/run_blue.py        Blue: classify proxy-log requests (--engine scripted | claude, --rules-mode)
blue/claude_engine.py   AI Blue (5.4): prompts v1 (off) / v2 (shadow, on); v3-open (D42, replay-only: widened attack definition + other/technique); one stateless call per line, reply validation, rule-first flow (5.5)
blue/rule_invention.py  the body's half of rule invention: fills ids/cwe/source, validates, caps -> rules / rejections
judge/fact1_landed.py   pure landed computation over artifacts (no network)
judge/fact2_detected.py pure detected/type_correct computation; 0.1/0.2 verdicts; instrument_failure cross-check vs api_calls.jsonl
judge/round_record.py   join fact 1 + fact 2 -> rounds.jsonl (validated)
judge/fact4_benign.py   fact 4a: benign false positives -> benign_results.jsonl + anomalies.jsonl
judge/red_facts.py      label_mismatch tripwire (D5): AI-Red attack solving a cross-CWE challenge
judge/anomalies.py      shared anomaly validator/writer (fact 4a and red_facts)
judge/rule_facts.py     facts 3 (offline replay) + 4b (benign fixture) per rule (uses rules/, never blue/); judge_rules step (5.5)
judge/rule_verdicts.py  Judge cross-check: re-runs the hot-load sequence (with the library snapshot), raises on any inconsistent rule verdict/artifact
judge/variants.py       variant mutator (M3): pure, seeded; per-variant counting classification (D24)
judge/retention.py      retention decisions (M2): pure; every failing criterion recorded (D23)
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
tools/audit_match.py          D16 label audit: scaffold / validate / apply (raw vs audited, --json) / sheet; AI labels only; replay folders
tools/stage5_6_smoke.py       Gate 1 (5.6): ONE AI-Red generation, nothing sent (--real-call; GO only)
tools/stage5_6_check.py       Gate 2 (5.6): 3 seeded --red ai matches, prints every attack (--real-calls; GO only)
tools/replay_blue.py          D17: Blue + full Judge on a copy of a frozen match -> data/replays/<id>/ (never writes the source); --blue-prompt open (D42), --thinking (6.3)
tools/stage5_5_check.py       Gate (5.5): 12 replays, 4 golden matches x off/shadow/on, prints every rule (--real-calls; GO only)
tools/four_facts.py           Stage 5 done-when check: facts 1, 2, 3, 4a, 4b computed -> PASS / N/A (no rules) / FAIL
tools/autonomy_table.py       autonomy table over frozen folders -> Markdown + JSON (6.2, zero token)
tools/free_play.py            free-play (D41): binary audit scaffold/sheet + report
tools/build_summary.py        #16: build / --check the analyst summary.json; refuses test or unknown sources without ARENA_GO (D59)
config/analyst_sources.json   #16: the summary's source groups (paths and roles only)
tools/export_dashboard.py     one frozen folder -> dashboard bundle + bundles.js (6.4, read-only)
tools/promote_rules.py        the ONLY path into the rule library: a train match -> retention evidence + a new library version
tools/build_holdout.py        capture + seal the offline benign files outside any match (--capture = Gate 0, GO only; --check)
tools/stage6_1_check.py       6.1b: Gate 1 (5 train matches) / --promote / --predict (zero token) / Gate 2 (M5 replays); GO only
tools/stage6_3_check.py       6.3 flagship gate: A (--estimate zero token; --probe), B (3 eval matches, Sol Red), C (Sonnet / empty-library replays); GO + token only
tools/stage5_7_gate1.py       Gate 1 (5.7): cached-token mapping, Blue 3 calls + Red dry run, raw usage (--real-calls; GO only)
tools/stage5_7_check.py       Gates 2-3 (5.7): caching effect on the gate-5.5 sources; 3 AI-vs-AI matches + audits (--real-calls; GO only)
dashboard/src/battle/    Stage 7 #13: Battle view (three acts), pure model.js (LIVE + REPLAY), live.js (the ONE EventSource)
dashboard/test/         node:test for the Battle model (run by tests/test_dashboard_battle.py)
dashboard/              offline match playback (React + Tailwind; 6.4): open dashboard/dist/index.html; bundles in public/data/ (README)
data/runs/live/         nginx stages proxy.jsonl here (+ archive/, match.lock); git-ignored
data/runs/<match_id>/   frozen match output incl. match.json (git-ignored)
data/replays/<replay_id>/  Blue replays incl. replay.json (git-ignored, D17)
data/library/           rule library versions v0000.. + retention/<match_id>/ evidence (ALL committed: raw evidence is never deleted)
data/golden/scripted-baseline-match/  committed scripted baseline run, Stage 4 (see its README)
data/golden/scripted-baseline-benign-match/  scripted baseline run with benign traffic, Stage 5.2
data/golden/claude-blue-haiku-first-match/  first AI Blue run (Haiku 5.5, Stage 5.4 Gate 2 run 1; see its README)
data/golden/ai-red-luna-gate2-match{1,2,3}/  first audited AI-Red batch (5.6 Gate 2; held-out candidate set)
data/golden/ai-vs-ai-gate3-match{1,2,3}/  first AI-vs-AI matches, audited (5.7 Gate 3; four facts PASS; never rewritten)
data/golden/train-6.1b-gate1-match{1..5}/  Stage 6.1b Gate 1 TRAIN matches (purpose train; audits in data/audits/; fed library v1-v5)
data/golden/eval-6.3-gateB-match{1,2,3}/  Stage 6.3 Gate B EVAL matches (TEST data, D35; Luna high Red vs Haiku + v5; full audits in data/golden/audits/)
data/golden/eval-6.3-gateB-deepseek-match{1,2,3}/  Stage 6.3 Gate B-deepseek EVAL matches (TEST data; deepseek-v4-pro max Red vs Haiku + v5; full audits)
data/golden/eval-6.3-gateB-evasion-match{1,2,3}/  Stage 6.3 Gate B-evasion EVAL matches (TEST data; D40: + Red prompt v2 evasion directive; full audits)
data/golden/eval-6.3-gateB-freeplay-match{1,2,3}/  Stage 6.3 Gate B-freeplay EVAL matches (TEST data; D41 exploratory: Red prompt v3 any-attack; binary audits)
data/golden/incidents/     archived failed / instrument-failure runs (never deleted, never in test_set.json)
data/audits/<match_id>.jsonl  D16 designer label audits for dev matches (git-ignored)
data/golden/audits/     D16 label audits of committed golden matches (committed)
data/golden/replays/gate-5.5/  Stage 5.5 gate evidence: 12 real-call Blue replays + README (never rewritten)
data/golden/replays/gate-5.7/  Stage 5.7 Gates 2/2b evidence: 8 cached Blue replays (rules on/off) + README (never rewritten)
data/golden/replays/gate-6.1b-2/  Stage 6.1b Gate 2 (M5) evidence: 3 Gate 3 sources x {empty v0000, library v5} + README (never rewritten)
data/golden/stats/      committed autonomy tables (autonomy_6.1b.{md,json}: the three M5 arms)
data/golden/replays/gate-6.1b-2b/  Stage 6.1b Gate 2b evidence: the same 3 sources, rules off (prompt v1) + README (never rewritten)
data/golden/replays/gate-6.3-C/  Stage 6.3 Gate C evidence: 3 Gate B eval sources x {Sonnet + v5 (between_tools), Haiku + v0000} + README (never rewritten)
data/golden/replays/gate-6.3-C-open/  Stage 6.3 D42 open-Blue evidence: 6 v3-open replays (free-play + deepseek) + FP check + README (never rewritten)
data/golden/incidents/     archived failed / instrument-failure runs (never deleted, never in test_set.json)
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
tests/test_red_guard.py     the rules-of-engagement guards (D15; D41 free-play labels + headers)
tests/test_ai_red.py        AI Red engine: prompt, validation, history, feedback, info wall
tests/test_run_match_red.py --red ai driver loop + wiring (fake Ops + fake provider)
tests/test_audit.py         D16: audit schema, audited view, audit-first flag, audit_match tool, scripted = valid
tests/test_rule_hotload.py  hot-load timing, tie-break, conflict flag (pure)
tests/test_blue_rules.py    rule invention: prompt v2, modes off/shadow/on, proposals, cap, refusals (fake provider)
tests/test_rule_verdicts.py Judge rule-verdict cross-check, incl. tampered artifacts
tests/test_run_match_rules.py  --blue-rules-mode wiring, judge_rules, match.json 0.6 (fake Ops + provider)
tests/test_replay_blue.py   replay = live run, never writes the source, refusals, audits, gate tool offline
tests/test_caching.py       caching off = pre-5.7 bytes, on = markers only, stable prefix, usage mapping, unpriced lifetimes
tests/test_four_facts.py    the four-facts check: PASS / N/A (no rules) / FAIL
tests/test_run_match_ai_vs_ai.py  --red ai --blue claude with caching flags, four facts, gate tools offline
tests/test_gate_5_5_evidence.py  committed gate replays: hashes, source links, Judge re-scores identically
tests/test_gate_5_7_evidence.py  committed Gate 2/2b replays: hashes, sources, verdicts = gate-5.5, re-score, 2x2
tests/test_gate_5_7_gate3_evidence.py  committed Gate 3 AI-vs-AI matches: hashes, config, re-score, four facts PASS, audits, cost
tests/test_rule_paths.py    the single above-root predicate; judge/ never imports red/
tests/test_rule_library.py  reader, canonical dedup, writer: versioned, never overwritten, never golden / test ids
tests/test_hotload_library.py  library rules live from line 1, first in the tie-break
tests/test_blue_library.py  AI Blue + library: no call, rule_origin, identical prompt bytes, 0.4 only with a library
tests/test_rule_verdicts_library.py  match with a library end to end; Judge cross-check on tampered artifacts; --purpose
tests/test_variants.py      mutator determinism, each transformation, per-variant classification (synthetic sources)
tests/test_retention.py     every reason code, dedup, cap, advisory behavioural duplicates
tests/test_promote_rules.py promotion end to end + every refusal (D26, D27, D30)
tests/test_train_test_wall.py  writer unreachable from match/replay code; leak test over every library file
tests/test_holdout_set.py   offline benign drafts, mocked capture + seal, drift check
tests/test_stage6_1_gates_offline.py  gate tool refusals, prediction, Gates 1-2 on the fake provider
tests/test_gate_6_1b_gate1_evidence.py  committed Gate 1 train matches, audits, library v0000-v0005 + retention; v5 sha = progress.md
tests/test_gate_6_1b_gate2_evidence.py  committed M5 replays (gate-6.1b-2, -2b): hashes, sources, library snapshots, cost
tests/test_autonomy.py      autonomy table: every column, CP bound, audit nulls, CLI (non-test folders)
tests/test_autonomy_6_1b_evidence.py  committed 6.1b table regenerates byte for byte
tests/test_export_dashboard.py  bundles copied from artifacts, cost totals, demo bundles regenerate, dashboard offline
tests/test_stage6_3_offline.py  6.3: red effort, purpose eval, promotion refuses eval, estimate, Gates B/C offline
tests/test_gate_6_3_gateB_evidence.py  committed Gate B eval matches: hashes, D38 config, test-set registration, full audit scaffold
tests/test_gate_6_3_gateB_deepseek_evidence.py  committed Gate B-deepseek eval matches: hashes, DeepSeek config, rate windows, test-set registration, full audit
tests/test_gate_6_3_gateB_freeplay_evidence.py  committed Gate B-freeplay eval matches: hashes, prompt v3 config, challenge catalog, binary audit
tests/test_gate_6_3_c_open_evidence.py  committed open-Blue (D42) replays: hashes, v3-open prompt, 2a recovery of landed other-class misses, 2b taxonomy unchanged
tests/test_gate_6_3_gateB_evasion_evidence.py  committed Gate B-evasion eval matches: hashes, prompt v2 sha, timeout, test-set registration, full audit
tests/test_gate_6_3_gateC_evidence.py  committed Gate C replays: hashes, sources, library snapshots, arm config (Sonnet between_tools), cost
tests/test_analyst_confidence.py  D60 table, cap, finding minimum, CP interval vs committed figures
tests/test_analyst_summary.py     summary figures = existing stats, no payloads, sources/hashes, CLI GO gate (synthetic data only)
tests/test_analyst_grounding.py   planted bad drafts rejected per code, a valid draft accepted, confidence by code
tests/live_fakes.py         fake live match: real orchestrator + traffic loop, fake provider, stubbed network
tests/test_live_tailer.py   tailer: every artifact line -> one event, causal order, catch-up, failures
tests/test_live_server.py   live server: SSE in order, reconnect, static, read-only, loopback, lab ports refused
tests/test_dashboard_battle.py  Battle model via node --test: a fake live match + every committed bundle through three acts
tests/test_test_data.py     D59 helper: manifest not folder name (the slip reproduced), eval purpose, replays, unknown skipped, only manifests opened
tests/test_go_token.py      every paid entry point (gate tools, direct run_match / replay_blue, real clients) refuses without ARENA_GO; only llm_client imports an SDK
```

## How to run the stack

```bash
docker compose up -d --wait     # starts Juice Shop + nginx; returns once healthy
tools/smoke_test.sh             # Stage 1: expects 4 valid, 2 stray, 0 invalid
.venv/bin/python tools/stage2_check.py   # Stage 2: runner + Judge, all PASS
.venv/bin/python tools/stage3_check.py   # Stage 3: full pipeline (Blue + round record)
.venv/bin/python run_match.py            # one complete match -> data/runs/<match_id>/
ARENA_GO=manual-<what> .venv/bin/python run_match.py --blue claude  # AI Blue: REAL, PAID calls (needs ARENA_ANTHROPIC_API_KEY + designer GO)
ARENA_GO=manual-<what> .venv/bin/python run_match.py --red ai       # AI Red: REAL, PAID calls (needs ARENA_OPENAI_API_KEY + designer GO)
.venv/bin/python tools/replay_blue.py --match <frozen dir> --engine scripted  # replay Blue (D17)
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

## Autonomy policy (designer-approved)

Ask for the designer's GO only when a step:
1. spends money (any real provider call or gate),
2. reads test-set data (config/test_set.json matches, holdout), or
3. changes what counts as evidence (retention criteria, Judge scoring, taxonomy,
   train/test split, audit rules).

Everything else — implementation choices, test moves/refactors, docs, schema bumps,
pure-code sub-stages — decide yourself, apply it, and list it under "Decided without
asking" in your report. Escalate only if unsure which category a step falls in.

Stage 7 lanes (designer, 2026-11-24; apply from #12 on).
- Important lane: #16 and #17. Stop for my review of the Step 0 plan, and stop again for
  my review before merging.
- Fast lane: every other Stage 7 issue. Put the plan in the PR description and proceed
  without waiting. Merge your own PR (Create a merge commit) once all tests pass. For
  dashboard changes, attach screenshots to the PR.
- Escalation: a fast-lane PR that touches the Judge, docs/contract.md, data/library/,
  data/golden/, config/test_set.json, agents/llm_client.py, CLAUDE.md or
  docs/*_decisions.md moves to the important lane.
- Never idle: when blocked on my review or GO, move to the next unblocked fast-lane issue.
- GO is unchanged: every paid call and every test-set read still needs my explicit GO
  token. Keep reporting "Decided without asking" in every PR.

## Working notes

- Python 3.11+. Always run Python via the project venv: `.venv/bin/python`
  (e.g. `.venv/bin/python -m pip install -r requirements.txt`,
  `.venv/bin/python -m pytest`). Never use the system `python3`.
- Schemas hardcode taxonomy enums. If `config/taxonomy.json` changes, update the
  schemas and contract too. Tests catch drift.
- `rules_file.schema.json` `$ref`s `rule.schema.json` by `$id`. Validators need a
  `referencing.Registry` that contains both (see `tests/test_schemas.py`).
- **Stage 6.1a (Nov 17):** rule library, retention, variant mutator, offline benign drafts,
  M5 tooling, built on the fake provider; branch `stage6.1a-rule-library`. Gate 0 (holdout
  capture + seal) done Nov 18; D24 amendment approved Nov 18 (`encoding_only`
  excluded from (d); new criterion (d′) `encoding_fragile`).
  Plan `docs/plans/stage6_1_step0.md`, decisions `docs/stage6_decisions.md`.
- **Test-set data rule (designer, 2026-11-18, revised the same day):**
  1. Protected data = the TEST SET only: the match ids in `config/test_set.json`, any match
     whose `purpose` is in its `test_purposes` (D35: `eval` is test data from the moment it
     exists, registered or not, including failed eval runs in `data/golden/incidents/`),
     replays of those matches, and the holdout set (`benign/holdout_v1.*`). Other golden
     folders (scripted baselines, the first Claude Blue match, gate-5.5 / gate-5.7 replays)
     are not test data. (Corrected 2026-11-24: the `test_purposes` clause was missing from
     this summary; D35 is the decision of record.)
  2. Committed read-only integrity tests (hash / re-score / unchanged-folder checks) have a
     standing GO and stay in the default suite.
  3. Any NEW code, test, debugging or exploratory run that reads test-set data needs the
     designer's explicit GO first.
  4. Offline tests never replay test-set matches (`tests/test_stage6_1_gates_offline.py`
     swaps in non-test golden folders and fails on any test-set replay). Only the real
     6.1b gates (Gate 2, `--predict`) touch the Gate 3 matches, each after a GO.
  5. **Scans (D59):** any scan over match or replay folders goes through
     `stats/test_data.scannable()`, which classifies a folder by its manifest (`match_id`,
     `purpose`, a replay's `source.match_id`). Never filter by folder name: golden folders
     are not named by match id (the 2026-11-24 slip, `docs/progress.md`).
- **Failed / instrument-failure runs are archived and marked, never deleted.** Raw evidence
  is never deleted (instrument failures are excluded from stats by D13, not removed). A failed
  run under `data/runs/` is kept, or archived to `data/golden/incidents/` with its cause;
  deleting a run folder is category 3 and needs the designer's GO (a Gate B-freeplay run was
  deleted in error, Nov 19).
- **Never chain a commit after tests with `;`.** Use `&&`, or run the tests, check the
  result, then commit (a failing suite once preceded a commit, Nov 18).
- **Paid runs need the GO token**, set for that one command only after the designer's GO
  (`docs/ops.md`):
  - Gate tools need their exact id: `ARENA_GO=gate-<id>`.
  - Any real provider client needs a well-formed token: `gate-<id>` or
    `manual-<short-description>`. This covers direct `run_match.py --blue claude / --red ai`
    and `replay_blue.py --engine claude`, and is enforced at the single exit,
    `agents/llm_client.py`.
  - Tests never set it. Only `agents/llm_client.py` may import a provider SDK
    (`tests/test_go_token.py`).
- Only `tools/promote_rules.py` may write a rule library (D26); never import `library/` from
  match, replay, Blue or Judge code (tests/test_train_test_wall.py). Never use golden or
  holdout data to select or tune rules (S6-1).
- **Stage 5 is done (Nov 14):** all three Stage 5.7 Gate 3 AI-vs-AI matches reach four
  facts PASS. Stage 5.7 (prompt caching per agent, D18; first AI-vs-AI matches; four-facts
  check): done, branch `stage5.7-caching-ai-vs-ai` (not merged yet); Gates 1–3 passed;
  evidence in `data/golden/replays/gate-5.7/` (Gates 2/2b) and
  `data/golden/ai-vs-ai-gate3-match{1,2,3}/` + `data/golden/audits/` (Gate 3, first AI-vs-AI
  label audit: 27 valid, 1 invalid).
- Stage 5.5 (Blue rule invention, modes off / shadow / on; hot-load; replay mode D17):
  built and tested on the fake provider (Nov 13), branch `stage5.5-rules-invention`; the
  gate (`tools/stage5_5_check.py --real-calls`, 12 replays) run and accepted Nov 13 ($0.057):
  **done**; evidence in `data/golden/replays/gate-5.5/` (not merged yet).
  Stage 5.6 (AI Red, OpenAI): done, Gates 1–2 + first D16 label audit (Nov 13), merged.
  Stage 5.4 (AI Blue) is done (Gates passed Nov 12).
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
- **Claude in Chrome (Stage 7, designer 2026-11-24): allowlist.** The browser may open
  ONLY the dashboard: the live server on `127.0.0.1` or `file://`. Every other port of the
  lab stack is off limits: the arena proxy (`127.0.0.1:8080`; requests are written to the
  proxy log and contaminate any match in progress), the Judge admin port
  (`127.0.0.1:8081`), and Juice Shop's own port if it is ever published (a direct visit can
  change Juice Shop state even without touching the proxy log: solved challenges are
  sticky).
- ALL arena traffic goes through `runner/arena_client.py`. Never tune Blue's
  signatures and the benign set against each other. A change to
  `benign/benign_set.json` needs a re-run of `tools/verify_benign_set.py` (a test
  checks the verification record's sha256 matches the set).
- Test fakes for `run_match.Ops` must override every network step
  (`test_fake_ops_override_every_network_step`): a fake that falls through sends
  live traffic to the Target.
