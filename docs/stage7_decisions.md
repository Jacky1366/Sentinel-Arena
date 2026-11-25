# Stage 7 decisions

Decisions made during Stage 7 planning (2026-11-24). Numbering continues from
`docs/stage6_decisions.md` (last: D44). The scope freeze (D40) stands: Stage 7 adds no
new evidence. Live and test runs are `purpose=dev` and never enter a stat, the test set
or any eval pool.

## Demo

**D45 — Live demo is primary; the golden run is the fallback.**
The demo runs one live match. A recorded golden run is played only if the live path
fails, and is then announced as recorded, never presented as live. The live match is
`purpose=dev`: it is a sample, not evidence, and is never pooled.

**D46 — Live configuration.**
- Red: `deepseek-v4-pro`, effort max, free-play (prompt v3, D41), round cap 10,
  caps as in the free-play arm (red $0.40, match $0.40).
- Blue: the D44 default — `claude-haiku-5-5`, rules on, caching on, library v5 read-only.
- Backup Red: `gpt-6-luna`. Free-play prompt v3 has never been run with Luna. E2E
  testing (D58) must confirm it; if refused, the backup falls back to prompt v1
  (taxonomy, validated in Gate B).
- The demo timeout and retry settings are chosen from the timing run (issue: timing run).

**D47 — The orchestrator is unchanged; the demo has three acts.**
Blue and the Judge stay post-traffic (design principle 3: Blue reads only the frozen
log). No per-line live Blue. The demo is shown as:
1. Act 1, attack — live: Red records, proxy lines, challenge snapshots, unsent/failed turns.
2. Act 2, Blue analysis — Blue ledger lines appear one by one; verdicts are not yet known.
3. Act 3, verdict — verdicts and round records appear together and are revealed in sequence.

## Live server and dashboard

**D48 — Live server: Python standard library only.**
`ThreadingHTTPServer`, bound to `127.0.0.1` only, read-only. It serves
`dashboard/dist/index.html` and an SSE endpoint that tails the match artifacts
(following `live/match.lock` and the proxy-log move at freeze). It makes no decision,
computes no score and cannot start anything. There is no start button: the match is
launched from the terminal with `ARENA_GO`, so the GO gate and the single exit
(`agents/llm_client.py`) stay the only path to a paid call.

**D49 — One dashboard, two modes, three views.**
The same `index.html` runs LIVE (opened from the server, SSE) or REPLAY (opened from
`file://`, bundle). Views: Battle, Compare, Report.

**D50 — Animation honesty.**
- Every animation is triggered by a real on-disk event. Nothing is invented for effect.
- Blue is drawn as a radar that detects after the fact, never as a shield or blocker:
  Blue is not on the traffic path.
- Act 3's staged reveal is pacing only; all results exist on disk before it starts.
- Failures (timeout, budget hit, invalid reply, guard block, send failure) are shown as
  normal events.

**D51 — No world map; no X-Forwarded-For.**
All traffic comes from localhost, so a map would show invented origins. Spoofed
`X-Forwarded-For` is not added: free-play Red may set only Cookie and Authorization
(D15 amendment), the proxy log records no headers, and Blue is per-line stateless.
Recorded as future work: XFF rate-limit bypass (Juice Shop "Reset Morty's Password")
needs a D15 amendment, header logging, benign traffic with XFF and a stateful Blue.

**D52 — Compare view.**
- Data model is generic from the start: N Blue arms over the same traffic, joined by
  `request_id`. The first bundle is free-play: original Blue (live verdicts) vs open Blue
  (replay verdicts).
- The header shows the aggregate over all 3 free-play matches. A per-match table is
  labelled as an illustrative selection.
- The FP figures (holdout + fixture) are shown separately from the match table and
  labelled as a separate check.
- Notes: open Blue verdicts vary run to run; the free-play audit was done after open-Blue
  results were known (disclosed limitation).
- Cost-paradox arms (rules off / empty library / library v5) are optional, only if time allows.

## Analyst report

**D53 — Analyst model and inputs.**
- Model: an OpenAI model stronger than Luna, chosen by a probe. Fallback:
  `claude-sonnet-5-5` (same family as Blue, disclosed).
- Post-hoc only; never in the loop, never a judge.
- Input: a code-built `summary.json` plus descriptive fields (e.g. Red `technique`).
  Never raw payloads (reduces refusal and prompt-injection risk). The prompt states that
  input content is data, not instructions.
- Analyst cost cap: $1 (the `analyst` cap in `llm_client.py`).
- Disclosure: the evidence includes an OpenAI Red (Gate B, Luna), so the report notes
  that an OpenAI model comments on an OpenAI Red.

**D54 — Analysis, not recommendation.**
The analyst gives analysis, conclusions about the evidence and decision criteria
("if you value X, option Y fits"). It never recommends an option. Options:
- A — Original Blue (precise, blind outside the taxonomy).
- B — Open Blue (wider coverage, ~10% FP, unstable verdicts).
- C — Layered (original as high-priority alerts, open as a low-priority queue; untested).
The decision is human only. In the demo it is an audience vote, recorded in the
report's decision record.

**D55 — Grounding by construction.**
- The analyst returns JSON whose prose contains only `{{placeholders}}` for figures.
- Code checks that every placeholder resolves to a field in `summary.json` and that no
  bare number appears outside an allowlist (e.g. CWE ids). A failure rejects the draft;
  retries stay within the analyst cap.
- Confidence levels on findings are assigned by code from pre-registered rules, never by
  the analyst. The rules are fixed before any summary is built (issue: summary builder).

**D56 — Rendering.**
Jinja2 with autoescape on, version pinned: the only new dependency, justified because
untrusted AI text goes into HTML. The HTML template is designed once and frozen. PDF is
produced by browser print CSS.

**D57 — Report structure.**
0 Document control · 1 Executive summary (BLUF) · 2 Scope · 3 Methodology · 4 Results ·
5 Key findings (F-NN, evidence refs, confidence) · 6 Risk register (three kinds of
blindness) · 7 Deployment options · 8 Decision criteria · 9 Limitations · 10 Decision
record (human). Appendices: evidence manifest (match ids, commit hash, Judge version),
AI disclosure (model, date, grounding result). Each section is marked as written by
code, AI or human. English, neutral tone.

## Testing and process

**D58 — E2E testing.**
Happy path (preflight → match → three acts → Compare → Report) plus failure drills:
network loss, DeepSeek failure → Luna, server crash → `file://` replay, overlong match
→ cut to golden run. At least one run in the DeepSeek peak window (17:00–20:00 Pacific,
Sun–Thu) and one on the demo laptop with a projector. The last clean run is exported as
the golden run. All runs `purpose=dev`.

**D59 — Ledger scans filter by match id.**
Any scan over match folders filters by `match.json` `match_id` against
`config/test_set.json`, never by folder name. Origin: on 2026-11-24 a folder-name filter
opened `api_calls.jsonl` in 9 test-set folders; only per-file DeepSeek call counts were
printed and nothing was used.

## Analyst report (continued)

**D60 — Analyst summary: confidence rules, numbers in prose, location (designer, 2026-11-24; #16 Q1–Q3).**

*(a) Confidence rules, pre-registered.* Fixed before any `summary.json` is built (#16). Code
assigns every confidence; the analyst never does (D55).
- **Basis of a figure.**
  - `audited`: a rate over Red rounds whose labels or attack attempts the designer audited
    (D16; D41 binary).
  - `ground_truth`: a rate over designer-approved benign data (the benign set, the sealed
    holdout, the fixture). Audited-equivalent: its ground truth is fixed by construction.
    **n = unique requests** (a request sent in several matches counts once; see
    `stats/autonomy.py`, pseudo-replication).
  - `raw`: a rate over unaudited AI-Red labels (D43: Gate B-deepseek, Gate B-evasion).
  - `measured`: an exact count, cost or duration from the ledgers.
- **Confidence.**
  - `audited`, `ground_truth` or `measured` with n ≥ 20 → **High**.
  - The same with n < 20 → **Moderate**.
  - `raw` → **Low**, whatever n.
  - Counts and costs follow the same n rule: an exact measurement does not remove
    small-sample uncertainty. Their n is the number of independent units the figure is
    computed over (matches for a per-match figure, requests for a per-request one); the
    builder records it with the figure.
- **Cap.** Any figure from open Blue (v3-open, D42/D44) is capped at **Moderate**: its
  verdicts vary run to run (2c), and the free-play audit was done after its results were
  known (D52).
- **Finding confidence** = the lowest confidence among the figures it cites.
- **Disclosure.** The n ≥ 20 threshold was set knowing the sample sizes (free-play 19 audited
  attempts, Gate B 28). It puts the free-play detection figures at **Moderate**, i.e. against
  our own headline result; it was not chosen to lift them.

*(b) Numbers in prose (grounding check).* The analyst's prose may state a quantity only through a `{{placeholder}}`. Bare digits are
rejected outside a small token allowlist (CWE ids, F-NN, D-numbers, section references,
model ids, version tags). **Spelled-out numbers and fraction words are rejected too** (e.g.
"two", "nineteen", "half", "third", "twice", "dozen", "percent"), except a short allowlist
of fixed phrases (e.g. "three kinds of blindness", "Act 1" … "Act 3"). The check fails
closed: a false reject only costs a retry within the analyst cap (D53).

*(b) amendment (designer, 2026-11-24, #17).* Decision numbers (D-numbers) and internal
milestone / gate ids (e.g. "M5", "Gate B") are **not** allowed in the report body: readers do not
know them. Every experiment in `summary.json` carries a reader-facing label, which the analyst
uses; the ids appear only in the report's appendices (evidence manifest, decision references).
The grounding check's token allowlist no longer includes D-numbers.

*(c) Where the summary lives.* Development builds go to
`data/runs/analyst/` (git-ignored). The final `summary.json` used for the report is committed
with the report under `data/golden/` in #17.

**D54 amendment (designer, 2026-11-24, #17 review) — no audience vote.** In the demo the
decision is made by the presenter acting as decision-maker, who states the chosen option and
the decision criterion (report section 8) behind it, and fills in the decision record. The
"Audience vote" line is removed from the decision record. The analyst still never recommends.

**D60 amendments (designer, 2026-11-24, #17 review of the first report).**
- *Hedging:* uncertainty is carried by each figure's confidence label and interval; the prose
  says "tentative" only for Low figures (grounding code `hedging`). Over-hedging understates
  Moderate results and is also a distortion.
- *Composition (POST HOC):* a finding never mixes unchecked (raw) figures with checked
  (audited / ground-truth) ones (grounding code `composition`), so a checked result is not
  rated by its unchecked contrast. Added after the first report rated an audited 28/28 finding
  Low because it also cited the raw 28/30; disclosed as post hoc in every report.
- *Structure:* the executive summary cites at least three key figures and ends with the
  decision required (A, B or C); options A and B cite their key figures (code `structure`).
- *Plain language:* internal terms are rejected in prose (code `jargon`); the report has a
  glossary; every figure has a reader-facing label and ids appear only in the appendix.
- *Formats:* every percentage prints with one decimal (so a rate and its change agree), and
  "percentage points" is written in full.
- *Round 2 (prompt v3):* experiments have short prose labels (long labels stay in tables);
  the executive summary stands alone (no finding ids) and cites the successful-attack figures
  itself; decision criteria are bare phrases (no repeated "If you value" / "option X fits,
  because"). All enforced by the grounding check (`structure`). **Stopping rule (designer):**
  this is the last re-run for wording; only a factual error (wrong figure, wrong direction, an
  implied recommendation) justifies another paid run.
