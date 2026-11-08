# Sentinel Arena — Build Progress

*Last updated: 2026-11-07*

A closed-loop evaluation harness for AI defenders. A Red agent attacks OWASP
Juice Shop through an nginx reverse proxy; a Blue agent reads only the proxy log,
classifies each request, and invents detection rules; a pure-code Judge scores
every round. Components never call each other — they communicate only through
file artifacts defined in a data contract.

## Status at a glance

| Stage | Description | Planned | Status |
|---|---|---|---|
| 0 | Data contract v0 | Nov 2–3 | Done (Nov 2) |
| 1 | Target + reverse proxy + challenge map | Nov 3–5 | Done (Nov 3) |
| 2 | Scripted Red + Judge fact 1 (landed) | Nov 5–7 | Done (Nov 4) |
| 3 | Blue v0 + Judge fact 2 + round record | Nov 7–9 | Done (Nov 5) |
| 4 | Integration: one-command match | Nov 9–11 | Done (Nov 7) |

Currently ~4 days ahead of plan. Next milestone: Progress Report (Nov 12).

## Completed

### Stage 0 — Data contract v0
- Defined 7 artifacts (taxonomy, red attack record, proxy log, verdict, rule,
  round record, challenge map) with JSON Schemas and a producer → consumer table.
- `request_id` (uuid4, carried in the `X-Arena-Request-Id` header) is the join
  key across red attacks, proxy log, verdicts, and round records.
- Split detection into `detected` (attack vs benign) and `type_correct`
  (correct CWE), so a misclassification is distinguishable from a miss.
- Drift-guard tests ensure schema enums stay in sync with the taxonomy.

### Stage 1 — Target + reverse proxy
- OWASP Juice Shop (pinned v20.3.0) behind nginx (pinned 1.30.6-alpine) via
  Docker Compose. Juice Shop is on an `internal` network with no published port;
  only nginx publishes a port, bound to `127.0.0.1` for host-only isolation.
- nginx forwards and logs only — no WAF, rate limiting, auth, or caching — so all
  defense lives in Blue and the Judge can measure it.
- JSON log captures raw path (`$request_uri`, never the normalized `$uri`),
  request body, and request_id, with UTC ISO-8601 timestamps. A log-validation
  tool classifies each line as valid / stray / invalid against the schema.
- Finalized `challenge_map.json` by testing every candidate against the running
  Juice Shop and recording the exact challenge names:
  - CWE-89 (SQLi): Login Admin, User Credentials
  - CWE-79 (XSS): none (not measurable, see limitations)
  - CWE-22 (path traversal): Poison Null Byte, Forgotten Developer Backup

### Stage 2 — Scripted Red + Judge fact 1 (landed)
- Scripted Red fires a data-driven attack set (`red/payloads.json`, 7 attacks
  across the 3 CWEs plus a genuine-but-failing negative control). Each attack
  writes its labeled ground-truth record *before* sending, so a failed send
  leaves an orphan rather than losing the record. Every payload was verified
  empirically against the running Juice Shop, not taken from writeups.
- A separate **admin path** (nginx `:8081`, `access_log off`) lets the measurement
  read challenge state without adding a line to `proxy.jsonl` — the measurement
  never disturbs Blue's input. Verified: admin reads add zero log lines.
- The runner resets the Target (restart → verified 0 solved), starts each run from
  a clean proxy log (the previous log is **archived, never deleted**), then per
  attack snapshots solved-state before/after to `challenge_snapshots.jsonl`. The
  after-snapshot waits for the solved set to stabilize, so an attack that solves
  several challenges at slightly different times has them all attributed to the one
  round instead of leaking into the next.
- **Judge fact 1** (`landed`) is pure code over artifacts (no network): per attack
  it computes `landed` ∈ {true, false, null} with a `landed_reason`
  (`not_measurable` / `already_solved`) and the `newly_solved` evidence list, only
  crediting challenges in the label's mapping.
- End-to-end check (`tools/stage2_check.py`) passes on a fresh `docker compose up`:
  all 7 attacks' (landed, reason) match expectations, each request_id appears
  exactly once in `proxy.jsonl`, and no `/api/Challenges` line leaks into it.

### Stage 3 — Blue v0 + Judge fact 2 + round record
- **Blue v0** (`blue/run_blue.py --engine scripted`) reads **only** the proxy log
  and emits one verdict per logged request. Signatures are generic OWASP-style
  patterns for CWE-89/22/79 over the URL-decoded path+query+body (double-decoding
  for `%2500`), written without reference to Red's payloads. An information-wall
  test enforces that Blue opens no file but the proxy log, and that the request id
  is never a classification feature. The engine is pluggable so a `claude` engine
  can be added later without touching the Judge or the verdict format.
- **Judge fact 2** (`judge/fact2_detected.py`, pure) uses Red records as the spine:
  per request_id it derives `detected` / `type_correct` / `detected_reason`,
  handling the no-verdict and orphan cases, ignoring verdicts with no Red record,
  and raising on duplicate verdicts for one request_id.
- **Round record** (`judge/round_record.py`) joins fact 1 + fact 2 into
  `rounds.jsonl`, one line per Red record, validating every line against the schema
  before writing. The orphan definition is reconciled: "no proxy line" is
  authoritative (contract §6); fact 1's "no snapshot" case is renamed
  "snapshot-missing".
- **Incomplete vs ambiguous data** (reverses the Stage-3 Step-0 "fail loud"
  decision): the join still **raises** on *ambiguous* data (duplicate verdicts,
  schema-invalid records — it must not guess), but on *incomplete* data (a missing
  snapshot) it records the round with `landed=null, landed_reason="snapshot_missing"`
  and scores detection normally, rather than discarding the whole match (and every
  other round's valid detection result). `snapshot_missing` is a runtime failure,
  kept distinct from the by-design `not_measurable` (§11). A scripted run should
  never produce one, so `stage3_check.py` fails if it sees one (a tripwire).
- **End-to-end** (`tools/stage3_check.py`) runs runner → fact 1 → Blue → round
  record and compares to `tools/stage3_expected.json` (expectations reasoned out
  before the first run). Passes 3× on a fresh `docker compose up`. No AI API calls
  in this stage — zero token cost.

### Stage 4 — Integration: one-command match
- **`run_match.py`** runs a whole scripted match on a running stack and leaves a
  frozen, self-describing `data/runs/<match_id>/` (`match_id` = UTC timestamp + 4
  hex, e.g. `20261108T054013Z-0594`). Sequence: preflight (containers Up, Juice Shop
  healthy, no leftovers in `live/`) → lock → reset (verify 0 solved) → rotate →
  scripted Red with snapshots → **freeze** → Judge fact 1 → Blue → round record →
  `match.json` → terminal summary. No AI API calls — zero token cost.
- **One code path.** Reset / rotate / snapshot / freeze logic lives only in
  `runner/match_ops.py`; `runner/stage2_run.py` is removed. The Stage 2/3/4 checks
  all run matches through `run_match.py`. Red and the runner write straight into the
  match directory; only `proxy.jsonl` is staged in `live/` (nginx never knows about
  matches). Red, Blue and the Judge accept `--run-dir`.
- **Freeze before scoring.** After Red, `proxy.jsonl` moves into the match dir and
  nginx reopens a fresh live log *before* Blue and the Judge run, so they read a file
  that can no longer change. `tools/stage4_check.py` proves it with a post-freeze
  probe: one arena request lands in `live/`, and the frozen file's sha256 is unchanged.
- **Failure handling.** Any failing step still finalizes the match: this match's
  artifacts are in its directory, `match.json` says `failed` with the step and error,
  the lock is released, exit is non-zero. A failed match never leaves artifacts in
  `live/`. The Judge raising on ambiguous data is a failure; `snapshot_missing` is not.
  If the freeze itself fails, finalize still moves the log into the match dir and
  makes one best-effort nginx reopen; the log is marked "NOT FROZEN" only if that
  reopen also fails. Covered by Docker-free tests that inject a failure at every step.
- **`match.json` manifest** (new contract artifact, §6.2): status, `judge_version`
  (`JUDGE_VERSION = "0.1.0"`), Blue engine, payload sha256, git commit + dirty flag,
  the image versions **actually running** (from `docker inspect`), and sha256 + size
  of every other file in the match dir. `stage4_check` recomputes the hashes.
- **Terminal summary** (`stats/match_stats.py`, pure, unit-tested, reusable for the
  autonomy table): one row per round, then each rate as `n/d (%)` with the rounds its
  denominator excludes, the edge-case counts, and the footer that detection is an
  upper bound until Stage 5.
- **Golden run** committed at `data/golden/scripted-baseline-match/`, produced from a
  clean tree (`git.dirty == false`).
- **Finding: nginx keeps appending to a moved log until reopen.** nginx holds its
  access-log file descriptor, so a renamed `proxy.jsonl` — even one moved out of the
  bind-mounted directory — keeps receiving lines until `nginx -s reopen`. Verified
  empirically on Docker Desktop / macOS bind mount: after the move a tagged request
  landed in the moved file (same inode); after reopen the next one landed in a new
  file (new inode). The existing rotate already reopened, so **Stage 2/3 data is
  unaffected**. The real bug was the **silent give-up**: if the fresh log never
  appeared, rotate continued anyway. Rotate and freeze now raise instead. Deleting an
  *empty* log on rotation is kept as a documented exception (it holds no evidence).
- **Finding: an attack solved a challenge outside the map (golden run, round 5).**
  `GET /ftp/coupons_2013.md.bak%2500.md` (CWE-22) scored `landed=null /
  already_solved` (both mapped CWE-22 challenges fell in round 4), but its
  `newly_solved` is `["Forgotten Sales Backup"]`, which is not in the CWE-22 map. The
  Judge behaved as designed (only mapped challenges are credited) and the raw
  evidence was kept, but landing is slightly **under-counted**. Deliberately not
  changed yet (challenge map, Stage 3 expectations and golden run stay as they are);
  revisit when variant attacks are designed. It is exactly the planned
  "`newly_solved` outside the map" tripwire below. Recorded in contract §7.

## Measurement limitations (known and documented)

These are honest boundaries of the instrument, recorded in the contract:

1. **Above-root traversal is invisible.** nginx rejects paths that climb above
   the web root while parsing the request line, before logging — so these
   requests have no request_id and are stray. Red must never send them.
2. **Orphan rounds.** A Red record with no matching proxy line is marked orphan,
   excluded from **all** statistics (detection and landing), and never counted as a
   miss. A send failure is infrastructure failure, not attack failure, so its
   fact-1 `landed=false` must not lower Red's landing rate.
3. **XSS landing is not measurable.** All HTTP-triggerable XSS challenges are
   disabled in Juice Shop's Docker deployment, and the one enabled XSS (DOM XSS)
   is solved via a websocket a single HTTP request can't reach. So CWE-79
   `landed` is recorded as `null` (not `false`) and excluded from landing stats —
   but CWE-79 **detection** is measured normally.
4. **Detection rate is gameable until Stage 5.** With attack-only traffic, a Blue
   that labels *everything* an attack scores a perfect detection rate. False
   positives are only measurable once benign traffic and fact 4 (`benign_fp`)
   arrive in Stage 5. Until then, detection numbers are an upper bound, not a
   capability claim.
5. **Stage 3 results are a pipe check, not a capability claim.** Scripted Blue v0's
   signatures and the Red payload set were written by the same author, so passing
   the end-to-end check proves the pipeline is wired correctly — not that Blue is
   good. Real capability must be measured on **held-out** attacks Blue's author
   never saw.

## Stage 6 tripwires (harness self-checks)

Conditions that mean the harness itself misbehaved, not that a side won/lost. What
happens when one trips depends on the context:

- **Scripted checks** (`tools/stage3_check.py`): a tripwire is a **FAIL**. A scripted
  run with known inputs should never trip one, so tripping means a real bug.
- **Real matches** (Stage 5+): a tripwire **flags** the run — it is recorded in
  `anomalies.jsonl` for human review, the affected stat is excluded per the contract,
  and the rest of the match is still scored. We do not discard a whole match's valid
  results over incomplete data. The one exception: a tripwire that reveals a **Judge
  bug** forces a re-score — bump the Judge version and note which results used the old
  one.

Stage 6 will centralize these; some are already enforced.

- **`snapshot_missing` appears** in any round record — a snapshot was dropped at
  runtime, so landing is unknown. A scripted run should never produce one;
  `tools/stage3_check.py` already fails on it.
- **`newly_solved` contains a challenge outside the label's map** — the attack did
  something the map does not credit, so landing may be under-counted (or the map is
  incomplete). Not enforced yet. First seen in the Stage 4 golden run, round 5
  (`Forgotten Sales Backup` from a CWE-22 attack); see contract §7.
- (more to be added as later stages surface them)

## Methodology notes (for the report)

- **Independent target.** We use OWASP Juice Shop — a third-party, authoritative
  vulnerable app — read but never modified, so the vulnerabilities Blue faces are
  independently designed, not planted by us. This mirrors the spirit of
  evaluation suites like MITRE ATT&CK Evaluations: fixed taxonomy + labeled
  ground truth + an independent scorer.
- **Seam / portability.** The nginx-defined log format is a seam: the Target is
  swappable (Juice Shop → another app) without changing Blue or the Judge,
  because they only read the log, never the Target directly.
- **Pure-code Judge.** Scoring is a mechanical comparison against ground truth
  (Red labels every attack), never an LLM judgment — the determinism anchors the
  credibility of the whole track record.

## Next
- Progress Report: the golden run (`data/golden/scripted-baseline-match/`) plus the
  Match-1 picture.
- Stage 5: benign traffic + false-positive scoring (fact 4), which turns the
  detection rate from an upper bound into a real measurement.
