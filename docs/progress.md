# Sentinel Arena — Build Progress

*Last updated: 2026-11-03*

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
| 3 | Blue v0 + Judge fact 2 + round record | Nov 7–9 | Next |
| 4 | Integration + Progress Report | Nov 9–11 | Pending |

Currently ~3 days ahead of plan. Next milestone: Progress Report (Nov 12).

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

## Measurement limitations (known and documented)

These are honest boundaries of the instrument, recorded in the contract:

1. **Above-root traversal is invisible.** nginx rejects paths that climb above
   the web root while parsing the request line, before logging — so these
   requests have no request_id and are stray. Red must never send them.
2. **Orphan rounds.** A Red record with no matching proxy line is marked orphan,
   excluded from all detection stats, and never counted as a miss.
3. **XSS landing is not measurable.** All HTTP-triggerable XSS challenges are
   disabled in Juice Shop's Docker deployment, and the one enabled XSS (DOM XSS)
   is solved via a websocket a single HTTP request can't reach. So CWE-79
   `landed` is recorded as `null` (not `false`) and excluded from landing stats —
   but CWE-79 **detection** is measured normally.

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

## Next: Stage 3
- Blue v0: reads only the proxy log, emits a verdict per request, and invents
  detection rules.
- Judge fact 2: joins Blue verdicts with the landed facts into the full round
  record (`detected`, `type_correct`, and the orphan field).
