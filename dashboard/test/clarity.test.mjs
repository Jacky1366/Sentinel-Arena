// #29 clarity pass + D61 matchups: the pure selectors behind the Battle and Compare views.
// Synthetic events only (plus the committed Compare bundle via ARENA_COMPARE when given).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { ACTS, MATCHUPS, attackName, bundleToEvents, initialState, latestRunOf, matchupOfBundle, missedAttacks,
  normalLine, playAll, reduce, reduceRuns, replayDelay, revealNext, sideBySide, sourceBundleFor, sourceResultsOf,
  stats4, summaryRow, turnCards } from "../src/battle/model.js";
import { ARM_NAMES, armCards, matchTabs, plain, takeaway, visibleRows } from "../src/compare/compareModel.js";
import { runLabel } from "../src/labels.js";

const RID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

// A small finished match: 3 Red turns (1 caught + succeeded, 2 missed + succeeded, 3 not
// sent) and 2 normal requests (1 false alarm).
function events(matchId = "m1", extra = {}) {
  const ev = [];
  let id = 0;
  const push = (type, data = {}) => ev.push({ id: ++id, type, match_id: matchId, ...data });
  push("match_started", extra);
  push("library_loaded", { library_version: 5, n_rules: 19 });
  push("red_turn_start", { round: 1 });
  push("red_attack", { row: { round: 1, request_id: RID(1), label: "CWE-89", technique: "SQL injection", method: "GET", endpoint: "/a" } });
  push("snapshot", { row: { request_id: RID(1), traffic: "red" }, newly_solved: ["Login Admin"] });
  push("benign_request", { row: { request_id: RID(2), benign_id: "n01" } });
  push("red_turn_start", { round: 2 });
  push("red_attack", { row: { round: 2, request_id: RID(3), label: "other", technique: "file access", method: "GET", endpoint: "/ftp" } });
  push("snapshot", { row: { request_id: RID(3), traffic: "red" }, newly_solved: ["Confidential Document"] });
  push("red_turn_start", { round: 3 });
  push("red_unsent", { row: { round: 3, kind: "brain_failure", reason: "invalid_shape" } });
  push("benign_request", { row: { request_id: RID(4), benign_id: "n02" } });
  push("proxy_frozen");
  push("rule", { row: { rule_id: "r-001" } });
  push("round_record", { row: { round: 1, request_id: RID(1), detected: true, landed: true } });
  push("round_record", { row: { round: 2, request_id: RID(3), detected: false, landed: true } });
  push("benign_result", { row: { request_id: RID(2), false_positive: true } });
  push("benign_result", { row: { request_id: RID(4), false_positive: false } });
  push("match_finished", { status: "completed" });
  return ev;
}

const run = (evs) => evs.reduce(reduce, initialState("live"));

test("matchups: three plain titles; golden bundles name their matchup", () => {
  assert.deepEqual(Object.values(MATCHUPS).map((m) => m.title), [
    "1 · Limited attacker vs limited defender", "2 · Free attacker vs limited defender",
    "3 · Free attacker vs free defender (same attacks as 2)"]);
  assert.equal(matchupOfBundle("golden-open"), "open");
  assert.equal(matchupOfBundle("golden-run"), null);
  assert.equal(matchupOfBundle("m5-library-gate3-match1"), null);
});

test("turn cards: one outcome each, a star when the attack succeeded; nothing before the reveal", () => {
  let s = run(events());
  assert.equal(s.act, ACTS.VERDICT);
  assert.deepEqual(turnCards(s).map((c) => c.outcome), [null, null, null]); // pacing (D50)
  assert.equal(stats4(s).caught, 0);
  while (!s.reveal.done) s = revealNext(s);
  const cards = turnCards(s);
  assert.deepEqual(cards.map((c) => [c.round, c.outcome, c.succeeded]),
    [[1, "caught", true], [2, "missed", true], [3, "not sent", false]]);
  assert.deepEqual(stats4(s), { attacks: 2, caught: 1, missed: 1, succeeded: 2, verdictsShown: true });
  assert.equal(normalLine(s).text, "2 normal requests · 1 false alarm");
  assert.deepEqual(missedAttacks(s), [{ round: 2, technique: "file access", succeeded: true }]);
});

test("normal traffic line before the verdict has no false-alarm count", () => {
  const evs = events().filter((e) => !["round_record", "benign_result", "match_finished"].includes(e.type));
  assert.equal(normalLine(run(evs)).text, "2 normal requests");
});

test("library rules and new rules are counted apart", () => {
  const s = run(events());
  assert.deepEqual(s.library, { version: 5, rules: 19 });
  assert.equal(s.newRules, 1);
});

test("summary row counts every Judge result of a finished run, whatever the reveal shows", () => {
  assert.deepEqual(summaryRow(run(events())), { attacks: 2, caught: 1, missed: 1, succeededMissed: 1,
    succeeded: 2, falseAlarms: 1, normal: 2 });
  assert.equal(summaryRow(initialState()), null);
});

test("matchup 3: both defenders side by side; original from the source results", () => {
  const evs = events("r1", { kind: "replay", matchup: "open", source_match_id: "m1" });
  evs.splice(1, 0, { id: 0, type: "source_results", match_id: "r1", rounds: [
    { round: 1, request_id: RID(1), detected: false, landed: true },
    { round: 2, request_id: RID(3), detected: false, landed: true }],
  benign: [{ request_id: RID(2), false_positive: false }, { request_id: RID(4), false_positive: false }] });
  let s = run(evs);
  assert.equal(s.runKind, "replay");
  assert.equal(s.matchup, "open");
  let sb = sideBySide(s);
  assert.deepEqual(sb.rows.map((r) => [r.round, r.original, r.open]), [[1, "missed", null], [2, "missed", null]]);
  assert.equal(sb.originalAlarms, 0);
  assert.equal(sb.openAlarms, null);
  while (!s.reveal.done) s = revealNext(s);
  sb = sideBySide(s);
  assert.deepEqual(sb.rows.map((r) => [r.round, r.original, r.open, r.succeeded]),
    [[1, "missed", "caught", true], [2, "missed", "missed", true]]);
  assert.equal(sb.openAlarms, 1);
});

test("runs: each match_started opens a run; events go to their run; reveal targets one run", () => {
  let runs = [];
  for (const e of events("m1", { matchup: "taxonomy" })) runs = reduceRuns(runs, e);
  for (const e of events("m2")) runs = reduceRuns(runs, e);
  runs = reduceRuns(runs, { type: "matchup", match_id: "m2", matchup: "freeplay" });
  assert.deepEqual(runs.map((r) => [r.id, r.state.matchup]), [["m1", "taxonomy"], ["m2", "freeplay"]]);
  assert.equal(latestRunOf(runs, "taxonomy").id, "m1");
  assert.equal(latestRunOf(runs, "open"), null);
  runs = reduceRuns(runs, { type: "reveal_next", run: "m1" });
  assert.equal(runs[0].state.reveal.index, 0);
  assert.equal(runs[1].state.reveal.index, -1);
  // a reconnect replays the history: the same run is rebuilt, not duplicated
  for (const e of events("m2")) runs = reduceRuns(runs, e);
  assert.deepEqual(runs.map((r) => r.id), ["m1", "m2"]);
  // only the last runs are kept
  for (let i = 0; i < 12; i++) runs = reduceRuns(runs, { type: "match_started", match_id: `x${i}` });
  assert.equal(runs.length, 10);
});

test("bundles: a replay bundle finds its match bundle; rules of the match only", () => {
  const match = { kind: "match", match_id: "m9", meta: { status: "completed" }, rules: [
    { rule_id: "r-001", origin: "match" }, { rule_id: "L-1", origin: "library" }],
  steps: [{ log_seq: 1, request_id: RID(1), request: { method: "GET", path: "/a", status: 200 },
    red: { kind: "attack", round: 1, label: "CWE-89" }, judge: { kind: "attack", detected: false, landed: true, newly_solved: [] },
    blue: { verdict: "benign", source: "ai" } }] };
  const replay = { ...match, kind: "replay", run_id: "r9", rules: [], steps: [{ ...match.steps[0],
    judge: { kind: "attack", detected: true, landed: true, newly_solved: [] } }] };
  assert.equal(sourceBundleFor(replay, { a: match, b: replay }), match);
  assert.equal(sourceBundleFor(match, { a: match }), null);
  assert.deepEqual(sourceResultsOf(match).rounds, [{ round: 1, request_id: RID(1), detected: false, landed: true }]);
  const s = playAll(bundleToEvents(replay, { matchup: "open", source: match }), "replay");
  assert.equal(s.matchup, "open");
  assert.deepEqual(sideBySide(s).rows.map((r) => [r.original, r.open]), [["missed", "caught"]]);
  assert.equal(playAll(bundleToEvents(match)).newRules, 1);
});

test("labels: reader-facing names for recorded runs", () => {
  assert.equal(runLabel("m5-library-gate3-match1"), "Cost comparison · with library · match 1");
  assert.equal(runLabel("m5-rules-off-gate3-match3"), "Cost comparison · rules off · match 3");
  assert.equal(runLabel("train-gate1-match2"), "Rule learning · training match 2");
  assert.match(runLabel("golden-freeplay"), /^Matchup 2 · free attacker vs limited defender/);
  assert.equal(runLabel("something-else"), "something-else");
});

test("compare: notes lose decision numbers; plain arm names", () => {
  assert.equal(plain("Open Blue's verdicts vary run to run (D42 2c)."), "Open Blue's verdicts vary run to run.");
  assert.equal(plain("Original Blue is the default (D44)."), "Original Blue is the default.");
  assert.doesNotMatch(plain("See D52 and (disclosed limitation, D52)."), /D\d/);
  assert.equal(ARM_NAMES.original.name, "Limited defender");
  assert.equal(ARM_NAMES.open.name, "Free defender");
});

test("compare: the committed free-play bundle", { skip: !process.env.ARENA_COMPARE }, () => {
  const b = JSON.parse(fs.readFileSync(process.env.ARENA_COMPARE, "utf8"));
  const cards = armCards(b);
  assert.deepEqual(cards.map((a) => [a.detected, a.attempts, a.fpCheck.fp, a.fpCheck.n]), [[12, 19, 0, 57], [14, 19, 6, 57]]);
  assert.equal(takeaway(b), "The free defender caught 14 of 19 attacks instead of 12 and 7 of 7 successful attacks"
    + " instead of 5, but raised 6 false alarms on 57 normal requests instead of 0.");
  const tabs = matchTabs(b);
  assert.equal(tabs.length, 3);
  assert.ok(tabs.every((t) => /^\d{1,2} [A-Z][a-z]{2} 2026$/.test(t.date)));
  for (const t of tabs) {
    const shown = visibleRows(b, t.match, false);
    assert.ok(shown.every((r) => r.divergent || r.landed));
    assert.deepEqual(shown.filter((r) => r.divergent).map((r) => r.round), t.disagree);
    assert.ok(visibleRows(b, t.match, true).length >= shown.length);
  }
});

test("recorded matchup 3 skips the attack act's pacing, nothing else", () => {
  assert.equal(replayDelay({ type: "red_attack" }, true), 0);
  assert.equal(replayDelay({ type: "proxy_line" }, true), 0);
  assert.ok(replayDelay({ type: "red_attack" }) > 0);
  assert.equal(replayDelay({ type: "match_finished" }, true), replayDelay({ type: "match_finished" }));
});

test("attack names: the technique when known, else the label in plain words", () => {
  assert.equal(attackName({ technique: "JWT forgery", label: "other" }), "JWT forgery");
  assert.equal(attackName({ technique: null, label: "CWE-89" }), "SQL injection");
  assert.equal(attackName({ label: "other" }), "an attack outside the three known types");
  assert.equal(attackName(null), null);
});

test("a recorded run lays out all its turn cards at once", () => {
  const b = { kind: "match", match_id: "m7", steps: [{ log_seq: 1, request_id: RID(1), request: { method: "GET", path: "/", status: 200 },
    red: { kind: "attack", round: 2, label: "other" } }], unsent: [{ round: 3, kind: "brain_failure", reason: "empty" }] };
  const first = bundleToEvents(b).slice(0, 1).reduce(reduce, initialState("replay"));
  assert.deepEqual(turnCards(first).map((c) => [c.round, c.state]), [[1, "pending"], [2, "pending"], [3, "pending"]]);
});

test("sessions: the stage shows only runs of the current demo session", async () => {
  const { reduceSession, sessionRuns } = await import("../src/battle/model.js");
  let runs = [];
  let cur = null;
  const feed = (ev) => { runs = reduceRuns(runs, ev); cur = reduceSession(cur, ev); };
  feed({ type: "match_started", match_id: "rehearsal" });                     // no session yet
  assert.equal(cur, null);
  assert.deepEqual(sessionRuns(runs, cur).map((r) => r.id), ["rehearsal"]);  // no sessions: all
  feed({ type: "session", session_id: "s1", started_at: "2026-12-03T17:00:00Z" });
  assert.deepEqual(sessionRuns(runs, cur), []);                               // boundary: none yet
  feed({ type: "match_started", match_id: "m1", session_id: "s1" });
  feed({ type: "match_started", match_id: "m2", session_id: "s1", matchup: "freeplay" });
  assert.deepEqual(sessionRuns(runs, cur).map((r) => r.id), ["m1", "m2"]);
  assert.equal(latestRunOf(sessionRuns(runs, cur), "freeplay").id, "m2");
  // a reconnect whose history lost the session event still knows it from the run starts
  let cur2 = null;
  for (const ev of [{ type: "match_started", match_id: "m1", session_id: "s1" }]) cur2 = reduceSession(cur2, ev);
  assert.equal(cur2, "s1");
});
