// Battle model tests (Stage 7 #13). Run by tests/test_dashboard_battle.py with:
//   ARENA_LIVE_EVENTS = a JSONL of live-server events from a fake match (liveserver tailer)
//   ARENA_LIVE_MATCH  = that match's frozen folder (rounds.jsonl, benign_results.jsonl)
//   ARENA_BUNDLES     = the committed demo bundles folder (dashboard/public/data)
// Done when (#13): a fake live match and an existing bundle both play through all three acts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { ACTS, attackView, blueProgress, bundleToEvents, initialState, playAll, reduce,
  revealNext, scoreboard } from "../src/battle/model.js";

const jl = (p) => fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map(JSON.parse) : [];
const env = process.env;

test("a fake live match plays through all three acts", { skip: !env.ARENA_LIVE_EVENTS }, () => {
  const events = jl(env.ARENA_LIVE_EVENTS);
  let s = initialState("live");
  const acts = [];
  let bursts = 0;
  for (const ev of events) {
    const before = s.target.burst;
    s = reduce(s, ev);
    acts.push(s.act);
    if (s.target.burst && s.target.burst !== before) bursts += 1;
  }
  // acts never go backwards and all three occur
  for (let i = 1; i < acts.length; i++) assert.ok(acts[i] >= acts[i - 1], `act went back at ${i}`);
  for (const a of [ACTS.ATTACK, ACTS.ANALYSIS, ACTS.VERDICT]) assert.ok(acts.includes(a), `act ${a}`);
  // Blue never shows a verdict before Act 3, and nothing is revealed before the reveal starts
  assert.ok(s.slots.every((x) => x.outcome === undefined));
  assert.equal(s.status, "finished");

  while (!s.reveal.done) s = revealNext(s);
  const rounds = Object.fromEntries(jl(path.join(env.ARENA_LIVE_MATCH, "rounds.jsonl")).map((r) => [r.round, r]));
  const benign = Object.fromEntries(jl(path.join(env.ARENA_LIVE_MATCH, "benign_results.jsonl")).map((r) => [r.request_id, r]));
  for (const x of s.slots) {
    if (x.kind === "red" && x.state === "unsent") assert.equal(x.outcome, "unsent");
    else if (x.kind === "red") assert.equal(x.outcome, rounds[x.round].detected ? "TP" : "FN");
    else assert.equal(x.outcome, benign[x.requestId].false_positive ? "FP" : "quiet");
  }
  const sb = scoreboard(s);
  assert.equal(sb.revealed, s.slots.length);
  assert.equal(sb.tp + sb.fn, Object.keys(rounds).length);
  assert.equal(sb.fp + sb.quiet, Object.keys(benign).length);
  assert.ok(sb.unsent >= 1 && sb.landed >= 1);
  assert.ok(bursts >= 1); // the landed burst fired during the match (cleared when traffic ends)
  assert.equal(s.target.burst, null);
  // failures are ordinary events in the feed
  assert.ok(s.feed.some((f) => /nothing sent/.test(f.text)));
  // the plan (derived from the transcript) shaped the timeline
  assert.ok(s.plan && s.plan.length === s.slots.length);
  // cost ticker ends at the match total
  const fin = events.find((e) => e.type === "match_finished");
  assert.equal(s.cost.usd, fin.cost_usd);
  assert.equal(blueProgress(s).total, s.proxyLines);
});

test("every committed bundle replays through all three acts", { skip: !env.ARENA_BUNDLES }, () => {
  const files = fs.readdirSync(env.ARENA_BUNDLES).filter((f) => f.endsWith(".json"));
  assert.ok(files.length >= 1);
  for (const f of files) {
    const b = JSON.parse(fs.readFileSync(path.join(env.ARENA_BUNDLES, f), "utf8"));
    const events = bundleToEvents(b);
    const s = playAll(events, "replay");
    assert.equal(s.act, ACTS.VERDICT, f);
    assert.ok(s.reveal.done, f);
    assert.equal(s.slots.length, b.steps.length + b.unsent.length, f);
    for (const st of b.steps) {
      const x = s.slots.find((y) => y.requestId === st.request_id);
      assert.ok(x, `${f} ${st.request_id}`);
      const want = st.judge.kind === "attack" ? (st.judge.detected ? "TP" : "FN")
        : st.judge.kind === "benign" ? (st.judge.false_positive ? "FP" : "quiet") : "unscored";
      assert.equal(x.outcome, want, `${f} log_seq ${st.log_seq}`);
      assert.equal(x.status, st.request.status);
    }
    assert.equal(s.slots.filter((x) => x.outcome === "unsent").length, b.unsent.length, f);
    assert.equal(s.cost.usd, b.total_cost.usd, f);
  }
});

test("Act 3 reveal does nothing before the match has finished (D50)", () => {
  let s = reduce(initialState(), { id: 1, type: "match_started", match_id: "m" });
  s = reduce(s, { id: 2, type: "red_turn_start", round: 1 });
  s = reduce(s, { id: 3, type: "round_record", row: { round: 1, detected: true } });
  assert.equal(revealNext(s), s);
  assert.equal(s.slots[0].outcome, undefined);
});

test("an outcome comes only from a Judge record; none -> unscored", () => {
  let s = reduce(initialState(), { id: 1, type: "match_started", match_id: "m" });
  s = reduce(s, { id: 2, type: "red_attack", row: { round: 1, request_id: "r1", label: "CWE-89", method: "GET", endpoint: "/x", payload: "/x" } });
  s = reduce(s, { id: 3, type: "match_finished", status: "completed" });
  s = revealNext(s);
  assert.equal(s.slots[0].outcome, "unscored");
});

test("a failed match ends in failure, not in a verdict act", () => {
  let s = reduce(initialState(), { id: 1, type: "match_started", match_id: "m" });
  s = reduce(s, { id: 2, type: "match_failed", step: "blue", error: "x" });
  s = reduce(s, { id: 3, type: "match_finished", status: "failed", failed_step: "blue" });
  assert.equal(s.status, "failed");
  assert.notEqual(s.act, ACTS.VERDICT);
  assert.equal(s.failure.step, "blue");
});

test("header values never reach the view (names only)", () => {
  const a = attackView({ round: 1, label: "other", method: "GET", endpoint: "/x", payload: "/x",
    request_id: "r", headers: { Cookie: "token=SECRET" } });
  assert.deepEqual(a.headerNames, ["Cookie"]);
  assert.ok(!JSON.stringify(a).includes("SECRET"));
});

test("events before a match starts are ignored; a new match resets the view", () => {
  let s = reduce(initialState(), { id: 1, type: "red_attack", row: { round: 1 } });
  assert.equal(s.slots.length, 0);
  s = reduce(s, { id: 2, type: "match_started", match_id: "a" });
  s = reduce(s, { id: 3, type: "red_turn_start", round: 1 });
  s = reduce(s, { id: 4, type: "match_started", match_id: "b" });
  assert.equal(s.matchId, "b");
  assert.equal(s.slots.length, 0);
});

test("LIVE is only possible from the loopback live server (file:// makes no request)", async () => {
  const { liveAvailable } = await import("../src/battle/live.js");
  assert.equal(liveAvailable({ protocol: "file:", hostname: "" }), false);
  assert.equal(liveAvailable({ protocol: "http:", hostname: "127.0.0.1" }), true);
  assert.equal(liveAvailable({ protocol: "http:", hostname: "localhost" }), true);
  assert.equal(liveAvailable({ protocol: "http:", hostname: "evil.example" }), false);
  assert.equal(liveAvailable({ protocol: "https:", hostname: "127.0.0.1" }), false);
  assert.equal(liveAvailable(null), false);
});

test("a late plan reorders the slots already seen (catch-up)", () => {
  let s = reduce(initialState(), { id: 1, type: "match_started", match_id: "m" });
  s = reduce(s, { id: 2, type: "red_attack", row: { round: 1, request_id: "r1", label: "x", method: "GET", endpoint: "/", payload: "/" } });
  s = reduce(s, { id: 3, type: "benign_request", row: { request_id: "b1", benign_id: "n01" } });
  s = reduce(s, { id: 4, type: "match_plan", planned: ["benign", "red", "benign"], n_red: 1, n_benign: 2, seed: 1 });
  assert.deepEqual(s.slots.map((x) => x.kind), ["benign", "red", "benign"]);
  assert.equal(s.slots[0].requestId, "b1");
  assert.equal(s.slots[1].requestId, "r1");
  assert.equal(s.slots[2].state, "pending");
});

test("match_finished carries the true start (timer after a catch-up)", () => {
  let s = reduce(initialState(), { id: 1, type: "match_started", match_id: "m", observed_at: "2026-11-24T20:00:00Z" });
  s = reduce(s, { id: 2, type: "match_finished", status: "completed", started_at: "2026-11-24T19:00:00Z", finished_at: "2026-11-24T19:10:00Z" });
  assert.equal(Date.parse(s.finishedAt) - Date.parse(s.startedAt), 600000);
});
