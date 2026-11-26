// Battle model (Stage 7 #13; D47, D49, D50). PURE: no React, no DOM, no network.
//
// One reducer for both modes:
//   LIVE   — events from the live server (liveserver/, SSE), as they happen;
//   REPLAY — events built from an exported bundle (bundleToEvents), played back with pacing.
// Every state change is caused by an event that comes from an artifact on disk (D50). The
// only action that is not an artifact event is `reveal_next`: Act 3's staged reveal, which is
// pacing over results that already exist when it starts (D50). The model judges nothing: it
// copies the Judge's facts (round records, benign results) and counts them for display.

export const ACTS = { IDLE: 0, ATTACK: 1, ANALYSIS: 2, VERDICT: 3 };
const FEED_MAX = 200;
export const KEEP_RUNS = 10; // as the live server (liveserver/tailer.py KEEP_RUNS)

// D61: the demo's three matchups, in plain words (projector, non-technical audience).
export const MATCHUPS = {
  taxonomy: { n: 1, title: "1 · Limited attacker vs limited defender" },
  freeplay: { n: 2, title: "2 · Free attacker vs limited defender" },
  open: { n: 3, title: "3 · Free attacker vs free defender (same attacks as 2)" },
};
export const MATCHUP_ORDER = ["taxonomy", "freeplay", "open"];

// The golden run of each matchup is the bundle golden-<matchup> (tools/export_golden.py).
export function matchupOfBundle(name) {
  const m = /^golden-(taxonomy|freeplay|open)$/.exec(name || "");
  return m ? m[1] : null;
}

export function initialState(mode = "live") {
  return {
    mode, // "live" | "replay"
    matchId: null,
    status: "idle", // idle | running | finished | failed
    act: ACTS.IDLE,
    startedAt: null, // ISO
    finishedAt: null,
    plan: null, // ["red" | "benign", ...] in slot order (derived, from the transcript)
    slots: [],
    red: { phase: "idle", round: null, since: null, slot: null },
    target: { hit: null, burst: null },
    blue: { calls: 0, failedCalls: 0, maxLogSeq: 0 },
    proxyLines: 0,
    cost: { usd: 0, calls: 0, lowerBound: false },
    catalog: {},
    library: null,
    newRules: 0, // rules Blue invented in this run (rules.jsonl); the library's are separate
    matchup: null, // D61: taxonomy | freeplay | open (from `demo matchup:` or the bundle name)
    runKind: "match", // match | replay
    sourceMatchId: null, // replay: the match whose log is re-judged
    source: null, // replay: the re-judged match's own results {rounds, benign} (original Blue)
    results: { rounds: {}, benign: {}, verdicts: 0, ready: false },
    reveal: { index: -1, done: false },
    finish: null,
    failure: null,
    feed: [],
    lastEventId: null,
  };
}

// ---------------------------------------------------------------- helpers
const clone = (s) => ({ ...s, slots: s.slots.slice(), feed: s.feed.slice() });

function feed(s, text, tone = "slate", at = null) {
  s.feed = [{ text, tone, at }, ...s.feed].slice(0, FEED_MAX);
}

function slotIndex(s, pred) {
  return s.slots.findIndex(pred);
}

function putSlot(s, i, patch) {
  s.slots[i] = { ...s.slots[i], ...patch };
}

function redSlot(s, round) {
  let i = slotIndex(s, (x) => x.kind === "red" && x.round === round);
  if (i < 0) {
    s.slots.push({ kind: "red", round, state: "pending" });
    i = s.slots.length - 1;
  }
  return i;
}

function nextBenignSlot(s) {
  let i = slotIndex(s, (x) => x.kind === "benign" && !x.requestId);
  if (i < 0) {
    s.slots.push({ kind: "benign", state: "pending" });
    i = s.slots.length - 1;
  }
  return i;
}

const short = (x, n = 160) => (typeof x === "string" && x.length > n ? `${x.slice(0, n)}…` : x);

// What Red sent, for display (free-play: technique; headers by name only, never values).
export function attackView(row) {
  return {
    round: row.round,
    label: row.label,
    technique: row.technique ?? null,
    method: row.method,
    endpoint: row.endpoint,
    payload: row.payload,
    rationale: row.rationale ?? null,
    headerNames: row.headers ? Object.keys(row.headers) : [],
    requestId: row.request_id,
  };
}

// An attack in plain words: Red's own technique when the run has it (live, free-play), else
// the name of its label (recorded bundles carry no technique, contract §6.14).
export const LABEL_NAMES = {
  "CWE-89": "SQL injection", "CWE-79": "cross-site scripting", "CWE-22": "path traversal",
  other: "an attack outside the three known types",
};
export const attackName = (a) => (a ? a.technique || LABEL_NAMES[a.label] || a.label || null : null);

// A Red turn with nothing sent, in plain words.
export const UNSENT_WHAT = {
  guard_block: "blocked by the rules of engagement",
  brain_failure: "the AI's reply was unusable",
  instrument_failure: "the AI call failed",
};

// The Judge's fact for a revealed slot -> the timeline outcome.
export function outcomeOf(slot, results) {
  if (slot.kind === "red") {
    if (slot.state === "unsent") return "unsent";
    const r = results.rounds[slot.round];
    if (!r) return "unscored";
    return r.detected ? "TP" : "FN";
  }
  const b = slot.requestId ? results.benign[slot.requestId] : null;
  if (!b) return "unscored";
  return b.false_positive ? "FP" : "quiet";
}

// ---------------------------------------------------------------- the reducer
export function reduce(state, ev) {
  if (!ev || typeof ev !== "object") return state;
  if (ev.type === "match_started") {
    const s = initialState(state.mode);
    s.matchId = ev.match_id ?? null;
    s.status = "running";
    s.act = ACTS.ATTACK;
    s.startedAt = ev.started_at ?? ev.observed_at ?? null;
    s.lastEventId = ev.id ?? null;
    s.matchup = ev.matchup ?? null;
    s.runKind = ev.kind === "replay" ? "replay" : "match";
    s.sourceMatchId = ev.source_match_id ?? null;
    // A recorded run knows its number of Red turns up front (from the bundle): lay out the
    // turn cards at once, as the live plan does. Pending until their own events arrive.
    for (let r = 1; r <= (ev.red_turns || 0); r++) s.slots.push({ kind: "red", round: r, state: "pending" });
    feed(s, s.runKind === "replay" ? "The free defender starts reading the same requests" : "Match started",
      "slate", ev.observed_at);
    return s;
  }
  if (ev.type === "reveal_next") return revealNext(state);
  if (state.status === "idle") return state; // nothing before a match starts
  const s = clone(state);
  s.lastEventId = ev.id ?? s.lastEventId;
  const at = ev.observed_at ?? null;
  const row = ev.row || {};

  switch (ev.type) {
    case "match_plan": {
      s.plan = Array.isArray(ev.planned) ? ev.planned.slice() : null;
      if (s.plan) {
        // Lay the timeline out in plan order; slots already seen keep their facts (a late
        // plan, e.g. a client that caught up, reorders them instead of being dropped).
        const reds = Object.fromEntries(s.slots.filter((x) => x.kind === "red").map((x) => [x.round, x]));
        const benign = s.slots.filter((x) => x.kind === "benign");
        let r = 0;
        let b = 0;
        s.slots = s.plan.map((k) => (k === "red" ? (reds[++r] || { kind: "red", round: r, state: "pending" })
          : (benign[b++] || { kind: "benign", state: "pending" })));
      }
      feed(s, `Plan: ${ev.n_red} attacker turns mixed with ${ev.n_benign} normal requests`, "slate", at);
      break;
    }
    case "target_reset":
      feed(s, "The web shop is reset: nothing hacked yet", "slate", at);
      break;
    case "library_loaded":
      s.library = { version: ev.library_version, rules: ev.n_rules };
      break;
    case "matchup":
      s.matchup = ev.matchup ?? s.matchup;
      break;
    case "source_results":
      s.source = {
        rounds: Object.fromEntries((ev.rounds || []).map((r) => [r.round, r])),
        benign: Object.fromEntries((ev.benign || []).map((b) => [b.request_id, b])),
      };
      break;
    case "rule":
      s.newRules += 1;
      break;
    case "challenge_catalog":
      s.catalog = ev.categories || {};
      break;
    case "red_turn_start": {
      const i = redSlot(s, ev.round);
      putSlot(s, i, { state: "active" });
      s.red = { phase: "thinking", round: ev.round, since: at, slot: i, attack: null, failure: null };
      s.target = { ...s.target, burst: null }; // the last turn's banner ends with the next turn
      feed(s, `Attacker turn ${ev.round}: thinking…`, "rose", at);
      break;
    }
    case "api_call": {
      s.cost = { usd: +(s.cost.usd + (ev.usd || 0)).toFixed(6), calls: s.cost.calls + 1,
        lowerBound: s.cost.lowerBound || !!ev.usd_lower_bound };
      if (row.agent === "red" && row.ok === false) {
        const secs = row.latency_ms != null ? ` after ${(row.latency_ms / 1000).toFixed(1)} s` : "";
        feed(s, `Attacker turn ${row.round}: the AI call failed${secs} (${row.error_type})`, "amber", at);
      } else if (row.agent === "blue") {
        s.blue = { ...s.blue, calls: s.blue.calls + 1,
          failedCalls: s.blue.failedCalls + (row.ok === false ? 1 : 0),
          maxLogSeq: Math.max(s.blue.maxLogSeq, row.log_seq_last || 0) };
        if (s.act < ACTS.ANALYSIS && s.status === "running") s.act = ACTS.ANALYSIS;
      }
      break;
    }
    case "blue_progress": // REPLAY only: Blue reached log line `log_seq` (from the bundle)
      s.blue = { ...s.blue, maxLogSeq: Math.max(s.blue.maxLogSeq, ev.log_seq || 0),
        calls: s.blue.calls + (ev.ai_call ? 1 : 0) };
      if (s.act < ACTS.ANALYSIS) s.act = ACTS.ANALYSIS;
      break;
    case "cost_total": // REPLAY only: the bundle's running cost at this point
      s.cost = { usd: ev.usd ?? s.cost.usd, calls: ev.calls ?? s.cost.calls, lowerBound: s.cost.lowerBound };
      break;
    case "red_attack": {
      const i = redSlot(s, row.round);
      const a = attackView(row);
      putSlot(s, i, { state: "sent", requestId: row.request_id, attack: a });
      s.red = { phase: "attack", round: row.round, since: s.red.since, slot: i, attack: a, failure: null };
      feed(s, `Attacker turn ${row.round}: ${attackName(a)} → ${a.method} ${short(a.endpoint, 60)}`, "rose", at);
      break;
    }
    case "red_unsent": {
      const i = redSlot(s, row.round);
      const failure = { kind: row.kind, reason: row.reason, detail: row.detail ?? null };
      putSlot(s, i, { state: "unsent", failure });
      s.red = { phase: "failed", round: row.round, since: s.red.since, slot: i, attack: null, failure };
      feed(s, `Attacker turn ${row.round}: nothing sent (${UNSENT_WHAT[row.kind] || row.kind})`, "amber", at);
      break;
    }
    case "benign_request": {
      const i = nextBenignSlot(s);
      putSlot(s, i, { state: "sent", requestId: row.request_id, benignId: row.benign_id,
        category: row.category });
      break;
    }
    case "proxy_line": {
      s.proxyLines += 1;
      const i = slotIndex(s, (x) => x.requestId && x.requestId === row.request_id);
      if (i >= 0) {
        putSlot(s, i, { status: row.status });
        if (s.slots[i].kind === "red") {
          s.target = { ...s.target, hit: { status: row.status, requestId: row.request_id, seq: s.proxyLines } };
          feed(s, `The web shop answered attacker turn ${s.slots[i].round}: HTTP ${row.status}`, "slate", at);
        }
      }
      break;
    }
    case "snapshot": {
      const newly = ev.newly_solved || [];
      const i = slotIndex(s, (x) => x.requestId && x.requestId === row.request_id);
      if (i >= 0) putSlot(s, i, { newlySolved: newly });
      if (newly.length) {
        s.target = { ...s.target, burst: { names: newly, requestId: row.request_id,
          traffic: row.traffic, seq: (s.target.burst?.seq || 0) + 1 } };
        const who = row.traffic === "red" ? "The attack succeeded" : "Normal traffic solved a challenge";
        feed(s, `${who}: ${newly.join(", ")}`, row.traffic === "red" ? "rose" : "amber", at);
      }
      break;
    }
    case "slot_done":
      break; // the artifacts already carry the slot's facts
    case "proxy_frozen":
      if (s.act < ACTS.ANALYSIS) s.act = ACTS.ANALYSIS;
      s.red = { ...s.red, phase: "done" };
      s.target = { ...s.target, burst: null };
      feed(s, "Attacks over. Blue now reads the record of every request (it never stood in the way).", "sky", at);
      break;
    case "landed":
      break;
    case "verdict":
      s.results = { ...s.results, verdicts: s.results.verdicts + 1 };
      break;
    case "round_record":
      s.results = { ...s.results, rounds: { ...s.results.rounds, [row.round]: row } };
      break;
    case "benign_result":
      s.results = { ...s.results, benign: { ...s.results.benign, [row.request_id]: row } };
      break;
    case "match_failed":
      s.failure = { step: ev.step, error: ev.error };
      feed(s, "The run stopped with an error", "amber", at);
      break;
    case "match_finished": {
      s.finish = { status: ev.status, failedStep: ev.failed_step ?? null, error: ev.error ?? null,
        costUsd: ev.cost_usd ?? null, finishedAt: ev.finished_at ?? null };
      s.finishedAt = ev.finished_at ?? at;
      if (ev.started_at) s.startedAt = ev.started_at; // match.json: the true start
      if (typeof ev.cost_usd === "number") s.cost = { ...s.cost, usd: ev.cost_usd };
      if (ev.status === "failed") {
        s.status = "failed";
        s.failure = s.failure || { step: ev.failed_step, error: ev.error };
      } else {
        s.status = "finished";
        s.act = ACTS.VERDICT; // every result is on disk now; the reveal is pacing only
        s.results = { ...s.results, ready: true };
        s.reveal = { index: -1, done: s.slots.length === 0 };
      }
      feed(s, ev.status === "failed" ? "The run stopped with an error" : "Results are in", "slate", at);
      break;
    }
    case "tail_warning":
    case "schedule_mismatch":
      feed(s, `${ev.type}: ${ev.detail || ev.kind || ""}`, "amber", at);
      break;
    default:
      break;
  }
  return s;
}

// Act 3: flip the next slot (pacing only; the facts were already on disk).
export function revealNext(state) {
  if (state.act !== ACTS.VERDICT || state.reveal.done) return state;
  const s = clone(state);
  const i = s.reveal.index + 1;
  if (i >= s.slots.length) {
    s.reveal = { index: s.reveal.index, done: true };
    return s;
  }
  putSlot(s, i, { outcome: outcomeOf(s.slots[i], s.results) });
  s.reveal = { index: i, done: i === s.slots.length - 1 };
  return s;
}

// Scoreboard: counts of what is on screen (Act 1 traffic; Act 3 revealed Judge facts).
export function scoreboard(s) {
  const reds = s.slots.filter((x) => x.kind === "red");
  const benign = s.slots.filter((x) => x.kind === "benign");
  const outcomes = s.slots.map((x) => x.outcome).filter(Boolean);
  const count = (o) => outcomes.filter((x) => x === o).length;
  return {
    redTurns: reds.filter((x) => x.state !== "pending").length,
    sent: reds.filter((x) => x.state === "sent").length,
    unsent: reds.filter((x) => x.state === "unsent").length,
    landed: reds.filter((x) => (x.newlySolved || []).length > 0).length,
    solved: [...new Set(s.slots.flatMap((x) => x.newlySolved || []))],
    benignSent: benign.filter((x) => x.state === "sent").length,
    tp: count("TP"), fn: count("FN"), fp: count("FP"), quiet: count("quiet"),
    revealed: outcomes.length,
  };
}

// Blue's progress in Act 2: how far through the log Blue's calls have reached (ledger
// log_seq_last). Lines answered by a rule make no call; they are counted when reached.
export function blueProgress(s) {
  const total = s.proxyLines;
  // In Act 3 every verdict is on disk: Blue has read the whole log (the lines after its last
  // AI call were answered by rules, which make no ledger line).
  const reached = s.act === ACTS.VERDICT ? total : Math.min(s.blue.maxLogSeq, total);
  return { reached, total, calls: s.blue.calls };
}

// ---------------------------------------------------------------- REPLAY: bundle -> events
// Built only from the bundle's fields (exported from the artifacts). Each step becomes the
// events the live tailer would have emitted for it; unsent Red turns are placed by round.
export function bundleToEvents(bundle, opts = {}) {
  const out = [];
  let id = 0;
  const push = (type, data = {}) => out.push({ id: ++id, type, match_id: bundle.match_id, ...data });
  const rounds = [...(bundle.steps || []).map((st) => (st.red?.kind === "attack" ? st.red.round : 0)),
    ...(bundle.unsent || []).map((u) => u.round)];
  push("match_started", { source: "bundle", kind: bundle.kind === "replay" ? "replay" : "match",
    red_turns: rounds.length ? Math.max(...rounds) : 0,
    matchup: opts.matchup ?? null, source_match_id: bundle.kind === "replay" ? bundle.match_id : null });
  // Matchup 3: the re-judged match's own results, from its bundle (same match_id, D61).
  if (opts.source) push("source_results", sourceResultsOf(opts.source));
  if (bundle.meta?.library) push("library_loaded", { library_version: bundle.meta.library.library_version,
    n_rules: bundle.meta.library.entries });
  const steps = bundle.steps || [];
  const unsent = (bundle.unsent || []).slice().sort((a, b) => a.round - b.round);
  let u = 0;
  const flushUnsent = (beforeRound) => {
    while (u < unsent.length && (beforeRound == null || unsent[u].round < beforeRound)) {
      const x = unsent[u++];
      push("red_turn_start", { round: x.round, derived: true, source: "bundle" });
      push("red_unsent", { row: { round: x.round, kind: x.kind, reason: x.reason, detail: null } });
    }
  };
  for (const st of steps) {
    const q = st.request || {};
    if (st.red?.kind === "attack") {
      flushUnsent(st.red.round);
      push("red_turn_start", { round: st.red.round, derived: true, source: "bundle" });
      push("red_attack", { row: { round: st.red.round, request_id: st.request_id, label: st.red.label,
        technique: st.red.technique ?? null, method: q.method, endpoint: q.path,
        payload: q.body || (q.query ? `${q.path}?${q.query}` : q.path), rationale: st.red.rationale ?? null } });
    } else {
      push("benign_request", { row: { request_id: st.request_id, benign_id: st.red?.benign_id ?? null,
        category: st.red?.category ?? null } });
    }
    push("proxy_line", { row: { request_id: st.request_id, status: q.status } });
    push("snapshot", { row: { request_id: st.request_id, traffic: st.red?.kind === "attack" ? "red" : "benign" },
      newly_solved: st.judge?.newly_solved || [] });
  }
  flushUnsent(null);
  push("proxy_frozen");
  for (const r of bundle.rules || []) if (r.origin === "match") push("rule", { row: { rule_id: r.rule_id } });
  for (const st of steps) {
    push("blue_progress", { log_seq: st.log_seq, ai_call: st.blue?.source === "ai" });
    if (st.cost_so_far) push("cost_total", { usd: st.cost_so_far.usd, calls: st.cost_so_far.calls });
  }
  for (const st of steps) {
    if (st.blue) push("verdict", { row: { request_id: st.request_id, verdict: st.blue.verdict } });
    if (st.judge?.kind === "attack") {
      push("round_record", { row: { round: st.red.round, request_id: st.request_id,
        detected: st.judge.detected, landed: st.judge.landed, newly_solved: st.judge.newly_solved } });
    } else if (st.judge?.kind === "benign") {
      push("benign_result", { row: { request_id: st.request_id, false_positive: st.judge.false_positive } });
    }
  }
  push("match_finished", { status: bundle.meta?.status || "completed", cost_usd: bundle.total_cost?.usd ?? null });
  push("lock_released");
  return out;
}

// REPLAY pacing (ms before an event is shown). Pacing only: nothing here changes a fact.
// Matchup 3 (skipAttack) has no attack act: its traffic is the attacks of matchup 2, so
// those events pass without pacing and the replay starts at the defender reading them.
const TRAFFIC_EVENTS = new Set(["red_turn_start", "red_attack", "red_unsent", "proxy_line", "snapshot",
  "benign_request"]);
export function replayDelay(ev, skipAttack = false) {
  if (skipAttack && TRAFFIC_EVENTS.has(ev.type)) return 0;
  switch (ev.type) {
    case "red_turn_start": return 900;
    case "red_attack": return 1400;
    case "red_unsent": return 1400;
    case "proxy_line": return 900;
    case "snapshot": return 500;
    case "benign_request": return 250;
    case "proxy_frozen": return 1200;
    case "blue_progress": return 120;
    case "match_finished": return 900;
    default: return 0;
  }
}

// Run a whole event list through the model, then the full Act 3 reveal (tests, catch-up).
export function playAll(events, mode = "live") {
  let s = initialState(mode);
  for (const ev of events) s = reduce(s, ev);
  let guard = s.slots.length + 2;
  while (s.act === ACTS.VERDICT && !s.reveal.done && guard-- > 0) s = revealNext(s);
  return s;
}

// The original Blue's results of a match bundle, as the live tailer's source_results event.
export function sourceResultsOf(bundle) {
  const steps = bundle.steps || [];
  return {
    source_match_id: bundle.match_id,
    rounds: steps.filter((st) => st.judge?.kind === "attack").map((st) => ({ round: st.red.round,
      request_id: st.request_id, detected: st.judge.detected, landed: st.judge.landed })),
    benign: steps.filter((st) => st.judge?.kind === "benign").map((st) => ({ request_id: st.request_id,
      false_positive: st.judge.false_positive })),
  };
}

// The bundle a matchup-3 bundle re-judges: the match bundle with the same match_id.
export function sourceBundleFor(bundle, bundles) {
  if (!bundle || bundle.kind !== "replay") return null;
  return Object.values(bundles || {}).find((b) => b.kind === "match" && b.match_id === bundle.match_id) || null;
}

// ---------------------------------------------------------------- runs (D61 switcher)
// LIVE: the server's history holds several runs, each starting with match_started. Every run
// keeps its own model state, so the presenter can return to an earlier matchup.
export function reduceRuns(runs, ev) {
  if (!ev || typeof ev !== "object") return runs;
  if (ev.type === "match_started") {
    const id = ev.match_id ?? `run-${runs.length + 1}`;
    const kept = runs.filter((r) => r.id !== id); // a reconnect replays history: same run again
    return [...kept, { id, state: reduce(initialState("live"), ev) }].slice(-KEEP_RUNS);
  }
  if (ev.type === "reveal_next") {
    return runs.map((r) => (r.id === ev.run ? { ...r, state: revealNext(r.state) } : r));
  }
  if (!runs.length) return runs;
  const target = ev.match_id != null ? runs.findIndex((r) => r.id === ev.match_id) : runs.length - 1;
  const i = target >= 0 ? target : runs.length - 1;
  const next = reduce(runs[i].state, ev);
  if (next === runs[i].state) return runs;
  const out = runs.slice();
  out[i] = { ...runs[i], state: next };
  return out;
}

// The latest live run of a matchup (the switcher's first choice; else its golden run).
export function latestRunOf(runs, matchup) {
  for (let i = runs.length - 1; i >= 0; i--) if (runs[i].state.matchup === matchup) return runs[i];
  return null;
}

// ---------------------------------------------------------------- display selectors
const isRed = (x) => x.kind === "red";
const judged = (s, round) => (s.results.ready ? s.results.rounds[round] : null);

// Did this attack succeed? The Judge's landed fact once results are in; before, a challenge
// solved right after the request (the live snapshot).
export function succeeded(s, slot) {
  const r = judged(s, slot.round);
  if (r) return r.landed === true;
  return (slot.newlySolved || []).length > 0;
}

// Item 5: one large card per Red turn, one outcome each.
export function turnCards(s) {
  return s.slots.filter(isRed).map((x) => ({
    round: x.round,
    state: x.state, // pending | active | sent | unsent
    outcome: x.outcome === "TP" ? "caught" : x.outcome === "FN" ? "missed" : x.outcome === "unsent" ? "not sent"
      : x.outcome === "unscored" ? "no result" : null,
    succeeded: x.state === "sent" && succeeded(s, x),
    technique: attackName(x.attack),
  }));
}

// Item 5: normal traffic as one line; false alarms once the reveal is done.
export function normalLine(s) {
  const benign = s.slots.filter((x) => x.kind === "benign");
  const sent = benign.filter((x) => x.state === "sent").length;
  const done = s.act === ACTS.VERDICT && s.reveal.done;
  const alarms = done ? benign.filter((x) => x.outcome === "FP").length : null;
  return { sent, alarms, text: `${sent} normal request${sent === 1 ? "" : "s"}${done ? ` · ${alarms} false alarm${alarms === 1 ? "" : "s"}` : ""}` };
}

// Item 6: four numbers. Caught / missed count revealed turns only (Act 3 pacing, D50).
export function stats4(s) {
  const reds = s.slots.filter(isRed);
  return {
    attacks: reds.filter((x) => x.state === "sent").length,
    caught: reds.filter((x) => x.outcome === "TP").length,
    missed: reds.filter((x) => x.outcome === "FN").length,
    succeeded: reds.filter((x) => x.state === "sent" && succeeded(s, x)).length,
    verdictsShown: s.act === ACTS.VERDICT,
  };
}

// Item 8: the attacks Blue missed, once revealed.
export function missedAttacks(s) {
  return s.slots.filter((x) => isRed(x) && x.outcome === "FN").map((x) => ({
    round: x.round, technique: attackName(x.attack),
    succeeded: succeeded(s, x),
  }));
}

// Item 3: matchup 3, both Blues on the same attacks. The original verdicts are the source
// match's own results (shown from the start); the open ones appear as they are revealed.
export function sideBySide(s) {
  const src = s.source || { rounds: {}, benign: {} };
  const rows = s.slots.filter((x) => isRed(x) && x.state === "sent").map((x) => {
    const o = src.rounds[x.round];
    return {
      round: x.round,
      technique: attackName(x.attack),
      original: o ? (o.detected ? "caught" : "missed") : null,
      open: x.outcome === "TP" ? "caught" : x.outcome === "FN" ? "missed" : null,
      succeeded: o ? o.landed === true : succeeded(s, x),
    };
  });
  const benign = s.slots.filter((x) => x.kind === "benign" && x.state === "sent");
  const done = s.act === ACTS.VERDICT && s.reveal.done;
  return {
    rows,
    normal: benign.length,
    originalAlarms: s.source ? benign.filter((x) => src.benign[x.requestId]?.false_positive === true).length : null,
    openAlarms: done ? benign.filter((x) => x.outcome === "FP").length : null,
    hasSource: !!s.source,
  };
}

// Item 4: one summary row per matchup, from a FINISHED run's Judge results (all of them,
// whatever the reveal shows). Copy and count only.
export function summaryRow(s) {
  if (!s || !s.results.ready) return null;
  const rounds = Object.values(s.results.rounds);
  const benign = Object.values(s.results.benign);
  return {
    attacks: rounds.length,
    caught: rounds.filter((r) => r.detected === true).length,
    missed: rounds.filter((r) => r.detected === false).length,
    succeededMissed: rounds.filter((r) => r.landed === true && r.detected === false).length,
    succeeded: rounds.filter((r) => r.landed === true).length,
    falseAlarms: benign.filter((b) => b.false_positive === true).length,
    normal: benign.length,
  };
}
