import React, { useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  ACTS, MATCHUPS, MATCHUP_ORDER, SUCCESS_RULES, UNSENT_WHAT, attackName, blueProgress, successRule, bundleToEvents, initialState, latestRunOf,
  matchupOfBundle, missedAttacks, normalLine, playAll, reduce, reduceRuns, reduceSession, replayDelay,
  sessionRuns, sideBySide,
  sourceBundleFor, stats4, summaryRow, turnCards,
} from "./model.js";
import { connectLive } from "./live.js";
import { runLabel } from "../labels.js";

// Battle view (Stage 7 #13; #29 clarity pass; D61 three matchups). For a non-technical
// audience at a glance: the matchup in plain words, ten numbered attacker turns, four numbers.
// Three acts (D47): 1 attack (live), 2 Blue analysis, 3 verdict (staged reveal of results
// already on disk). Matchup 3 has no attack act: both defenders' verdicts on the same
// attacks, side by side. Honesty (D50): every animation is triggered by a real event; Blue
// is a radar that reads the record afterwards, never a shield; failures are ordinary events.

const REVEAL_MS = 450;

function useNow(ms = 250) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

const mmss = (ms) => {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return "0:00";
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};
const since = (iso, now) => (iso ? now - Date.parse(iso) : null);

function Typewriter({ text, cps = 45 }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    setN(0);
    if (!text) return undefined;
    const step = Math.max(1, Math.ceil(text.length / ((2000 * cps) / 1000)));
    const t = setInterval(() => setN((k) => (k >= text.length ? k : k + step)), 1000 / cps);
    return () => clearInterval(t);
  }, [text, cps]);
  return (
    <span>
      {text.slice(0, n)}
      {n < text.length && <span className="caret">▌</span>}
    </span>
  );
}

const ACT_NAMES = { 1: "Attack", 2: "Defender reads", 3: "Verdict" };

function Header({ state, conn, mode, now, title }) {
  const elapsed = state.startedAt
    ? (state.finishedAt ? Date.parse(state.finishedAt) : now) - Date.parse(state.startedAt) : null;
  const acts = state.matchup === "open" || state.runKind === "replay" ? [2, 3] : [1, 2, 3];
  return (
    <header className="flex flex-col gap-3 border-b border-slate-800 pb-3">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-4xl font-black text-white lg:text-5xl">{title}</h1>
        <div className="flex items-center gap-5 text-xl">
          {mode === "live" ? (
            <span className={`flex items-center gap-2 font-bold ${conn === "open" ? "text-emerald-400" : "text-amber-400"}`}>
              <span className={`inline-block h-3 w-3 rounded-full ${conn === "open" ? "live-dot bg-emerald-400" : "bg-amber-400"}`} />
              {conn === "open" ? "LIVE" : conn === "reconnecting" ? "RECONNECTING" : "CONNECTING"}
            </span>
          ) : (
            <span className="rounded bg-amber-500 px-3 py-1 font-black text-slate-950">RECORDED</span>
          )}
          <span className="font-mono text-white" title="time">⏱ {mmss(elapsed)}</span>
          <span className="font-mono text-emerald-300" title="AI cost so far">
            ${state.cost.usd.toFixed(4)}{state.cost.lowerBound ? "+" : ""}
          </span>
        </div>
      </div>
      <div className="flex gap-2">
        {acts.map((a) => (
          <span key={a} className={`rounded-full px-4 py-1 text-lg font-bold ${
            state.act === a ? "bg-white text-slate-950" : state.act > a ? "bg-slate-700 text-slate-200" : "bg-slate-900 text-slate-500"}`}>
            {ACT_NAMES[a]}
          </span>
        ))}
      </div>
    </header>
  );
}

function Panel({ title, sub, tone, children, className = "" }) {
  return (
    <section className={`flex min-h-0 flex-col gap-3 rounded-2xl border-2 bg-slate-900/80 p-5 ${tone} ${className}`}>
      <div>
        <h2 className="text-2xl font-black tracking-wide">{title}</h2>
        {sub && <p className="text-base text-slate-400">{sub}</p>}
      </div>
      {children}
    </section>
  );
}

function Star() {
  return <span className="rounded bg-yellow-400 px-2 py-0.5 text-base font-black text-slate-950">★ succeeded</span>;
}

function RedPanel({ state, now }) {
  const r = state.red;
  let body;
  if (state.act === ACTS.VERDICT) {
    // Item 8: the attacks Blue missed, as they are revealed.
    const missed = missedAttacks(state);
    body = missed.length ? (
      <div className="flex flex-col gap-2">
        <div className="text-2xl font-bold text-rose-200">Attacks the defender missed</div>
        {missed.map((m) => (
          <div key={m.round} className="flip-in flex flex-wrap items-center gap-2 rounded-lg bg-slate-950 px-3 py-2">
            <span className="rounded bg-rose-600 px-2 py-0.5 text-lg font-black text-white">Turn {m.round}</span>
            <span className="text-xl text-rose-100">{m.technique || "attack"}</span>
            {m.succeeded && <Star />}
          </div>
        ))}
      </div>
    ) : (
      <div className="py-6 text-2xl text-slate-300">
        {state.reveal.done ? "The defender missed no attack." : "Revealing the verdicts…"}
      </div>
    );
  } else if (r.phase === "thinking") {
    body = (
      <div className="flex flex-col items-center gap-3 py-6">
        <div className="thinking text-6xl">◉</div>
        <div className="text-3xl font-bold text-rose-200">Turn {r.round}: thinking…</div>
        <div className="font-mono text-2xl text-slate-300">{mmss(since(r.since, now))}</div>
      </div>
    );
  } else if (r.phase === "attack" && r.attack) {
    const a = r.attack;
    body = (
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded bg-rose-600 px-3 py-1 text-xl font-bold text-white">Turn {a.round}</span>
          {a.headerNames.map((h) => (
            <span key={h} className="rounded bg-violet-700 px-2 py-1 text-base text-white">with {h}</span>
          ))}
        </div>
        <div className="text-3xl font-bold leading-tight text-rose-100">{attackName(a)}</div>
        <div className="break-all rounded-xl bg-black/70 p-4 font-mono text-xl leading-relaxed text-emerald-300">
          <span className="text-sky-400">{a.method} </span>
          <Typewriter key={a.requestId} text={a.payload || a.endpoint || ""} />
        </div>
        {a.rationale && <p className="text-lg italic text-slate-300">“{a.rationale}”</p>}
      </div>
    );
  } else if (r.phase === "failed" && r.failure) {
    const f = r.failure;
    body = (
      <div className="flex flex-col gap-2 rounded-xl border-2 border-amber-500 bg-amber-950/60 p-4">
        <div className="text-2xl font-bold text-amber-200">Turn {r.round}: nothing sent</div>
        <div className="text-xl text-amber-100">{UNSENT_WHAT[f.kind] || f.kind}</div>
        <div className="font-mono text-sm text-amber-300/70">{f.reason}</div>
      </div>
    );
  } else if (r.phase === "done") {
    body = <div className="py-6 text-2xl text-slate-300">The attacker's turns are over.</div>;
  } else {
    body = <div className="py-6 text-2xl text-slate-500">Waiting for the attacker's turn…</div>;
  }
  return (
    <Panel title="RED · attacker" sub="an AI that proposes one request per turn" tone="border-rose-600 text-rose-300">
      {body}
    </Panel>
  );
}

function Stat({ label, value, tone = "text-white" }) {
  return (
    <div className="rounded-lg bg-slate-950 p-2">
      <div className={`text-5xl font-black ${tone}`}>{value}</div>
      <div className="text-base uppercase tracking-wide text-slate-400">{label}</div>
    </div>
  );
}

function TargetPanel({ state }) {
  const hit = state.target.hit;
  const burst = state.target.burst;
  const st = stats4(state);
  const tone = (x) => (x >= 500 ? "bg-rose-600" : x >= 400 ? "bg-amber-500" : x >= 300 ? "bg-sky-600" : "bg-emerald-600");
  return (
    <Panel title="TARGET · web shop" sub="a practice shop with known weaknesses; nothing protects it" tone="border-slate-500 text-slate-200">
      <div className="relative flex h-40 items-center justify-center rounded-xl bg-black/60">
        {hit ? (
          <div key={hit.seq} className={`hit rounded-xl px-6 py-3 text-4xl font-black text-white ${tone(hit.status)}`}>
            HTTP {hit.status}
          </div>
        ) : (
          <div className="text-2xl text-slate-500">no attack yet</div>
        )}
        {burst && (
          <div key={`b${burst.seq}`} className="burst absolute inset-x-2 bottom-2 rounded-lg bg-yellow-400 px-3 py-2 text-center text-xl font-black text-slate-950">
            ★ {burst.traffic === "red" && successRule(state.matchup) === "any" ? "Attack succeeded" : "Challenge solved"}: {burst.names.join(", ")}
          </div>
        )}
      </div>
      <div className="grid grid-cols-4 gap-2 text-center">
        <Stat label="attacks" value={st.attacks} />
        <Stat label="caught" value={st.verdictsShown ? st.caught : "–"} tone="text-emerald-300" />
        <Stat label="missed" value={st.verdictsShown ? st.missed : "–"} tone="text-rose-300" />
        <Stat label="succeeded" value={st.succeeded ?? "–"} tone="text-yellow-300" />
      </div>
      <RuleNote rule={st.rule} />
    </Panel>
  );
}

// Which definition of "succeeded" applies, in plain words (one per matchup).
function RuleNote({ rule }) {
  return <div className="text-base text-slate-400">★ {SUCCESS_RULES[rule]}</div>;
}

function LibraryLine({ state }) {
  if (!state.library) return null;
  return (
    <span className="text-lg text-amber-300">
      Rule library: {state.library.rules} rules learned in earlier matches · {state.newRules} new rule{state.newRules === 1 ? "" : "s"} this match
    </span>
  );
}

function BluePanel({ state, title = "BLUE · defender", sub = "reads the record of every request after the attacks; never blocks" }) {
  const p = blueProgress(state);
  const sweeping = state.act === ACTS.ANALYSIS;
  const pct = p.total ? Math.round((100 * p.reached) / p.total) : 0;
  return (
    <Panel title={title} sub={sub} tone="border-sky-600 text-sky-300">
      <div className="flex items-center gap-5">
        <div className={`radar ${sweeping ? "radar-on" : ""}`} />
        <div className="flex flex-col gap-1 text-xl">
          {state.act <= ACTS.ATTACK && <span className="text-slate-400">Waits until the attacks are over.</span>}
          {state.act >= ACTS.ANALYSIS && (
            <span className="text-white">requests read <b className="font-mono">{p.reached}</b> / {p.total}</span>
          )}
          <LibraryLine state={state} />
        </div>
      </div>
      {state.act >= ACTS.ANALYSIS && (
        <div className="h-3 rounded bg-slate-800">
          <div className="h-3 rounded bg-sky-500 transition-all" style={{ width: `${pct}%` }} />
        </div>
      )}
      {state.act === ACTS.VERDICT && (
        <div className="text-xl text-sky-200">{state.reveal.done ? "All verdicts shown." : "Showing the verdicts…"}</div>
      )}
    </Panel>
  );
}

const CARD = {
  caught: ["bg-emerald-500 text-slate-950", "✓", "caught"],
  missed: ["bg-rose-600 text-white", "✗", "missed"],
  "not sent": ["bg-slate-700 text-slate-200", "–", "not sent"],
  "no result": ["bg-slate-800 text-slate-400", "?", "no result"],
};

function Legend() {
  return (
    <div className="flex flex-wrap gap-5 text-lg text-slate-300">
      <span><b className="text-emerald-400">✓</b> caught</span>
      <span><b className="text-rose-400">✗</b> missed</span>
      <span><b className="text-slate-400">–</b> not sent</span>
      <span><b className="text-yellow-300">★</b> attack succeeded</span>
    </div>
  );
}

// Item 5: the ten attacker turns as large numbered cards, one outcome each.
function Timeline({ state }) {
  const cards = turnCards(state);
  const normal = normalLine(state);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        {cards.map((c) => {
          const o = c.outcome && CARD[c.outcome];
          const cls = o ? o[0] : c.state === "active" ? "bg-rose-500 thinking text-white"
            : c.state === "sent" ? "bg-rose-800 text-white" : c.state === "unsent" ? "unsent-cell text-amber-200"
              : "border-2 border-slate-600 text-slate-500";
          return (
            <div key={`${c.round}-${c.outcome || c.state}`} title={c.technique || ""}
              className={`relative flex h-20 w-24 flex-col items-center justify-center rounded-xl ${o ? "flip" : ""} ${cls}`}>
              <span className="text-sm font-bold opacity-80">turn {c.round}</span>
              <span className="text-3xl font-black">{o ? o[1] : c.state === "unsent" ? "–" : c.round}</span>
              {o && <span className="text-xs font-bold uppercase">{o[2]}</span>}
              {c.succeeded && <span className="absolute -right-2 -top-2 text-2xl text-yellow-300">★</span>}
            </div>
          );
        })}
      </div>
      <div className="text-xl text-slate-200">{normal.text}</div>
      <Legend />
      <RuleNote rule={successRule(state.matchup)} />
    </div>
  );
}

function Feed({ state }) {
  const tones = { rose: "text-rose-300", amber: "text-amber-300", sky: "text-sky-300", slate: "text-slate-300" };
  return (
    <div className="flex flex-col gap-1 overflow-hidden text-lg">
      {state.feed.slice(0, 6).map((f, i) => (
        <div key={state.feed.length - i} className={`${tones[f.tone] || "text-slate-300"} ${i === 0 ? "font-bold" : "opacity-80"}`}>
          {f.text}
        </div>
      ))}
    </div>
  );
}

function RunSummary({ state }) {
  if (state.status === "failed") {
    return (
      <div className="rounded-2xl border-2 border-amber-500 bg-amber-950/70 p-5 text-2xl text-amber-100">
        This run stopped with an error. Switch to the recorded run.
      </div>
    );
  }
  if (!(state.act === ACTS.VERDICT && state.reveal.done)) return null;
  const st = stats4(state);
  const alarms = normalLine(state).alarms;
  return (
    <div className="flip-in rounded-2xl border-2 border-white bg-slate-900 p-5 text-3xl font-black text-white">
      The defender caught {st.caught} of {st.attacks} attacks · {alarms} false alarm{alarms === 1 ? "" : "s"} · {st.succeeded} attack{st.succeeded === 1 ? "" : "s"} succeeded
      <div className="mt-1 text-lg font-normal text-slate-400">★ {SUCCESS_RULES[st.rule]}</div>
    </div>
  );
}

// Item 3: matchup 3 — both defenders on the same attacks and normal requests.
function Verdict({ v, pending }) {
  if (!v) return <span className="text-xl text-slate-500">{pending}</span>;
  const [cls, mark, word] = CARD[v];
  return <span className={`flip-in rounded-lg px-3 py-1 text-xl font-black ${cls}`}>{mark} {word}</span>;
}

function SideBySide({ state }) {
  const sb = sideBySide(state);
  const reading = state.act < ACTS.VERDICT ? "reading…" : "…";
  return (
    <div className="flex flex-col gap-4">
      <BluePanel state={state} title="FREE DEFENDER · reading the same requests"
        sub="the same attacks as matchup 2, judged again with a wider idea of what an attack is" />
      <section className="rounded-2xl border border-slate-700 bg-slate-900/70 p-4">
        <table className="w-full table-fixed border-separate border-spacing-y-2 text-xl">
          <thead>
            <tr className="text-left text-lg text-slate-400">
              <th className="w-24">turn</th><th>attack</th>
              <th className="w-72">limited defender (matchup 2)</th><th className="w-72">free defender</th>
            </tr>
          </thead>
          <tbody>
            {sb.rows.map((r) => (
              <tr key={r.round} className="bg-slate-950">
                <td className="rounded-l-lg px-3 py-2 font-black text-white">{r.round}</td>
                <td className="truncate px-2 text-rose-100" title={r.technique || ""}>
                  {r.technique || "attack"} {r.succeeded && <Star />}
                </td>
                <td className="px-2"><Verdict v={r.original} pending={sb.hasSource ? "–" : "not available"} /></td>
                <td className="rounded-r-lg px-2"><Verdict v={r.open} pending={reading} /></td>
              </tr>
            ))}
            <tr className="bg-slate-950">
              <td className="rounded-l-lg px-3 py-2 text-slate-300" colSpan={2}>{sb.normal} normal requests</td>
              <td className="px-2 text-slate-200">{sb.originalAlarms == null ? "–" : `${sb.originalAlarms} false alarms`}</td>
              <td className="rounded-r-lg px-2 text-slate-200">{sb.openAlarms == null ? reading : `${sb.openAlarms} false alarms`}</td>
            </tr>
          </tbody>
        </table>
        <div className="mt-2 flex flex-col gap-1"><Legend /><RuleNote rule={successRule(state.matchup)} /></div>
      </section>
    </div>
  );
}

// Item 4: all three matchups at a glance.
export function SummaryAll({ rows, onCompare }) {
  return (
    <div className="flip-in flex flex-col gap-4 rounded-2xl border-2 border-white bg-slate-900 p-5">
      <div className="text-3xl font-black text-white">All three matchups</div>
      <table className="w-full table-fixed border-separate border-spacing-y-2 text-2xl">
        <thead>
          <tr className="text-left text-lg text-slate-400">
            <th className="w-1/3">matchup</th><th>caught</th><th>missed</th><th>successful attacks missed</th><th>false alarms</th>
          </tr>
        </thead>
        <tbody>
          {MATCHUP_ORDER.map((m) => {
            const r = rows[m];
            return (
              <tr key={m} className="bg-slate-950">
                <td className="rounded-l-lg px-3 py-2 font-bold text-white">
                  {MATCHUPS[m].title}
                  {r?.recorded && <span className="ml-2 rounded bg-amber-500 px-2 text-sm font-black text-slate-950">recorded</span>}
                </td>
                {r ? (
                  <>
                    <td className="px-2 text-emerald-300">{r.caught} of {r.attacks}</td>
                    <td className="px-2 text-rose-300">{r.missed}</td>
                    <td className="px-2 text-yellow-300">{r.succeededMissed} of {r.succeeded}</td>
                    <td className="rounded-r-lg px-2 text-orange-300">{r.falseAlarms} of {r.normal}</td>
                  </>
                ) : (
                  <td className="rounded-r-lg px-2 text-slate-500" colSpan={4}>not run yet</td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="text-lg text-slate-400">
        ★ succeeded — matchup 1: {SUCCESS_RULES.mapped.replace("succeeded = ", "")} · matchups 2 and 3:
        {" "}{SUCCESS_RULES.any.replace("succeeded = ", "")}
      </div>
      <div>
        <button onClick={onCompare} className="rounded-xl bg-sky-500 px-5 py-3 text-2xl font-black text-slate-950 hover:bg-sky-400">
          Why? → Compare
        </button>
      </div>
    </div>
  );
}

// One run on screen (live or recorded).
function Stage({ state, mode, conn, now, title, summaryRows, onCompare }) {
  if (state.status === "idle") {
    return <div className="flex flex-1 items-center justify-center text-3xl text-slate-400">Loading…</div>;
  }
  const three = state.matchup === "open" || state.runKind === "replay";
  const done = state.act === ACTS.VERDICT && state.reveal.done;
  return (
    <div className="flex flex-col gap-4">
      <Header state={state} conn={conn} mode={mode} now={now} title={title} />
      {three ? <SideBySide state={state} /> : (
        <>
          <main className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <RedPanel state={state} now={now} />
            <TargetPanel state={state} />
            <BluePanel state={state} />
          </main>
          <section className="grid grid-cols-1 gap-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 lg:grid-cols-3">
            <div className="lg:col-span-2"><Timeline state={state} /></div>
            <Feed state={state} />
          </section>
        </>
      )}
      {three && done ? <SummaryAll rows={summaryRows} onCompare={onCompare} /> : <RunSummary state={state} />}
    </div>
  );
}

const titleOf = (state, fallback) => (state.matchup ? MATCHUPS[state.matchup].title : fallback);

// A recorded run, played back with pacing (REPLAY).
function BundlePlayer({ name, bundle, source, conn, summaryRows, onCompare }) {
  const matchup = matchupOfBundle(name);
  const events = useMemo(() => bundleToEvents(bundle, { matchup, source }), [bundle, matchup, source]);
  const [state, dispatch] = useReducer(reduce, "replay", initialState);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [pos, setPos] = useState(0);
  const now = useNow();

  useEffect(() => {
    if (!playing || pos >= events.length) return undefined;
    const ev = events[pos];
    const t = setTimeout(() => {
      dispatch({ ...ev, observed_at: new Date().toISOString(),
        started_at: ev.type === "match_started" ? new Date().toISOString() : undefined,
        finished_at: ev.type === "match_finished" ? new Date().toISOString() : undefined });
      setPos((p) => p + 1);
    }, (pos === 0 ? 300 : replayDelay(ev, matchup === "open" || bundle.kind === "replay")) / speed);
    return () => clearTimeout(t);
  }, [playing, pos, events, speed, matchup, bundle.kind]);

  useEffect(() => {
    if (state.act !== ACTS.VERDICT || state.reveal.done || !playing) return undefined;
    const t = setTimeout(() => dispatch({ type: "reveal_next" }), REVEAL_MS / speed);
    return () => clearTimeout(t);
  }, [state.act, state.reveal, playing, speed]);

  const restart = () => { setPos(0); setPlaying(true); dispatch({ type: "match_started", match_id: bundle.match_id }); };
  return (
    <>
      <Stage state={state} mode="replay" conn={conn} now={now} title={titleOf(state, runLabel(name))}
        summaryRows={summaryRows} onCompare={onCompare} />
      <div className="flex items-center gap-3 text-lg text-slate-300">
        <button className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700" onClick={() => setPlaying((p) => !p)}>
          {playing ? "❚❚ pause" : "▶ play"}
        </button>
        <button className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700" onClick={restart}>↺ restart</button>
        <label className="flex items-center gap-2">
          speed
          <select className="rounded bg-slate-800 px-2 py-1" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
            {[0.5, 1, 2, 4, 8].map((x) => <option key={x} value={x}>{x}×</option>)}
          </select>
        </label>
      </div>
    </>
  );
}

// Final results per matchup for the summary card: the latest finished live run of each,
// else its golden run (computed from the bundle, marked recorded).
export function summaryRowsFor(runs, bundles) {
  const rows = {};
  for (const m of MATCHUP_ORDER) {
    const live = [...runs].reverse().find((r) => r.state.matchup === m && r.state.results.ready);
    if (live) { rows[m] = { ...summaryRow(live.state), recorded: false }; continue; }
    const b = bundles[`golden-${m}`];
    if (b) {
      const st = playAll(bundleToEvents(b, { matchup: m, source: sourceBundleFor(b, bundles) }), "replay");
      const r = summaryRow(st);
      if (r) rows[m] = { ...r, recorded: true };
    }
  }
  return rows;
}

// Battle: the matchup switcher (item 2) over live runs and recorded golden runs.
export default function Battle({ live, bundles, initial, onCompare }) {
  const [allRuns, dispatchRuns] = useReducer(reduceRuns, []);
  const [session, dispatchSession] = useReducer(reduceSession, null);
  const dispatchLive = (ev) => { dispatchRuns(ev); dispatchSession(ev); };
  // Only the current demo session's runs reach the stage (scripts/demo.sh --new-session).
  const runs = sessionRuns(allRuns, session);
  const [conn, setConn] = useState("connecting");
  const [sel, setSel] = useState(initial || (live ? { kind: "follow" } : { kind: "none" }));
  const now = useNow();
  const lastId = runs.length ? runs[runs.length - 1].id : null;
  const seen = useRef(lastId);

  useEffect(() => (live ? connectLive((ev) => { dispatchRuns(ev); dispatchSession(ev); }, setConn) : undefined), [live]);
  // A new live run (the presenter started the next matchup) is shown at once.
  useEffect(() => {
    if (lastId && lastId !== seen.current) setSel({ kind: "follow" });
    seen.current = lastId;
  }, [lastId]);

  const shownRun = sel.kind === "follow" ? runs[runs.length - 1] : sel.kind === "live" ? runs.find((r) => r.id === sel.id) : null;
  // Act 3 reveal of the live run on screen (pacing only, D50).
  useEffect(() => {
    const st = shownRun?.state;
    if (!st || st.act !== ACTS.VERDICT || st.reveal.done) return undefined;
    const t = setTimeout(() => dispatchLive({ type: "reveal_next", run: shownRun.id }), REVEAL_MS);
    return () => clearTimeout(t);
  }, [shownRun]);

  const summaryRows = useMemo(() => summaryRowsFor(runs, bundles), [runs, bundles]);
  const choose = (m) => {
    const r = latestRunOf(runs, m);
    if (r) setSel({ kind: "live", id: r.id });
    else if (bundles[`golden-${m}`]) setSel({ kind: "bundle", name: `golden-${m}` });
  };
  const current = sel.kind === "bundle" ? matchupOfBundle(sel.name) : shownRun?.state.matchup;
  const others = Object.keys(bundles).filter((n) => !matchupOfBundle(n)).sort();
  const unnamedRuns = runs.filter((r) => !r.state.matchup);

  return (
    <div className="flex min-h-[calc(100vh-3.5rem)] flex-col gap-4 p-5">
      <nav className="flex flex-wrap items-center gap-2">
        {MATCHUP_ORDER.map((m) => {
          const available = !!latestRunOf(runs, m) || !!bundles[`golden-${m}`];
          return (
            <button key={m} disabled={!available} onClick={() => choose(m)}
              className={`rounded-xl px-4 py-2 text-xl font-black ${current === m && sel.kind !== "summary"
                ? "bg-white text-slate-950" : available ? "bg-slate-800 text-slate-100 hover:bg-slate-700" : "bg-slate-900 text-slate-600"}`}>
              {MATCHUPS[m].title.split(" (")[0]}
            </button>
          );
        })}
        <button onClick={() => setSel({ kind: "summary" })}
          className={`rounded-xl px-4 py-2 text-xl font-black ${sel.kind === "summary" ? "bg-white text-slate-950" : "bg-slate-800 text-slate-100 hover:bg-slate-700"}`}>
          All three
        </button>
        {(others.length > 0 || unnamedRuns.length > 0) && (
          <select className="ml-auto rounded border border-slate-700 bg-slate-900 px-2 py-1 text-base text-slate-300"
            value={sel.kind === "bundle" && !matchupOfBundle(sel.name) ? `b:${sel.name}` : sel.kind === "live" && !shownRun?.state.matchup ? `l:${sel.id}` : ""}
            onChange={(e) => {
              const v = e.target.value;
              if (v.startsWith("b:")) setSel({ kind: "bundle", name: v.slice(2) });
              else if (v.startsWith("l:")) setSel({ kind: "live", id: v.slice(2) });
            }}>
            <option value="">other runs…</option>
            {unnamedRuns.map((r, i) => <option key={r.id} value={`l:${r.id}`}>live run {i + 1}</option>)}
            {others.map((n) => <option key={n} value={`b:${n}`}>{runLabel(n)}</option>)}
          </select>
        )}
      </nav>
      {sel.kind === "summary" ? <SummaryAll rows={summaryRows} onCompare={onCompare} />
        : sel.kind === "bundle" && bundles[sel.name] ? (
          <BundlePlayer key={sel.name} name={sel.name} bundle={bundles[sel.name]}
            source={sourceBundleFor(bundles[sel.name], bundles)} conn={conn} summaryRows={summaryRows} onCompare={onCompare} />
        ) : shownRun ? (
          <Stage state={shownRun.state} mode="live" conn={conn} now={now} title={titleOf(shownRun.state, "Live run")}
            summaryRows={summaryRows} onCompare={onCompare} />
        ) : (
          <div className="flex flex-1 items-center justify-center text-center text-3xl text-slate-400">
            {live ? "Waiting for the next matchup… (the presenter starts it from the terminal)"
              : "Nothing to show yet: pick a matchup above."}
          </div>
        )}
    </div>
  );
}
