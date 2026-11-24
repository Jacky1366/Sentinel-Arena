import React, { useEffect, useMemo, useReducer, useState } from "react";
import { ACTS, blueProgress, bundleToEvents, initialState, reduce, replayDelay, scoreboard } from "./model.js";
import { connectLive } from "./live.js";

// Battle view (Stage 7 #13). Three acts (D47): 1 attack (live), 2 Blue analysis (ledger),
// 3 verdict (staged reveal of results already on disk). Honesty (D50): every animation is
// triggered by a real event; Blue is a radar that reads the log afterwards, never a shield;
// failures are ordinary events. Projector-first: dark, large type, high contrast.

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

const ACT_NAMES = { 1: "Attack", 2: "Blue analysis", 3: "Verdict" };

function Header({ state, conn, mode, now }) {
  const elapsed = state.startedAt
    ? (state.finishedAt ? Date.parse(state.finishedAt) : now) - Date.parse(state.startedAt) : null;
  return (
    <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3">
      <div className="flex items-baseline gap-3">
        <span className="text-3xl font-black tracking-widest text-white">SENTINEL ARENA</span>
        {state.matchId && <span className="font-mono text-sm text-slate-500">{state.matchId}</span>}
      </div>
      <div className="flex gap-2">
        {[1, 2, 3].map((a) => (
          <span
            key={a}
            className={`rounded-full px-4 py-1 text-lg font-bold ${
              state.act === a ? "bg-white text-slate-950" : state.act > a ? "bg-slate-700 text-slate-200" : "bg-slate-900 text-slate-500"
            }`}
          >
            {a} · {ACT_NAMES[a]}
          </span>
        ))}
      </div>
      <div className="flex items-center gap-5 text-xl">
        {mode === "live" ? (
          <span className={`flex items-center gap-2 font-bold ${conn === "open" ? "text-emerald-400" : "text-amber-400"}`}>
            <span className={`inline-block h-3 w-3 rounded-full ${conn === "open" ? "live-dot bg-emerald-400" : "bg-amber-400"}`} />
            {conn === "open" ? "LIVE" : conn === "reconnecting" ? "RECONNECTING" : "CONNECTING"}
          </span>
        ) : (
          <span className="rounded bg-amber-500 px-3 py-1 font-black text-slate-950">RECORDED · REPLAY</span>
        )}
        <span className="font-mono text-white" title="match time">⏱ {mmss(elapsed)}</span>
        <span className="font-mono text-emerald-300" title="AI cost so far (stats/cost.py pricing)">
          ${state.cost.usd.toFixed(4)}
          {state.cost.lowerBound ? "+" : ""}
          <span className="ml-2 text-base text-slate-400">{state.cost.calls} calls</span>
        </span>
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

function RedPanel({ state, now }) {
  const r = state.red;
  let body;
  if (r.phase === "thinking") {
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
          <span className="rounded bg-slate-700 px-3 py-1 text-xl font-bold text-white">{a.label}</span>
          {a.headerNames.map((h) => (
            <span key={h} className="rounded bg-violet-700 px-2 py-1 text-base text-white">with {h}</span>
          ))}
        </div>
        {a.technique && <div className="text-3xl font-bold leading-tight text-rose-100">{a.technique}</div>}
        <div className="break-all rounded-xl bg-black/70 p-4 font-mono text-xl leading-relaxed text-emerald-300">
          <span className="text-sky-400">{a.method} </span>
          <Typewriter key={a.requestId} text={a.payload || a.endpoint || ""} />
        </div>
        {a.rationale && <p className="text-lg italic text-slate-300">“{a.rationale}”</p>}
      </div>
    );
  } else if (r.phase === "failed" && r.failure) {
    const f = r.failure;
    const what = { guard_block: "Blocked by the rules of engagement", brain_failure: "Unusable reply",
      instrument_failure: "Call failed" }[f.kind] || f.kind;
    body = (
      <div className="flex flex-col gap-2 rounded-xl border-2 border-amber-500 bg-amber-950/60 p-4">
        <div className="text-2xl font-bold text-amber-200">Turn {r.round}: nothing sent</div>
        <div className="text-xl text-amber-100">{what}</div>
        <div className="font-mono text-lg text-amber-300">{f.reason}{f.detail ? ` — ${f.detail}` : ""}</div>
      </div>
    );
  } else if (r.phase === "done") {
    body = <div className="py-6 text-2xl text-slate-300">Red is done.</div>;
  } else {
    body = <div className="py-6 text-2xl text-slate-500">Waiting for Red's turn…</div>;
  }
  return (
    <Panel title="RED · attacker" sub="AI proposes one request per turn" tone="border-rose-600 text-rose-300">
      {body}
    </Panel>
  );
}

function TargetPanel({ state, sb }) {
  const hit = state.target.hit;
  const burst = state.target.burst;
  const benign = state.slots.filter((x) => x.kind === "benign");
  const tone = (st) => (st >= 500 ? "bg-rose-600" : st >= 400 ? "bg-amber-500" : st >= 300 ? "bg-sky-600" : "bg-emerald-600");
  const final = state.act === ACTS.VERDICT;
  return (
    <Panel title="TARGET · Juice Shop" sub="behind a logging proxy (no defenses)" tone="border-slate-500 text-slate-200">
      <div className="relative flex h-40 items-center justify-center rounded-xl bg-black/60">
        {hit ? (
          <div key={hit.seq} className={`hit rounded-xl px-6 py-3 text-4xl font-black text-white ${tone(hit.status)}`}>
            HTTP {hit.status}
          </div>
        ) : (
          <div className="text-2xl text-slate-500">no Red request yet</div>
        )}
        {burst && (
          <div key={`b${burst.seq}`} className="burst absolute inset-x-2 bottom-2 rounded-lg bg-yellow-400 px-3 py-2 text-center text-xl font-black text-slate-950">
            ★ Challenge solved: {burst.names.map((n) => (state.catalog[n] ? `${n} (${state.catalog[n]})` : n)).join(", ")}
          </div>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1">
        <span className="mr-2 text-base text-slate-400">benign traffic</span>
        {benign.map((x, i) => (
          <span key={i} className={`inline-block h-3 w-3 rounded-full ${x.state === "sent" ? "bg-emerald-400" : "border border-slate-600"}`} />
        ))}
      </div>
      <div className="grid grid-cols-4 gap-2 text-center">
        <Stat label="Red turns" value={sb.redTurns} />
        <Stat label="sent" value={sb.sent} />
        <Stat label="not sent" value={sb.unsent} tone="text-amber-300" />
        <Stat label="landed" value={sb.landed} tone="text-yellow-300" />
        {final && (
          <>
            <Stat label="detected" value={sb.tp} tone="text-emerald-300" big />
            <Stat label="missed" value={sb.fn} tone="text-rose-300" big />
            <Stat label="false alarms" value={sb.fp} tone="text-orange-300" big />
            <Stat label="quiet benign" value={sb.quiet} tone="text-slate-300" big />
          </>
        )}
      </div>
    </Panel>
  );
}

function Stat({ label, value, tone = "text-white", big }) {
  return (
    <div className={`rounded-lg bg-slate-950 p-2 ${big ? "flip-in" : ""}`}>
      <div className={`font-black ${big ? "text-4xl" : "text-3xl"} ${tone}`}>{value}</div>
      <div className="text-sm uppercase tracking-wide text-slate-400">{label}</div>
    </div>
  );
}

function BluePanel({ state }) {
  const p = blueProgress(state);
  const sweeping = state.act === ACTS.ANALYSIS;
  const pct = p.total ? Math.round((100 * p.reached) / p.total) : 0;
  return (
    <Panel title="BLUE · defender" sub="reads only the proxy log, after the match" tone="border-sky-600 text-sky-300">
      <div className="flex items-center gap-5">
        <div className={`radar ${sweeping ? "radar-on" : ""}`} />
        <div className="flex flex-col gap-1 text-xl">
          {state.act <= ACTS.ATTACK && (
            <span className="text-slate-400">Not on the traffic path. Waiting for the frozen log.</span>
          )}
          {state.act >= ACTS.ANALYSIS && (
            <>
              <span className="text-white">
                log lines reached <b className="font-mono">{p.reached}</b> / {p.total}
              </span>
              <span className="text-slate-300">
                AI calls <b className="font-mono">{p.calls}</b>
              </span>
              {state.library && (
                <span className="text-base text-amber-300">
                  rule library v{state.library.version} ({state.library.rules} rules, read-only)
                </span>
              )}
            </>
          )}
        </div>
      </div>
      {state.act >= ACTS.ANALYSIS && (
        <div className="h-3 rounded bg-slate-800">
          <div className="h-3 rounded bg-sky-500 transition-all" style={{ width: `${pct}%` }} />
        </div>
      )}
      {state.act === ACTS.VERDICT && <div className="text-xl text-sky-200">{state.reveal.done ? "All verdicts revealed (Judge facts)." : "Verdicts are in. Revealing the Judge's facts…"}</div>}
    </Panel>
  );
}

const OUTCOME = {
  TP: ["bg-emerald-500 text-slate-950", "✓", "detected"],
  FN: ["bg-rose-600 text-white", "✗", "missed"],
  FP: ["bg-orange-500 text-slate-950", "!", "false alarm"],
  quiet: ["bg-emerald-900 text-emerald-200", "", "quiet benign"],
  unsent: ["bg-slate-700 text-slate-300", "–", "not sent"],
  unscored: ["bg-slate-800 text-slate-400", "?", "no Judge record"],
};

function Timeline({ state }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {state.slots.map((x, i) => {
        const red = x.kind === "red";
        const o = x.outcome && OUTCOME[x.outcome];
        let cls;
        if (o) cls = o[0];
        else if (red) cls = x.state === "active" ? "bg-rose-500 thinking" : x.state === "sent" ? "bg-rose-700 text-white"
          : x.state === "unsent" ? "unsent-cell text-amber-200" : "border-2 border-slate-600 text-slate-500";
        else cls = x.state === "sent" ? "bg-emerald-700" : "border border-slate-600";
        const landed = (x.newlySolved || []).length > 0;
        return (
          <div
            key={`${i}-${x.outcome || ""}`}
            title={red ? `Red turn ${x.round}${o ? ` · ${o[2]}` : ""}` : `benign ${x.benignId || ""}${o ? ` · ${o[2]}` : ""}`}
            className={`flex items-center justify-center rounded-md font-black ${o ? "flip" : ""} ${cls} ${
              red ? "h-12 w-12 text-xl" : "h-5 w-5 text-xs"}`}
          >
            {o ? o[1] : red ? x.round : ""}
            {landed && <span className="ml-0.5 text-yellow-300">★</span>}
          </div>
        );
      })}
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

function Summary({ state, sb, onCompare }) {
  if (state.status === "failed") {
    return (
      <div className="rounded-2xl border-2 border-amber-500 bg-amber-950/70 p-5 text-2xl text-amber-100">
        Match failed at step '{state.failure?.step}'. Switch to the recorded run.
      </div>
    );
  }
  if (!(state.act === ACTS.VERDICT && state.reveal.done)) return null;
  const attacks = sb.tp + sb.fn;
  return (
    <div className="flip-in flex flex-wrap items-center justify-between gap-4 rounded-2xl border-2 border-white bg-slate-900 p-5">
      <div className="text-3xl font-black text-white">
        Blue detected {sb.tp} of {attacks} attacks · {sb.fp} false alarm{sb.fp === 1 ? "" : "s"} · {sb.landed} landed
      </div>
      {sb.fn > 0 && (
        <button onClick={onCompare} className="rounded-xl bg-sky-500 px-5 py-3 text-2xl font-black text-slate-950 hover:bg-sky-400">
          Why missed? → Compare
        </button>
      )}
    </div>
  );
}

export default function Battle({ source, onCompare }) {
  const mode = source.kind;
  const [state, dispatch] = useReducer(reduce, mode, initialState);
  const [conn, setConn] = useState("connecting");
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [pos, setPos] = useState(0);
  const now = useNow();
  const events = useMemo(() => (mode === "replay" && source.bundle ? bundleToEvents(source.bundle) : []), [mode, source.bundle]);

  // LIVE: the server's events, as they arrive.
  useEffect(() => {
    if (mode !== "live") return undefined;
    return connectLive((ev) => dispatch(ev), setConn);
  }, [mode]);

  // REPLAY: the bundle's events with pacing; each is stamped with the time it is shown.
  useEffect(() => {
    if (mode !== "replay" || !playing || pos >= events.length) return undefined;
    const ev = events[pos];
    const t = setTimeout(() => {
      dispatch({ ...ev, observed_at: new Date().toISOString(), started_at: ev.type === "match_started" ? new Date().toISOString() : undefined,
        finished_at: ev.type === "match_finished" ? new Date().toISOString() : undefined });
      setPos((p) => p + 1);
    }, (pos === 0 ? 300 : replayDelay(ev)) / speed);
    return () => clearTimeout(t);
  }, [mode, playing, pos, events, speed]);

  // Act 3: the staged reveal (pacing only, D50).
  useEffect(() => {
    if (state.act !== ACTS.VERDICT || state.reveal.done || (mode === "replay" && !playing)) return undefined;
    const t = setTimeout(() => dispatch({ type: "reveal_next" }), REVEAL_MS / speed);
    return () => clearTimeout(t);
  }, [state.act, state.reveal, mode, playing, speed]);

  const sb = scoreboard(state);
  const restart = () => {
    setPos(0);
    setPlaying(true);
    dispatch({ type: "match_started", match_id: source.bundle?.match_id, source: "bundle" });
  };

  return (
    <div className="flex min-h-[calc(100vh-3.5rem)] flex-col gap-4 p-5">
      <Header state={state} conn={conn} mode={mode} now={now} />
      {state.status === "idle" ? (
        <div className="flex flex-1 items-center justify-center text-3xl text-slate-400">
          {mode === "live" ? "Waiting for a match… (start it from the terminal with ARENA_GO)" : "Loading the recorded run…"}
        </div>
      ) : (
        <>
          <main className="grid flex-1 grid-cols-1 gap-4 lg:grid-cols-3">
            <RedPanel state={state} now={now} />
            <TargetPanel state={state} sb={sb} />
            <BluePanel state={state} />
          </main>
          <Summary state={state} sb={sb} onCompare={onCompare} />
          <section className="grid grid-cols-1 gap-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <div className="mb-2 flex flex-wrap gap-4 text-base text-slate-400">
                <span>Timeline</span>
                <span><b className="text-rose-400">■</b> Red turn</span>
                <span><b className="text-emerald-500">●</b> benign</span>
                <span><b className="text-emerald-400">✓</b> detected</span>
                <span><b className="text-rose-400">✗</b> missed</span>
                <span><b className="text-orange-400">!</b> false alarm</span>
                <span><b className="text-slate-400">–</b> not sent</span>
                <span><b className="text-yellow-300">★</b> landed</span>
              </div>
              <Timeline state={state} />
            </div>
            <Feed state={state} />
          </section>
        </>
      )}
      {mode === "replay" && (
        <div className="flex items-center gap-3 text-lg text-slate-300">
          <button className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700" onClick={() => setPlaying((p) => !p)}>
            {playing ? "❚❚ pause" : "▶ play"}
          </button>
          <button className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700" onClick={restart}>
            ↺ restart
          </button>
          <label className="flex items-center gap-2">
            speed
            <select className="rounded bg-slate-800 px-2 py-1" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              {[0.5, 1, 2, 4, 8].map((x) => (
                <option key={x} value={x}>{x}×</option>
              ))}
            </select>
          </label>
          <span className="text-slate-500">event {pos} / {events.length}</span>
        </div>
      )}
    </div>
  );
}
