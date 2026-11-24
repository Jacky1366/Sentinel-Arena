import React, { useState } from "react";
import Battle from "./battle/Battle.jsx";
import { liveAvailable } from "./battle/live.js";
import Compare from "./compare/Compare.jsx";
import Inspect from "./Inspect.jsx";

// Sentinel Arena dashboard (Stage 7, D49): one index.html, two modes, three views.
//   LIVE   — opened from the live server on 127.0.0.1 (python -m liveserver): events over SSE.
//   REPLAY — opened from file:// (or picked here): an exported bundle, announced as recorded.
// Views: Battle (#13), Compare (#15), Report (#17); Inspect is the Stage 6.4 step-through.

const bundles = () => (typeof window !== "undefined" && window.ARENA_BUNDLES) || {};

const fromHash = () => {
  const h = new URLSearchParams((typeof window !== "undefined" && window.location.hash.slice(1)) || "");
  return { tab: h.get("tab"), src: h.get("src") };
};

const TABS = ["battle", "compare", "report", "inspect"];

function Placeholder({ title, issue, text }) {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
      <div className="text-4xl font-black text-white">{title}</div>
      <div className="max-w-2xl text-2xl text-slate-400">{text}</div>
      <div className="text-lg text-slate-500">(issue {issue})</div>
    </div>
  );
}

export default function App() {
  const names = Object.keys(bundles()).sort();
  const live = liveAvailable();
  const h = fromHash();
  const [tab, setTab] = useState(TABS.includes(h.tab) ? h.tab : "battle");
  const defaultSrc = h.src && (h.src === "live" ? live : names.includes(h.src.replace(/^bundle:/, "")))
    ? h.src : live ? "live" : names.length ? `bundle:${names[0]}` : "none";
  const [src, setSrc] = useState(defaultSrc);
  const source = src === "live" ? { kind: "live" }
    : src.startsWith("bundle:") ? { kind: "replay", bundle: bundles()[src.slice(7)] } : null;

  return (
    <div className="min-h-screen text-slate-100">
      <nav className="flex h-14 items-center justify-between border-b border-slate-800 bg-slate-950 px-5">
        <div className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`rounded-lg px-4 py-1.5 text-lg font-bold capitalize ${tab === t ? "bg-slate-200 text-slate-950" : "text-slate-400 hover:bg-slate-800"}`}
            >
              {t}
            </button>
          ))}
        </div>
        {tab === "battle" && (
          <label className="flex items-center gap-2 text-base text-slate-400">
            source
            <select className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100" value={src}
              onChange={(e) => setSrc(e.target.value)}>
              {live && <option value="live">live match (this server)</option>}
              {names.map((n) => (
                <option key={n} value={`bundle:${n}`}>recorded: {n}</option>
              ))}
            </select>
          </label>
        )}
      </nav>
      {tab === "battle" && (source
        ? <Battle key={src} source={source} onCompare={() => setTab("compare")} />
        : <Placeholder title="Nothing to show" issue="#13" text="Open this page from the live server, or export a bundle." />)}
      {tab === "compare" && <Compare />}
      {tab === "report" && (
        <Placeholder title="Report" issue="#17"
          text="The code-grounded evaluation report and the human decision record (D53–D57). Not built yet." />
      )}
      {tab === "inspect" && <Inspect />}
    </div>
  );
}
