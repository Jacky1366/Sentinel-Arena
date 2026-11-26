import React, { useState } from "react";
import Battle from "./battle/Battle.jsx";
import { liveAvailable } from "./battle/live.js";
import { MATCHUP_ORDER } from "./battle/model.js";
import Compare from "./compare/Compare.jsx";
import Inspect from "./Inspect.jsx";
import Report from "./report/Report.jsx";

// Sentinel Arena dashboard (Stage 7, D49; #29 clarity pass): one index.html, two modes.
//   LIVE   — opened from the live server on 127.0.0.1 (python -m liveserver): events over SSE.
//   REPLAY — opened from file://: exported bundles, announced as recorded.
// Main views: Battle (the three matchups, D61), Compare, Report. Inspect is an audit tool,
// reached from the small "Audit" link.

const bundles = () => (typeof window !== "undefined" && window.ARENA_BUNDLES) || {};

const fromHash = () => {
  const h = new URLSearchParams((typeof window !== "undefined" && window.location.hash.slice(1)) || "");
  return { tab: h.get("tab"), src: h.get("src") };
};

const TABS = ["battle", "compare", "report"];

function initialSelection(src, live, all) {
  if (src === "live" && live) return { kind: "follow" };
  const name = src && src.replace(/^bundle:/, "");
  if (name && all[name]) return { kind: "bundle", name };
  if (live) return { kind: "follow" };
  const golden = MATCHUP_ORDER.map((m) => `golden-${m}`).find((n) => all[n]);
  if (golden) return { kind: "bundle", name: golden };
  const names = Object.keys(all).sort();
  return names.length ? { kind: "bundle", name: names[0] } : { kind: "none" };
}

export default function App() {
  const all = bundles();
  const live = liveAvailable();
  const h = fromHash();
  const [tab, setTab] = useState([...TABS, "audit", "inspect"].includes(h.tab) ? (h.tab === "inspect" ? "audit" : h.tab) : "battle");
  const [initial] = useState(() => initialSelection(h.src, live, all));

  return (
    <div className="min-h-screen text-slate-100">
      <nav className="flex h-14 items-center justify-between border-b border-slate-800 bg-slate-950 px-5">
        <div className="flex items-center gap-1">
          <span className="mr-4 text-lg font-black tracking-widest text-slate-300">SENTINEL ARENA</span>
          {TABS.map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`rounded-lg px-4 py-1.5 text-lg font-bold capitalize ${tab === t ? "bg-slate-200 text-slate-950" : "text-slate-400 hover:bg-slate-800"}`}>
              {t}
            </button>
          ))}
        </div>
        <button onClick={() => setTab(tab === "audit" ? "battle" : "audit")}
          className={`text-sm underline-offset-4 hover:underline ${tab === "audit" ? "text-slate-200" : "text-slate-500"}`}>
          {tab === "audit" ? "← back" : "Audit"}
        </button>
      </nav>
      {tab === "battle" && <Battle live={live} bundles={all} initial={initial} onCompare={() => setTab("compare")} />}
      {tab === "compare" && <Compare />}
      {tab === "report" && <Report />}
      {tab === "audit" && <Inspect />}
    </div>
  );
}
