import React, { useState } from "react";
import { reportView, SANDBOX, VIEWS } from "./reportModel.js";

// Report view (Stage 7 #17; D53-D57). Opens on the decision brief; "Full report" switches to
// the whole report. Both are code-rendered and shown in a fully sandboxed iframe (scripts
// cannot run even if something slipped past Jinja2's autoescape and the report's own CSP).
// "Print / save PDF" opens the view's own HTML file, which prints with its print CSS.
// The decision record stays blank here: the decision-maker fills it in (D54 as amended).

export default function Report() {
  const [view, setView] = useState("brief");
  const v = reportView(typeof window !== "undefined" ? window.ARENA_REPORT : null, view);
  if (!v.available) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
        <div className="text-4xl font-black text-white">Report</div>
        <div className="max-w-2xl text-2xl text-slate-400">
          No report yet. It is written by tools/build_report.py --run after the designer's GO, and published only after the designer has read it.
        </div>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-3 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          {Object.entries(VIEWS).map(([k, x]) => (
            (k === "brief" && !v.hasBrief) ? null : (
              <button key={k} onClick={() => setView(k)}
                className={`rounded-lg px-4 py-2 text-lg font-bold ${v.view === k ? "bg-white text-slate-950" : "bg-slate-800 text-slate-200 hover:bg-slate-700"}`}>
                {x.label}
              </button>
            )
          ))}
          <span className="ml-3 text-base text-slate-400">{v.line}</span>
        </div>
        <a href={v.printFile} target="_blank" rel="noopener"
          className="rounded-lg bg-white px-4 py-2 text-lg font-bold text-slate-950 hover:bg-slate-200">
          Print / save PDF ↗
        </a>
      </div>
      <iframe title={VIEWS[v.view].label} sandbox={SANDBOX} srcDoc={v.html}
        className="h-[calc(100vh-9rem)] w-full rounded-xl border border-slate-700 bg-white" />
    </div>
  );
}
