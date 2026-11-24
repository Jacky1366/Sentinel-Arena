import React from "react";
import { reportView, SANDBOX } from "./reportModel.js";

// Report view (Stage 7 #17; D53-D57). Shows the code-rendered report in a fully sandboxed
// iframe (scripts cannot run even if something slipped past Jinja2's autoescape and the
// report's own CSP). "Print / save PDF" opens report.html, which prints with its print CSS.
// The decision record stays blank here: the decision is human (D54).

export default function Report() {
  const v = reportView(typeof window !== "undefined" ? window.ARENA_REPORT : null);
  if (!v.available) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
        <div className="text-4xl font-black text-white">Report</div>
        <div className="max-w-2xl text-2xl text-slate-400">
          No report yet. It is written by tools/build_report.py --run after the designer's GO, and committed only after the designer has read it.
        </div>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-3 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-lg text-slate-300">{v.line}</div>
        <a href="./report/report.html" target="_blank" rel="noopener"
          className="rounded-lg bg-white px-4 py-2 text-lg font-bold text-slate-950 hover:bg-slate-200">
          Print / save PDF ↗
        </a>
      </div>
      <iframe title="Evaluation report" sandbox={SANDBOX} srcDoc={v.html}
        className="h-[calc(100vh-9rem)] w-full rounded-xl border border-slate-700 bg-white" />
    </div>
  );
}
