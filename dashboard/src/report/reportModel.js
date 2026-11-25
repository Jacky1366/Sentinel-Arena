// Report tab model (Stage 7 #17). PURE. The report HTML is rendered by code from a grounded
// analyst draft (tools/build_report.py); the dashboard only shows it, sandboxed.
// Two views (#17 review): the decision brief (default) and the full report.

export const SANDBOX = ""; // no allow-scripts, no allow-same-origin: nothing in it can run

export const VIEWS = {
  brief: { label: "Decision brief", file: "./report/brief.html" },
  full: { label: "Full report", file: "./report/report.html" },
};

export function reportView(r, view = "brief") {
  if (!r || typeof r.html !== "string" || !r.meta) return { available: false };
  const m = r.meta;
  const hasBrief = typeof r.brief === "string" && r.brief.length > 0;
  const v = view === "full" || !hasBrief ? "full" : "brief";
  return {
    available: true,
    view: v,
    hasBrief,
    html: v === "brief" ? r.brief : r.html,
    printFile: VIEWS[v].file,
    line: `${m.report_id} · analyst ${m.model} (${m.provider}) · ${m.date} · ${m.attempts} attempt(s)`,
  };
}
