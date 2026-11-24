// Report tab model (Stage 7 #17). PURE. The report HTML is rendered by code from a grounded
// analyst draft (tools/build_report.py); the dashboard only shows it, sandboxed.

export const SANDBOX = ""; // no allow-scripts, no allow-same-origin: nothing in it can run

export function reportView(r) {
  if (!r || typeof r.html !== "string" || !r.meta) return { available: false };
  const m = r.meta;
  return {
    available: true,
    html: r.html,
    line: `${m.report_id} · analyst ${m.model} (${m.provider}) · ${m.date} · ${m.attempts} attempt(s)`,
  };
}
