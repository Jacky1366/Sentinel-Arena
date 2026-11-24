// Compare model (Stage 7 #15, D52). PURE selectors over a Compare bundle
// (tools/export_compare.py, contract 6.18). Copy only: no judging, no recomputation of a
// fact; counts shown are the bundle's own aggregates.

export const pct = (k, n) => (n ? Math.round((1000 * k) / n) / 10 : null);

export function armCards(bundle) {
  return bundle.arms.map((a) => {
    const g = bundle.aggregate[a.id];
    return {
      id: a.id, label: a.label, blue: a.blue,
      role: a.blue === "original" ? "default defender" : "analysis only",
      detected: g.detected, attempts: g.attempts, detPct: pct(g.detected, g.attempts),
      landedDetected: g.landed_detected, landedAttempts: g.landed_attempts,
      fpCheck: bundle.fp_check ? bundle.fp_check[a.id] ?? null : null,
    };
  });
}

export function matchRows(bundle, match) {
  return bundle.rows.filter((r) => r.match === match).sort((a, b) => a.round - b.round);
}

// Open the table on the first match with a divergent row (else match 1).
export function defaultMatch(bundle) {
  const d = bundle.rows.find((r) => r.divergent);
  return d ? d.match : bundle.matches[0]?.match ?? 1;
}

export function cell(v, attempt = "yes") {
  if (!v) return { mark: "—", tone: "none", text: "no verdict line" };
  // Not an attack attempt (audit): excluded from detection, so never drawn as a hit or miss.
  if (attempt === "no") return { mark: "·", tone: "none", text: v.verdict ?? "—" };
  if (v.detected === true) return { mark: "✓", tone: "hit", text: v.verdict };
  if (v.detected === false) return { mark: "✗", tone: "miss", text: v.verdict ?? v.reason ?? "missed" };
  return { mark: "?", tone: "none", text: v.reason ?? "not scored" };
}

export function divergentCount(bundle) {
  return bundle.rows.filter((r) => r.divergent).length;
}
