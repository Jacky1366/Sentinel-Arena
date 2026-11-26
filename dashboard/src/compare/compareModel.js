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

// ---- #29 clarity pass (display only; every number is the bundle's) ----------------------

// The two defenders in plain words (the same names as the Battle matchups, D61).
export const ARM_NAMES = {
  original: { name: "Limited defender", sub: "original Blue: knows three attack types" },
  open: { name: "Free defender", sub: "open Blue: a wider idea of what an attack is" },
};

// Bundle notes without decision numbers or internal ids (readers do not know them).
export function plain(text) {
  return (text || "")
    .replace(/\s*\([^()]*\bD\d+[^()]*\)/g, "")
    .replace(/\s*\bD\d+\b/g, "")
    .replace(/\s+([.,;])/g, "$1")
    .trim();
}

const dateOf = (matchId) => {
  const m = /^(\d{4})(\d{2})(\d{2})T/.exec(matchId || "");
  if (!m) return null;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(m[3])} ${months[Number(m[2]) - 1]} ${m[1]}`;
};

// Item 13: each match tab describes its match.
export function matchTabs(bundle) {
  return bundle.matches.map((x) => {
    const rows = bundle.rows.filter((r) => r.match === x.match);
    return {
      match: x.match,
      date: dateOf(x.match_id),
      attacks: rows.filter((r) => r.attack_attempt === "yes").length,
      disagree: rows.filter((r) => r.divergent).map((r) => r.round).sort((a, b) => a - b),
    };
  });
}

// Item 13: by default only the rounds where the defenders disagree or the attack succeeded.
export function visibleRows(bundle, match, showAll) {
  const rows = matchRows(bundle, match);
  return showAll ? rows : rows.filter((r) => r.divergent || r.landed);
}

// Item 11: one line under the cards, built from the bundle's own figures.
export function takeaway(bundle) {
  const g = bundle.aggregate;
  const fp = bundle.fp_check;
  if (!g.original || !g.open) return null;
  const caught = `caught ${g.open.detected} of ${g.open.attempts} attacks instead of ${g.original.detected}`;
  const landed = `${g.open.landed_detected} of ${g.open.landed_attempts} successful attacks instead of ${g.original.landed_detected}`;
  const alarms = fp && fp.open && fp.original
    ? `, but raised ${fp.open.fp} false alarms on ${fp.open.n} normal requests instead of ${fp.original.fp}` : "";
  return `The free defender ${caught} and ${landed}${alarms}.`;
}
