// Reader-facing names for recorded runs (Stage 7 #29). PURE. A bundle's file name is an id
// (e.g. "m5-library-gate3-match1"); people see a label instead. Unknown names fall back to
// the name itself.

const COST_ARMS = { library: "with library", empty: "empty library", "rules-off": "rules off" };

export function runLabel(name) {
  let m = /^golden-(taxonomy|freeplay|open)$/.exec(name || "");
  if (m) {
    return { taxonomy: "Matchup 1 · limited attacker vs limited defender · recorded",
      freeplay: "Matchup 2 · free attacker vs limited defender · recorded",
      open: "Matchup 3 · free attacker vs free defender · recorded" }[m[1]];
  }
  m = /^m5-(library|empty|rules-off)-gate3-match(\d+)$/.exec(name || "");
  if (m) return `Cost comparison · ${COST_ARMS[m[1]]} · match ${m[2]}`;
  m = /^train-gate1-match(\d+)$/.exec(name || "");
  if (m) return `Rule learning · training match ${m[1]}`;
  return name;
}
