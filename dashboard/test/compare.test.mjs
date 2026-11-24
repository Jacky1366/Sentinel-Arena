// Compare model tests (Stage 7 #15). Reads the committed Compare bundle (derived, in
// dashboard/public/compare/), never a match folder. Figures must equal the committed stats.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { armCards, cell, defaultMatch, divergentCount, matchRows } from "../src/compare/compareModel.js";

const dir = new URL("../public/compare/", import.meta.url).pathname;
const bundles = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"))) : [];

test("every committed Compare bundle is internally consistent", () => {
  assert.ok(bundles.length >= 1);
  for (const b of bundles) {
    const ids = b.arms.map((a) => a.id);
    for (const r of b.rows) {
      assert.deepEqual(Object.keys(r.verdicts).sort(), [...ids].sort());
      const det = new Set(ids.map((a) => r.verdicts[a]?.detected));
      assert.equal(r.divergent, det.size > 1, `${r.match}/${r.round}`);
    }
    for (const a of armCards(b)) {   // header detection = the per-match audited rates
      const k = b.matches.reduce((s, m) => s + (m.per_arm[a.id].detection?.num || 0), 0);
      const n = b.matches.reduce((s, m) => s + (m.per_arm[a.id].detection?.den || 0), 0);
      assert.equal(a.detected, k);
      assert.equal(a.attempts, n);
      // and = the attempt rows the arm detected
      const rows = b.rows.filter((r) => r.attack_attempt === "yes");
      assert.equal(rows.length, n);
      assert.equal(rows.filter((r) => r.verdicts[a.id]?.detected === true).length, k);
    }
    const m = defaultMatch(b);
    assert.ok(matchRows(b, m).length > 0);
  }
});

test("the free-play bundle equals the committed stats (progress.md, D43 audit)", () => {
  const b = bundles.find((x) => x.name === "freeplay");
  assert.ok(b, "freeplay bundle committed");
  const c = Object.fromEntries(armCards(b).map((a) => [a.id, a]));
  assert.equal(`${c.original.detected}/${c.original.attempts}`, "12/19");
  assert.equal(`${c.open.detected}/${c.open.attempts}`, "14/19");
  assert.equal(c.original.role, "default defender");
  assert.equal(c.open.role, "analysis only");
  // open Blue recovers the two landed other-class attacks the original missed
  assert.equal(c.open.landedDetected - c.original.landedDetected, 2);
  assert.equal(divergentCount(b), 2);
});

test("a non-attempt is never drawn as a hit or a miss", () => {
  assert.equal(cell({ detected: false, verdict: "benign" }, "no").tone, "none");
  assert.equal(cell({ detected: true, verdict: "CWE-89" }, "no").tone, "none");
  assert.equal(cell({ detected: false, verdict: "benign" }, "yes").tone, "miss");
  assert.equal(cell({ detected: true, verdict: "other" }).tone, "hit");
  assert.equal(cell(null).mark, "—");
});
