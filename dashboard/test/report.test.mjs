// Report tab (Stage 7 #17).
import { test } from "node:test";
import assert from "node:assert/strict";
import { reportView, SANDBOX } from "../src/report/reportModel.js";

test("the report iframe sandbox allows nothing", () => {
  assert.equal(SANDBOX, "");
});

test("no report -> not available; a report -> its line", () => {
  assert.equal(reportView(null).available, false);
  assert.equal(reportView({ html: 1, meta: {} }).available, false);
  const v = reportView({ html: "<p>x</p>", meta: { report_id: "r", model: "m", provider: "p", date: "d", attempts: 1 } });
  assert.ok(v.available && v.line.includes("analyst m (p)"));
});
