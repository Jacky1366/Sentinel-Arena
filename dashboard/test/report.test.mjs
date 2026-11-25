// Report tab (Stage 7 #17).
import { test } from "node:test";
import assert from "node:assert/strict";
import { reportView, SANDBOX, VIEWS } from "../src/report/reportModel.js";

const R = { html: "<p>full</p>", brief: "<p>brief</p>", meta: { report_id: "r", model: "m", provider: "p", date: "d", attempts: 1 } };

test("the report iframe sandbox allows nothing", () => {
  assert.equal(SANDBOX, "");
});

test("opens on the brief; the full report is one button away; print follows the view", () => {
  const b = reportView(R);
  assert.equal(b.view, "brief"); assert.equal(b.html, "<p>brief</p>"); assert.equal(b.printFile, VIEWS.brief.file);
  const f = reportView(R, "full");
  assert.equal(f.html, "<p>full</p>"); assert.equal(f.printFile, VIEWS.full.file);
});

test("no report -> not available; no brief -> the full report", () => {
  assert.equal(reportView(null).available, false);
  assert.equal(reportView({ html: 1, meta: {} }).available, false);
  assert.equal(reportView({ ...R, brief: "" }).view, "full");
});
