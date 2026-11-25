# analyst-report-7 — Stage 7 #17 evaluation report (frozen)

The AI-drafted, code-grounded evaluation report (D53–D57, D60 with its amendments) and its
decision brief. **Approved by the designer on 2026-11-25** after reading the brief ("no factual
errors"). Final run under the designer's stopping rule: no further wording re-runs.

| | |
|---|---|
| Run | `report-20261125T025425Z-832d`, GO `manual-analyst-report`, 2026-11-25 02:54 UTC |
| Code | commit `9bb9049` (tree clean) |
| Analyst | `gpt-6.1-sol` (OpenAI), prompt **v3** (sha256 `2a90df06d6397b826a06c973c494154d1cd258d7af8c486f39ced566b502952e`), 1 draft, grounding check passed |
| Cost | **$0.071268** (1 call: 18,919 input / 3,343 output tokens) |
| Re-render | once, template-only (no AI call): one "written by AI" line in the brief instead of a badge per heading (designer); recorded in `meta.json` `rerenders` |

**Files**
- `summary.json`: code-built figures from frozen evidence (schema 0.3), each with basis, n, confidence and sources (Appendix A)
- `draft.json` (= `draft-gpt-6.1-sol.json`): the analyst's prose with placeholders only
- `grounding_result.json`: the code check that accepted the draft, with each finding's confidence
- `meta.json`: model, prompt version + sha256, template sha256, attempts, cost, GO, re-render record
- `api_calls.jsonl`: the analyst's ledger line
- `brief.html` / `brief.pdf` (2 pages): the decision brief, shown first in the dashboard's Report tab
- `report.html` / `report.pdf` (19 pages): the full report, rendered once; the dashboard links to the same PDFs

**History (all #17 analyst spending).**
- Probe run 1: one unrecorded call, in `data/golden/incidents/analyst-probe-run1-*`; cost pending from the provider.
- Probe run 2: $0.309720, in `data/golden/incidents/analyst-probe-run2-*`; invalid as a model comparison because of a build bug.
- Report run 1: $0.067546, prompt v1. Read by the designer, then the review changes (prompt v2, D54 / D60 amendments).
- Report run 2: $0.188606, prompt v2. One dropped call because the laptop slept; 2 drafts. The designer asked for three wording fixes (prompt v3).
- Report run 3: this folder.
- Report runs 1 and 2 stay in `data/runs/analyst/` (git-ignored): superseded drafts, not evidence.
- Recorded total: $0.637140.

**Integrity:** `tests/test_analyst_report_7_evidence.py` re-checks the grounding, re-renders
both HTML files byte for byte from the committed inputs, checks the PDFs and the dashboard copies,
and the key figures. Never rewritten; a new report is a new folder.
