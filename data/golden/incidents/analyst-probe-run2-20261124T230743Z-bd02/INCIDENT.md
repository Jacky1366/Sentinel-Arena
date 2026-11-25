# Probe invalid as a model comparison (kept, never deleted)

- 2026-11-24 23:07 UTC, GO `manual-analyst-probe`, commit `4f95b68`; total $0.309720 (ledger).
- All four candidates failed the schema step because `analyst/draft.strict_schema()` dropped
  the findings' `title` PROPERTY (it treated the property name as the annotation keyword
  `title`): no candidate was asked for a title. A build bug, not a model result.
- Fixed in the next commit (property names are never dropped; a test compares every property
  name of the strict schema with the full schema; prompt v1 now states that every finding has a
  title and cites at least one figure).
- Zero-cost diagnostic of these drafts (title injected): gpt-6.1-sol 0 prose grounding errors;
  terra 1 (bare "M5"); gpt-5.6-sol 2 ("M5"); claude-sonnet-5-5 19.
