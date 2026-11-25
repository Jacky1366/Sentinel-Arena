# Failed probe run (kept, never deleted)

- 2026-11-24 23:05 UTC, GO `manual-analyst-probe`, commit `e4eb35f`.
- The first candidate call (`gpt-6.1-sol`) SUCCEEDED and was billed, then the ledger write
  failed: `tools/build_report.py` passed the folder name (`probe-...`) as `match_id`, which
  `api_call.schema.json` rejects. The run crashed before the next candidate.
- Consequences: the call's tokens / cost are NOT in any ledger (upper bound: 16384 output
  tokens x $10/M + input, about $0.17); the reply text was lost; the $1 analyst cap could not
  count this call.
- Fix: a match-id-shaped id (`run_match.new_match_id()`) for analyst runs, and a test that
  runs the probe through the real LLMClient (fake adapter) so the ledger schema is exercised.
