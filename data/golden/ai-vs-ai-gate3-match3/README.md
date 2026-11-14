# First AI-vs-AI matches, match 3 of 3 (Stage 5.7, Gate 3)

This folder is a copy of one complete match, `20261114T072621Z-a41b`: match 3 of 3 of Stage 5.7 Gate 3
(`tools/stage5_7_check.py --gate 3 --real-calls`), run with `--red ai --blue claude
--blue-rules-mode on --blue-caching on --red-caching on --seed 5202` on a fresh stack from
a clean tree at commit `be63592` (`match.json` has `git.dirty: false`). The other two
matches of the batch are `../ai-vs-ai-gate3-match1/`, `../ai-vs-ai-gate3-match2/`.

These are the **first AI-vs-AI matches**: AI Red (OpenAI `gpt-6-luna`) attacks, AI Blue
(Anthropic `claude-haiku-5-5`) reads the proxy log and invents rules (mode on, hot-loaded),
and both agents use prompt caching (D18). They are gate evidence for the Stage 5 done-when
(four facts PASS, contract §6.11). They are not the reserved "golden run" (the recorded
demo match).

## Label audit (D16)

The designer's audit is `../audits/20261114T072621Z-a41b.jsonl` (one line per Red round; the single
source of truth). The read-only view is `docs/audits/stage5_7_gate3_label_audit.md`
(regenerate with `tools/audit_match.py sheet`). Audited numbers are derived, never
stored: `.venv/bin/python tools/audit_match.py apply data/golden/ai-vs-ai-gate3-match3`.
The CWE-22 criterion is the one refined in Stage 5.6, unchanged.

## Configuration (`match.json` → `red_params`, `blue_params`)

| Setting | Value |
|---|---|
| Red | OpenAI `gpt-6-luna`, Responses API; `RED_PROMPT_VERSION "1"` (system prompt sha256 `dbb15c865572…`); round cap 10; D15 guard; caching on (explicit breakpoints, 30-minute TTL) |
| Blue | Anthropic `claude-haiku-5-5`; prompt v2 (sha256 `cf440507f446…`); `chunk_size` 1, `max_output_tokens` 512; rules on, `max_rules` 10, starting from zero rules (D7); caching on (system block, 5-minute TTL) |
| Judge | `JUDGE_VERSION` 0.6.0 |
| Traffic | seed 5202 (fixes the benign schedule only, C6); 17 benign slots |
| Price table | `config/prices.json` as of 2026-11-12 |

Every file except this README is listed in `match.json` → `artifacts` with its sha256 and
size. `tests/test_gate_5_7_gate3_evidence.py` checks those hashes, the configuration, that
the Judge re-scores the folder offline to byte-identical outputs, four facts PASS, the
audited numbers and the per-agent cost. Re-running makes real, paid calls; model output is
not expected to repeat. The files here are never rewritten.

## Result

| | Value |
|---|---|
| slots | 10 sent, unsent: none |
| attack mix | 8 × CWE-89 (7 on `/rest/products/search`, 1 on `/search`), 1 × CWE-79, 1 × CWE-22 (`/ftp/../package.json`) |
| landed | 0 |
| detection (AI Blue) | raw 10/10, audited 10/10 (no invalid label) |
| FP rate | 0/17 (hard negatives 0/6) |
| rules | 7 proposed, 7 stored, 0 rejected |
| four facts | PASS |
| Red | 10 calls, $0.001247; cache read / write 10,859 / 2,821 tokens; net cache savings +$0.000907 |
| Blue | 24 calls, $0.001615; cache read / write 43,104 / 0 tokens; net cache savings +$0.003879 |
| total cost | $0.002862; no `max_tokens` stops, no refusals, no unpriced usage |

Round 2 solved Error Handling (audit first; valid). Round 2's rationale names the application ("Juice Shop's product-search API").

`anomalies.jsonl` holds one `benign_solved_challenge` line: benign `h06` expects Error
Handling, which Red had already solved earlier in the match (as in the Stage 5.6 batch).
