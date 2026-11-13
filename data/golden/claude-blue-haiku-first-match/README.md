# First AI Blue match: Claude Haiku 5.5 (Stage 5.4, Gate 2)

This folder is a copy of one complete match, `20261113T003417Z-35af`: run 1 of 3 of
Stage 5.4 Gate 2 (`tools/stage5_4_check.py --real-calls`, all PASS), with
`--blue claude --seed 5202` on a fresh stack. Red is scripted (the same 7 payloads
as the scripted baselines); Blue is the AI. The match ran from a clean tree at
commit `af755e3`, so `match.json` has `git.dirty: false`. Runs 2 and 3
(`…003616Z-6154`, `…003809Z-9234`) are not committed; they gave the same 24
verdicts.

This is **not** the "golden run" (reserved for the recorded AI-vs-AI demo match).
It is the first reference run of AI Blue: same traffic as
`../scripted-baseline-benign-match/` (same seed, payloads and benign set, so the
same schedule), different Blue.

## Blue configuration (`match.json` → `blue_params`)

| Setting | Value |
|---|---|
| Provider / model | Anthropic `claude-haiku-5-5` (D12: cheapest current model, dev) |
| SDK | `anthropic==2.3.0` (API version `2026-10-21`) |
| Prompt | `PROMPT_VERSION "1"`, system prompt sha256 `938ea67c385a…` (`blue/claude_engine.py`) |
| Calls | one stateless call per proxy line, `chunk_size` 1, `log_seq` order (D14) |
| Request | `max_output_tokens` 256, thinking disabled, effort low, structured output (JSON schema, label enum) |
| Temperature | not settable on this model / API version (`null`, recorded with a note) |
| Price table | `config/prices.json` as of 2026-11-12, Haiku 5.5 designer-verified |

Every file except this README is listed in `match.json` → `artifacts` with its
sha256 and size. To check that nothing has changed:

```bash
.venv/bin/python -c "import json,sys; sys.path.insert(0,'.'); import run_match; \
from pathlib import Path; d=Path('data/golden/claude-blue-haiku-first-match'); \
a=run_match.artifact_hashes(d); a.pop('README.md'); \
print(a == json.loads((d/'match.json').read_text())['artifacts'])"
```

Re-running it makes real, paid calls (`run_match.py --blue claude --seed 5202`, about
$0.003) and needs `ARENA_ANTHROPIC_API_KEY`. Model output is not guaranteed to
repeat; the Judge part re-scores this folder offline (tested).

## Files

As in `../scripted-baseline-benign-match/` (contract §2, §2.1, §3, §3.1, §6, §6.1,
§6.5, §6.6), with these differences:

| File | What changed |
|---|---|
| `verdicts.jsonl` | schema 0.2: one row per line (24), every one `source: "ai"` with the model's one-sentence `rationale` (§4) |
| `rounds.jsonl`, `benign_results.jsonl` | schema 0.2: `verdict_source` (§6, §6.5) |
| `api_calls.jsonl` | 24 lines, one per Blue call: tokens, `stop_reason`, latency, prompt sha256. Never prompt or response text, never a key (§6.3) |
| `match.json` | schema 0.4: `blue_engine: "claude"`, `models.blue`, `blue_params`, cost (§6.2) |

## Result

| Rate | Value | Notes |
|---|---|---|
| landing | 3/4 (75%) | Red side, unchanged: round 5 already_solved; rounds 6–7 not_measurable |
| detection | 7/7 (100%) | FP rate 0/17 next to it |
| type accuracy | 7/7 (100%) | |
| FP rate | 0/17 | hard negatives 0/6 (95% upper bound about 18% for n=17, about 50% for n=6) |
| precision | 7/7 (100%) | traffic mix 7 attack : 17 benign |
| no-verdict | 0/7 attack, 0/17 benign | |
| instrument failure | 0/7 attack, 0/17 benign | no body refusal, no API failure |
| model refusals | 0 attack, 0 benign | |
| stop reasons | `end_turn` × 24 | no `max_tokens` (largest reply 85 of 256 output tokens) |
| tokens | 20,897 input, 1,526 output | 24 attempts, 0 retries, 0 refused |
| cost | $0.002853 | Haiku 5.5, uncached |

**A ceiling effect, not a capability result.** Scripted and AI Blue both score
7/7 and 0/17 on this traffic. The scripted payloads are textbook cases, so this
traffic cannot discriminate between defenders; capability claims need the variant /
held-out attacks (5.6+). The 0 differences across the three Gate 2 runs (3 × 24
verdicts) show stability on clear-cut cases only, not on ambiguous ones.
