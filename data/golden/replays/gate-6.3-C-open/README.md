# Stage 6.3 D42: open Blue (v3-open) replay analysis

`ARENA_GO=gate-6.3-C-open tools/stage6_3_check.py --gate C-open --real-calls`, 2026-11-19,
from a clean tree at commit `724979c`. Haiku Blue only (no DeepSeek). Total $0.014219.

Open Blue = Blue prompt **v3-open** (the v2 prompt with the attack definition WIDENED beyond
the three CWEs; adds the label `other` + a flat `technique`; sha256 recorded in
`blue/claude_engine.py`). Replay-only (D17), rules on, library v5 read-only. The live Blue
prompts (v1/v2) and the core Judge are unchanged; an `other` verdict is an attack verdict.

## (2a) Free-play arm — original (live v2) vs open (v3-open) detection per round

| source | detected orig → open | rounds open newly catches |
|---|---|---|
| freeplay-match1 | 4 → 4 | — (the misses are recon, not attacks) |
| freeplay-match2 | 2 → **4** | r8 broken access control → sensitive data exposure (**landed**); r10 information disclosure → sensitive file (**landed**) |
| freeplay-match3 | 6 → 6 | — |

Open Blue recovered **both landed `other`-class attacks** that original Blue missed. No
detections were lost.

## (2b) Taxonomy arm (deepseek) — does widening hurt?

| source | detected orig → open | type-correct orig → open | open `other` verdicts |
|---|---|---|---|
| deepseek-match1 | 8 → 8 | 8 → 8 | 0 |
| deepseek-match2 | 9 → 9 | 9 → 9 | 0 |
| deepseek-match3 | 9 → 9 | 9 → 9 | 0 |

Widening did **not** hurt taxonomy detection or type accuracy: open Blue gave zero `other`
verdicts on CWE attacks and labelled them exactly as the original prompt did.

## (2c) Prompt false positives — AI-only over the holdout (TEST) + fixture (57 benign lines)

| prompt | FP | detail |
|---|---|---|
| original v2 | **0/57** | — |
| open v3-open | **6/57 = 10.5%**, CP95% [3.96%, 21.5%] | holdout: xn05, xn08, xh24 (other), xh23, xh28 (CWE-22); fixture: n08 (other) |

Widening the definition costs false positives: open Blue flags ~10% of ordinary requests as
attacks (CP 95% CI [3.96%, 21.5%]); original v2 is 0/57 (CP95% upper 6.3%). This is the price
of catching the `other`-class attacks, on benign traffic the original prompt passes cleanly.
Every benign-line verdict is persisted in `fp-on/fp_verdicts.jsonl` and
`fp-open/fp_verdicts.jsonl` (persisted 2026-11-19 under gate-6.3-C-open `--fp-only`). The FP
COUNT is stable at 6/57; the exact hard-negative look-alikes vary run to run (AI
nondeterminism) — a first FP run gave xh20 (CWE-89) where this one gives xh24 (other).

## Remaining free-play misses under open Blue (classification — per the D41 audit)

Correction (audited 2026-11-19): the remaining undetected rounds are NOT recon-to-be-excluded.
The binary audit marks `GET /ftp` (m1 r8, r10; m2 r9) and `GET /api/Challenges` (m2 r2, r4) as
**attack attempts (YES)** — forced browsing / enumeration of resources the frontend never links
or requests (objective frontend check). Both the closed and the open prompt miss them: this is
**application-context blindness** (fix = a site map / allowlist, future work), not prompt-scope.
Only the three `GET /` rounds are ordinary browsing (audited NO, excluded). No **structural**
(identity-dependent) miss appears, because Red set no Cookie/Authorization in these runs.
Audited free-play detection: original Blue 12/19 (63.2%), open Blue 14/19 (73.7%).

`tests/test_gate_6_3_c_open_evidence.py` checks the committed replays (hashes, open prompt
version, the 2a/2b detection deltas, the 2c FP counts).
