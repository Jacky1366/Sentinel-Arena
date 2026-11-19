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
| open v3-open | **6/57** | holdout: xn05 (other), xn08 (other), xh20 (CWE-89), xh23 (CWE-22), xh28 (CWE-22); fixture: n08 (other) |

Widening the definition costs false positives: open Blue flags 6 ordinary requests as attacks
(2 as `other`, 3 as CWEs on hard-negative look-alikes). This is the price of catching the
`other`-class attacks, and it is on benign traffic the original prompt passes cleanly.

## Remaining free-play misses under open Blue (classification)

All remaining undetected free-play rounds are **reconnaissance / enumeration** probes that did
NOT land: recon, directory listing, API-endpoint enumeration. None are landed exploits, and
**none are structural (needing user identity)** — Red set no Cookie/Authorization in these
runs, so no identity-dependent attack landed-but-evaded. They are recon that a monitor reading
only request content cannot separate from ordinary browsing; the binary audit (D41) would mark
them "not an attack attempt".

`tests/test_gate_6_3_c_open_evidence.py` checks the committed replays (hashes, open prompt
version, the 2a/2b detection deltas, the 2c FP counts).
