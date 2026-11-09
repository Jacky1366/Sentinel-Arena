# Scripted baseline run with benign traffic (Stage 5.2)

This folder is a copy of one complete match, `20261109T021518Z-7d72`, run with
`--seed 5202` by `tools/stage5_2_check.py` (pass 1 of 3, all PASS) on a fresh stack.
The match ran from a clean tree at commit `4b9fa15`, so `match.json` has
`git.dirty: false`. No AI was used: Red and Blue are both scripted. The Stage 4
baseline (`../scripted-baseline-match/`, no benign traffic) is kept unchanged.

Every file except this README is listed in `match.json` → `artifacts` with its
sha256 and size. To check that nothing has changed:

```bash
.venv/bin/python -c "import json,sys; sys.path.insert(0,'.'); import run_match; \
from pathlib import Path; d=Path('data/golden/scripted-baseline-benign-match'); \
a=run_match.artifact_hashes(d); a.pop('README.md'); \
print(a == json.loads((d/'match.json').read_text())['artifacts'])"
```

To reproduce the schedule: `.venv/bin/python run_match.py --seed 5202` (same payloads
and benign set). Six matches with this seed (3 passes × 2) gave identical results per
slot.

## Files (in the order the match produces them)

| File | Producer | What it is | Contract |
|---|---|---|---|
| `red_attacks.jsonl` | Scripted Red | Ground truth: one labeled record per attack (7), written **before** the attack is sent. Blue never reads it. | §2 |
| `benign_requests.jsonl` | Benign sender | Ground truth: one record per benign request (17), written **before** it is sent. Blue never reads it. | §2.1 |
| `challenge_snapshots.jsonl` | Measurement runner | Solved challenges just before and after each of the 24 requests, in executed order, each row marked `traffic: red / benign`. | §3.1 |
| `proxy.jsonl` | nginx | Blue's **only** input: 24 lines, Red and benign interleaved and indistinguishable apart from content. Frozen before Blue and the Judge ran. | §3 |
| `landed.jsonl` | Judge fact 1 | Did each attack land (Red rows only). | §6.1 |
| `verdicts.jsonl` | Blue v0 (`scripted`) | One verdict per logged request (24). | §4 |
| `rounds.jsonl` | Judge round record | Red's scored rounds; identical to the Stage 4 baseline. | §6 |
| `benign_results.jsonl` | Judge fact 4a | One false-positive result per benign request. | §6.5 |
| `anomalies.jsonl` | Judge fact 4a | Harness self-checks that tripped: **empty**. h06's "Error Handling" solve is in its `expected_solves`. | §6.6 |
| `match.json` | Orchestrator | Manifest (schema 0.3), written last: status, provenance, the seed and planned schedule, the benign set's sha256, images, cost ($0), artifact hashes. | §6.2 |

## Result

| Rate | Value | Notes |
|---|---|---|
| landing | 3/4 (75%) | round 5 already_solved; rounds 6–7 not_measurable (XSS, §11) |
| detection | 7/7 (100%) | FP rate 0/17 next to it |
| type accuracy | 7/7 (100%) | |
| FP rate | 0/17 | hard negatives 0/6. Not "0%": the 95% upper bound is about 18% for n=17 and about 50% for n=6 (rule of three) |
| precision | 7/7 (100%) | traffic mix 7 attack : 17 benign |
| benign no-verdict | 0/17 (0%) | |

**These numbers check the pipeline; they do not measure Blue's skill.** The same
author wrote Blue's signatures, Red's payloads and the benign set, and the hard
negatives were drafted by someone who had read the signatures. Scripted Blue
happens to flag none of these 17 benign requests; a Blue that labels everything an
attack would score detection 100% but FP 100% here, which is what makes detection
no longer gameable.
