# Scripted baseline run

This folder is a copy of one complete match, `20261108T054250Z-ffa1`. It was made by
`.venv/bin/python run_match.py`, called from `tools/stage4_check.py`, which passed.
The match ran from a clean tree at commit `828e4e9`, so `match.json` has
`git.dirty: false`. It shows what a frozen match directory looks like and gives
a reference for the scripted pipeline. No AI was used: Red and Blue are both scripted.

Every file except this README is listed in `match.json` → `artifacts` with its
sha256 and size. To check that nothing has changed:

```bash
.venv/bin/python -c "import json,sys; sys.path.insert(0,'.'); import run_match; \
from pathlib import Path; d=Path('data/golden/scripted-baseline-match'); \
a=run_match.artifact_hashes(d); a.pop('README.md'); \
print(a == json.loads((d/'match.json').read_text())['artifacts'])"
```

## Files (in the order the match produces them)

| File | Producer | What it is | Contract |
|---|---|---|---|
| `red_attacks.jsonl` | Scripted Red | Ground truth: one labeled record per attack (7), written **before** the attack is sent. Blue never reads it. | §2 |
| `challenge_snapshots.jsonl` | Measurement runner | Solved Juice Shop challenges just before and just after each attack, read through the admin port, which nginx does not log. | §3.1 |
| `proxy.jsonl` | nginx | Blue's **only** input: one line per arena request. It was frozen (moved here, then nginx reopened its log) **before** Blue and the Judge ran. | §3 |
| `landed.jsonl` | Judge fact 1 | Did each attack land: `landed` plus `landed_reason` and the `newly_solved` evidence. An intermediate file. | §6.1 |
| `verdicts.jsonl` | Blue v0 (`scripted`) | One verdict per logged request, using generic signatures. | §4 |
| `rounds.jsonl` | Judge round record | The scored result. It joins Red, fact 1 and fact 2 by `request_id`. Downstream readers use only this file. | §6 |
| `match.json` | Orchestrator | Manifest, written last. It records status, Judge version, Blue engine, a hash of the payload file, the git commit and dirty flag, the Docker images that were actually running, and artifact hashes. | §6.2 |

## Result

| Rate | Value | Excluded from the denominator |
|---|---|---|
| landing | 3/4 (75%) | round 5 already_solved; rounds 6–7 not_measurable (XSS, §11) |
| detection | 7/7 (100%) | none |
| type accuracy | 7/7 (100%) | none |

Round 1 is the negative control: a real SQLi attempt that fails (`landed: false`)
but is still detected. **Read these numbers as a check that the pipeline works, not
as a measure of Blue's skill.** The same author wrote Blue's signatures and Red's
payloads. Also, there is no benign traffic yet, so detection is only an upper bound
until false-positive scoring arrives in Stage 5.
