# Dashboard (Stage 6.4, M8; Stage 7 #13): Battle, Compare, Report, Inspect

**Stage 7 (D49): one `index.html`, two modes, tabs Battle / Compare / Report / Inspect.**
- **LIVE:** open it from the live server (`python -m liveserver`, see `liveserver/README.md`):
  `http://127.0.0.1:8765/`. The Battle tab streams the running match over SSE in three acts
  (D47): 1 Attack (Red's turns, the Target's answers, solved challenges), 2 Blue analysis
  (Blue's ledger lines; Blue is a radar that reads the frozen log, never a shield, D50),
  3 Verdict (the Judge's facts, revealed slot by slot; pacing only).
- **REPLAY:** open `dist/index.html` from `file://` (no network at all) and pick a recorded
  bundle; the header says RECORDED · REPLAY (D45). Deep link: `#tab=battle&src=bundle:<name>`.
- **Honesty (D50):** every animation comes from a real event; failures (timeout, budget hit,
  invalid reply, guard block, send failure) are ordinary events; Act 3 starts only when
  `match.json` exists.
- The Battle logic is a pure module (`src/battle/model.js`), tested with `node --test`
  (`dashboard/test/`, run by `tests/test_dashboard_battle.py`) on a fake live match and on
  every committed bundle.
- Compare (#15) and Report (#17) are placeholders for now. **Inspect** is the Stage 6.4
  step-through below.

## Inspect: offline match playback (Stage 6.4)

Plays back ONE frozen match or replay, line by line, in three columns:
- **Red:** what was sent and why;
- **Judge:** the pure-code facts;
- **Blue:** the verdict, its source and `rule_origin`, and the fired rules.

A cost strip shows calls, tokens and USD so far. Read-only: every value comes from a
bundle exported from the artifacts (contract §6.14). The dashboard computes and judges
nothing, and makes **no network request**. There is no world map (S6-5: all traffic is
localhost).

## Run it offline (no server, no network)

Open the committed build in a browser:

```bash
open dashboard/dist/index.html                    # macOS
xdg-open dashboard/dist/index.html                # Linux
```

- **Navigation:** pick a bundle from the menu, then step with ◀ prev / next ▶ (or ← →) and
  ▶ play (space).
- **Deep link:** `dist/index.html#bundle=m5-library-gate3-match1&step=6`.
- **Other bundles:** "open bundle…" loads any other bundle JSON from disk.

## Export another match or replay

```bash
.venv/bin/python tools/export_dashboard.py <frozen match or replay folder> --name <name>
cd dashboard && npm ci && npm run build          # npm ci needs the registry once; the build is offline
```

The export writes `public/data/<name>.json` and rewrites `public/data/bundles.js`; the build
copies them into `dist/`. Committed demo bundles:
- `train-gate1-match1` (`data/golden/train-6.1b-gate1-match1`);
- `m5-library-gate3-match1` (the library arm of Gate 2,
  `data/golden/replays/gate-6.1b-2/ai-vs-ai-gate3-match1-library`).

`tests/test_export_dashboard.py` checks that they regenerate byte for byte and that the build
makes no network calls.

## Development

```bash
cd dashboard && npm ci && npm run dev             # http://localhost:5173 (local only)
```

Dependencies are pinned exactly (`package.json` + `package-lock.json`). The build inlines
JS and CSS into one `dist/index.html` (`vite-plugin-singlefile`; no module preload
polyfill).
