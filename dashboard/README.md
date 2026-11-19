# Dashboard (Stage 6.4, M8): offline match playback

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
