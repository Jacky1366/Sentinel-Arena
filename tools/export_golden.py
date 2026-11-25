"""Stage 7 #18: turn a finished, clean dev match into the demo's golden run bundle (D45,
D58). Zero tokens, no network, never writes the source folder.

    .venv/bin/python tools/export_golden.py data/runs/<match_id>
    .venv/bin/python tools/export_golden.py data/runs/<match_id> --check   (no write)

Clean = match.json status completed, purpose dev (D45: a sample, not evidence), not test
data by its manifest (D59), the configuration of the live demo (Blue D46, AI Red
deepseek-v4-pro or the Luna backup) and four facts PASS (or N/A: Blue stored no rule). Writes the bundle
`golden-run` with tools/export_dashboard.py (dashboard/public/data/golden-run.json +
bundles.js), then copies dashboard/public/data/ into dashboard/dist/data/ so the built
dashboard plays it from file:// with no rebuild. scripts/demo.sh --replay opens it:

    file://<repo>/dashboard/dist/index.html#src=bundle:golden-run&tab=battle

The match folder stays in data/runs/ (git-ignored); whether to also commit it under
data/golden/ is the designer's call (data/golden/ is important lane)."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from stats import test_data  # noqa: E402
from tools import export_dashboard, four_facts  # noqa: E402

NAME = "golden-run"
PUBLIC = REPO / "dashboard" / "public" / "data"
DIST = REPO / "dashboard" / "dist" / "data"
DEMO_REDS = {"deepseek-v4-pro", "gpt-6-luna"}
DEMO_BLUE = "claude-haiku-5-5"


def problems(d: Path, registry=None) -> list[str]:
    """Why `d` cannot be the golden run ([] = clean). Reads the manifest first (D59)."""
    d = Path(d)
    v = test_data.classify(d, registry or test_data.load_registry())
    if v.kind != test_data.NOT_TEST:
        return [f"not exportable: {v.kind} ({v.reason})"]
    if (d / "replay.json").is_file():
        return ["a replay, not a live match"]
    m = json.loads((d / "match.json").read_text(encoding="utf-8"))
    out = []
    if m.get("status") != "completed":
        out.append(f"status {m.get('status')!r} (failed step {m.get('failed_step')!r})")
    if m.get("purpose") != "dev":
        out.append(f"purpose {m.get('purpose')!r}, not dev (D45)")
    red = (m.get("models") or {}).get("red") or {}
    if m.get("red_engine") != "ai" or red.get("model") not in DEMO_REDS:
        out.append(f"Red {m.get('red_engine')} {red.get('model')!r} is not a demo Red")
    blue = (m.get("models") or {}).get("blue") or {}
    if m.get("blue_engine") != "claude" or blue.get("model") != DEMO_BLUE:
        out.append(f"Blue {m.get('blue_engine')} {blue.get('model')!r} is not the demo Blue")
    if not out:
        r = four_facts.check(d)
        if r["status"] not in (four_facts.PASS, four_facts.NA):  # NA: Blue stored no rule
            out.append(f"four facts {r['status']}: {'; '.join(r['reasons'])}")
    return out


def sync_dist(public: Path = PUBLIC, dist: Path = DIST) -> None:
    """dashboard/dist/data/ = dashboard/public/data/ (what `npm run build` would copy)."""
    dist.mkdir(parents=True, exist_ok=True)
    for p in public.iterdir():
        if p.is_file():
            shutil.copy2(p, dist / p.name)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("match", type=Path, help="a finished match folder under data/runs/")
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    args = ap.parse_args(argv)
    if not (args.match / "match.json").is_file() and not (args.match / "replay.json").is_file():
        print(f"REFUSED: {args.match} has no match.json")
        return 2
    why = problems(args.match)
    if why:
        print("REFUSED: not a clean demo run:\n  " + "\n  ".join(why))
        return 2
    if args.check:
        print(f"OK: {args.match} is a clean demo run (nothing written)")
        return 0
    p = export_dashboard.export(args.match, NAME, PUBLIC)
    sync_dist()
    print(f"wrote {p.relative_to(REPO)} (+ bundles.js) and synced dashboard/dist/data/")
    print(f"replay: file://{REPO}/dashboard/dist/index.html#src=bundle:{NAME}&tab=battle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
