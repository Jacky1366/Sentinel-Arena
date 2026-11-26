"""Stage 7 #18: turn a finished, clean demo run into the golden run of its matchup (D45, D58,
D61). Zero tokens, no network, never writes the source folder.

    .venv/bin/python tools/export_golden.py <match or replay folder> --check   (no write)
    .venv/bin/python tools/export_golden.py <match or replay folder>

The matchup comes from the manifest:
  taxonomy  a match, Red prompt v1           -> bundle golden-taxonomy   (matchup 1)
  freeplay  a match, Red prompt v3           -> bundle golden-freeplay   (matchup 2)
  open      a replay, Blue prompt v3-open    -> bundle golden-open       (matchup 3)
Clean = not test data by its manifest (D59, read first); completed; purpose dev (D45); the
demo configuration (tools/demo_match.py: demo Red, original Blue rules on; for open, the
source is a clean free-play demo match still on disk); four facts PASS (or N/A: Blue stored
no rule). Writes the bundle with tools/export_dashboard.py (dashboard/public/data/ +
bundles.js), then copies dashboard/public/data/ into dashboard/dist/data/, so
`scripts/demo.sh --replay <matchup>` plays it from file:// with no rebuild.

Match and replay folders stay in data/runs/ and data/replays/ (git-ignored); whether to also
commit them under data/golden/ is the designer's call (data/golden/ is important lane)."""

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
from tools import demo_match, export_dashboard, four_facts  # noqa: E402

KINDS = ("taxonomy", "freeplay", "open")
PROMPT_KIND = {"1": "taxonomy", "3": "freeplay"}
PUBLIC = REPO / "dashboard" / "public" / "data"
DIST = REPO / "dashboard" / "dist" / "data"


def bundle_name(kind: str) -> str:
    return f"golden-{kind}"


def _read(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _match_problems(m: dict, kind: str) -> list[str]:
    out = []
    if m.get("status") != "completed":
        out.append(f"status {m.get('status')!r} (failed step {m.get('failed_step')!r})")
    if m.get("purpose") != "dev":
        out.append(f"purpose {m.get('purpose')!r}, not dev (D45)")
    if not out and not demo_match.is_demo_match(m, {"taxonomy": "1", "freeplay": "3"}[kind]):
        red = ((m.get("models") or {}).get("red") or {}).get("model")
        blue = ((m.get("models") or {}).get("blue") or {}).get("model")
        out.append(f"not the {kind} demo configuration (Red {m.get('red_engine')} {red!r}, "
                   f"Blue {m.get('blue_engine')} {blue!r})")
    return out


def classify_run(d: Path, registry=None) -> tuple[str | None, list[str]]:
    """(matchup kind or None, problems). [] problems = a clean golden-run candidate."""
    d = Path(d)
    registry = registry or test_data.load_registry()
    v = test_data.classify(d, registry)
    if v.kind != test_data.NOT_TEST:
        return None, [f"not exportable: {v.kind} ({v.reason})"]
    if (d / "replay.json").is_file():
        r = _read(d / "replay.json")
        bp = r.get("blue_params") or {}
        if bp.get("prompt_version") != "3-open":
            return None, [f"a replay with Blue prompt {bp.get('prompt_version')!r}, not open "
                          f"Blue (3-open): not a demo matchup"]
        kind, out = "open", []
        if r.get("status") != "completed":
            out.append(f"status {r.get('status')!r} (failed step {r.get('failed_step')!r})")
        if ((r.get("models") or {}).get("blue") or {}).get("model") != demo_match.BLUE:
            out.append("open Blue is not the demo Blue model")
        src = REPO / ((r.get("source") or {}).get("path") or "")
        if not (src / "match.json").is_file():
            out.append(f"its source match folder is missing: {src}")
        elif test_data.classify(src, registry).kind != test_data.NOT_TEST:
            out.append("its source is not exportable (test or unknown)")
        else:
            out += [f"source: {p}" for p in _match_problems(_read(src / "match.json"), "freeplay")]
    else:
        m = _read(d / "match.json")
        kind = PROMPT_KIND.get((m.get("red_params") or {}).get("prompt_version"))
        if kind is None:
            return None, [f"Red prompt {(m.get('red_params') or {}).get('prompt_version')!r}: "
                          f"not a demo matchup (taxonomy v1, free-play v3)"]
        out = _match_problems(m, kind)
    if not out:
        f = four_facts.check(d)
        if f["status"] not in (four_facts.PASS, four_facts.NA):  # NA: Blue stored no rule
            out.append(f"four facts {f['status']}: {'; '.join(f['reasons'])}")
    return kind, out


def problems(d: Path, registry=None) -> list[str]:
    return classify_run(d, registry)[1]


def sync_dist(public: Path = PUBLIC, dist: Path = DIST) -> None:
    """dashboard/dist/data/ = dashboard/public/data/ (what `npm run build` would copy)."""
    dist.mkdir(parents=True, exist_ok=True)
    for p in public.iterdir():
        if p.is_file():
            shutil.copy2(p, dist / p.name)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder", type=Path, help="a finished demo match or open-Blue replay folder")
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    args = ap.parse_args(argv)
    if not (args.folder / "match.json").is_file() and not (args.folder / "replay.json").is_file():
        print(f"REFUSED: {args.folder} has no match.json or replay.json")
        return 2
    kind, why = classify_run(args.folder)
    if why:
        print("REFUSED: not a clean demo run:\n  " + "\n  ".join(why))
        return 2
    name = bundle_name(kind)
    if args.check:
        print(f"OK: {args.folder} is a clean {kind} demo run -> would be {name} (nothing written)")
        return 0
    p = export_dashboard.export(args.folder, name, PUBLIC)
    sync_dist()
    print(f"wrote {p.relative_to(REPO)} (+ bundles.js) and synced dashboard/dist/data/")
    print(f"replay: scripts/demo.sh --replay {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
