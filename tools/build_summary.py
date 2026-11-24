"""Build the analyst summary.json (Stage 7 #16; D53, D55, D60). Zero tokens.

    .venv/bin/python tools/build_summary.py [--manifest config/analyst_sources.json] [--out FILE]
    .venv/bin/python tools/build_summary.py --check FILE

Every source folder is classified by its manifest first (stats/test_data, D59), before any
other file in it is opened. If ANY source is test data, or unknown (no manifest: nothing
proves it is not test data), the build refuses unless ARENA_GO holds a well-formed token
(runner/go_token): the designer's GO for a test-set read is visible in the command, the same
way as for a paid call, e.g. ARENA_GO=manual-analyst-summary.

Development builds go to data/runs/analyst/ (git-ignored, D60 c); the final summary used for
the report is committed with it under data/golden/ in #17.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from analyst import summary as summary_mod  # noqa: E402
from judge import JUDGE_VERSION  # noqa: E402
from runner import go_token  # noqa: E402
from stats import cost as cost_mod  # noqa: E402
from stats import test_data  # noqa: E402

MANIFEST = REPO / "config" / "analyst_sources.json"
OUT_DIR = REPO / "data" / "runs" / "analyst"
SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "analyst_summary.schema.json").read_text(encoding="utf-8")))


def folders_of(manifest: dict, repo: Path = REPO) -> list[Path]:
    return [(repo / p) if not Path(p).is_absolute() else Path(p)
            for g in manifest["groups"] for p in g["folders"]]


def gate(manifest: dict, env=None, registry=None, repo: Path = REPO) -> str | None:
    """None if the build may read every source; else the refusal text (D59 + GO)."""
    registry = registry if registry is not None else test_data.load_registry()
    kinds = [test_data.classify(d, registry).kind for d in folders_of(manifest, repo)]
    guarded = sum(k != test_data.NOT_TEST for k in kinds)
    if guarded == 0:
        return None
    if go_token.valid((os.environ if env is None else env).get(go_token.ENV)):
        return None
    return (f"REFUSED: {guarded} of {len(kinds)} source folders are test data or unknown "
            f"(D59). Reading them needs the designer's GO: set ARENA_GO=<token> for this "
            f"command (e.g. manual-analyst-summary).")


def validate(doc: dict) -> list[str]:
    return [e.message for e in SCHEMA.iter_errors(doc)]


def _git() -> dict:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                            text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                                capture_output=True, text=True).stdout.strip())
    return {"commit": commit or None, "dirty": dirty}


def main(argv: list[str] | None = None, env=None) -> int:
    ap = argparse.ArgumentParser(description="Build the analyst summary.json (zero tokens).")
    ap.add_argument("--manifest", type=Path, default=MANIFEST)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--check", type=Path, default=None, help="validate an existing summary")
    args = ap.parse_args(argv)
    if args.check is not None:
        errs = validate(json.loads(args.check.read_text(encoding="utf-8")))
        print("summary OK" if not errs else f"summary INVALID: {errs[:5]}")
        return 0 if not errs else 1
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    refusal = gate(manifest, env)
    if refusal:
        print(refusal)
        return 2
    doc = summary_mod.build(manifest, prices=cost_mod.load_prices(), git=_git(),
                            judge_version=JUDGE_VERSION, manifest_path=args.manifest)
    errs = validate(doc)
    if errs:
        print(f"BUG: summary is schema-invalid: {errs[:5]}")
        return 1
    out = args.out or OUT_DIR / ("summary-" + datetime.now(timezone.utc)
                                 .strftime("%Y%m%dT%H%M%SZ") + ".json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"{len(doc['figures'])} figures from {len(doc['sources'])} sources -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
