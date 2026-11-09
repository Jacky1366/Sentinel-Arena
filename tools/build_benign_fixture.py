"""Build (or --check) the fact-4b benign fixture from a FROZEN golden match.

The fixture is the benign lines of the match's frozen proxy.jsonl, selected via
its benign_requests.jsonl, with method/path/query/body copied VERBATIM: rules must
see exactly the form Blue sees in a real log. It is never rebuilt from
benign_set.json. Lines follow benign_requests.jsonl order.

    .venv/bin/python tools/build_benign_fixture.py            # write v1
    .venv/bin/python tools/build_benign_fixture.py --check    # rebuild, compare, exit 1 on drift
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "data" / "golden" / "scripted-baseline-benign-match"
FIXTURE = REPO / "benign" / "fixture_v1.jsonl"
META = REPO / "benign" / "fixture_v1.meta.json"
VERSION = "1"


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(match_dir: Path) -> tuple[str, dict]:
    proxy = {l["request_id"]: l for l in _jsonl(match_dir / "proxy.jsonl")}
    manifest = json.loads((match_dir / "match.json").read_text(encoding="utf-8"))
    lines = []
    for b in _jsonl(match_dir / "benign_requests.jsonl"):
        p = proxy.get(b["request_id"])
        if p is None:
            raise ValueError(f"benign {b['benign_id']} has no proxy line in {match_dir}")
        lines.append(json.dumps({"benign_id": b["benign_id"], "category": b["category"],
                                 "method": p["method"], "path": p["path"],
                                 "query": p["query"], "body": p["body"]}, ensure_ascii=False))
    text = "\n".join(lines) + "\n"
    rel = match_dir.resolve().relative_to(REPO).as_posix()
    meta = {"fixture_version": VERSION, "path": FIXTURE.relative_to(REPO).as_posix(),
            "entries": len(lines),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "source": {"match_dir": rel, "match_id": manifest["match_id"],
                       "proxy_sha256": manifest["artifacts"]["proxy.jsonl"]["sha256"],
                       "benign_requests_sha256":
                           manifest["artifacts"]["benign_requests.jsonl"]["sha256"],
                       "benign_set_sha256": manifest["traffic"]["benign_set"]["sha256"]},
            "note": "Fact-4b fixture: the benign lines of the frozen golden proxy log, "
                    "verbatim. Not held out: the same 17 requests are sent in every match "
                    "(D1 layer 1), so Blue may have seen them (contract 6.7). Blue must "
                    "never read this file."}
    return text, meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--match", type=Path, default=SOURCE)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    text, meta = build(args.match)
    if args.check:
        ok = FIXTURE.read_text(encoding="utf-8") == text and \
            json.loads(META.read_text(encoding="utf-8")) == meta
        print("fixture matches its source" if ok else "FIXTURE DRIFT: rebuild differs")
        return 0 if ok else 1
    FIXTURE.write_text(text, encoding="utf-8")
    META.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"{meta['entries']} entries -> {FIXTURE.relative_to(REPO)} sha256 {meta['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
