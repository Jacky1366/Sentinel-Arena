"""Capture and seal the offline benign files (Stage 6.1, M4, D27, D31). Zero tokens, no AI.

    .venv/bin/python tools/build_holdout.py --check     # drafts valid; sealed files intact
    .venv/bin/python tools/build_holdout.py --capture   # Gate 0: touches the Target (GO only)

Two designer-approved drafts are captured together:
  benign/holdout_v1.draft.json          -> benign/holdout_v1.jsonl          TEST (S6-1)
  benign/fixture_v2_offline.draft.json  -> benign/fixture_v2_offline.jsonl  TRAIN (D31)

--capture sends each entry ONCE through the shared arena client (the same sender, same
headers as every match, design principle 8) to a freshly reset Target, OUTSIDE any match
(it holds the match lock so it never overlaps one), reads the logged proxy lines and
copies method/path/query/body VERBATIM, so offline rules see exactly what Blue would
see. Then it resets the Target. It writes each .jsonl and .meta.json with an exclusive
create (a sealed file is never overwritten) and records both sha256 in
config/test_set.json. Commit all of it in ONE commit before the first train match
(pre-registration: tools/promote_rules.py checks the sealed hashes exist at the train
match's commit). The capture traffic stays in data/runs/live/ until the next match
rotates it into the archive; it is never part of any match.

--check (no network) validates both drafts and, once sealed, that each file still matches
its .meta.json and config/test_set.json and holds exactly its draft's entries, in order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from red.scripted_red import request_target  # noqa: E402  (same target builder as Red)
from runner import arena_client, match_ops  # noqa: E402

BENIGN = REPO / "benign"
TEST_SET = REPO / "config" / "test_set.json"
SETS = ("holdout_v1", "fixture_v2_offline")


def _schema(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((REPO / "schemas" / f"{name}.schema.json")
                                           .read_text(encoding="utf-8")))


DRAFT, LINE, TEST_SET_SCHEMA = (_schema("benign_offline_draft"), _schema("benign_holdout"),
                                _schema("test_set"))


def draft_path(name: str) -> Path:
    return BENIGN / f"{name}.draft.json"


def out_path(name: str) -> Path:
    return BENIGN / f"{name}.jsonl"


def meta_path(name: str) -> Path:
    return BENIGN / f"{name}.meta.json"


def load_draft(name: str) -> dict:
    d = json.loads(draft_path(name).read_text(encoding="utf-8"))
    errors = [e.message for e in DRAFT.iter_errors(d)]
    if errors:
        raise ValueError(f"{draft_path(name)} is schema-invalid: {errors}")
    if d["set"] != name:
        raise ValueError(f"{draft_path(name)} says set {d['set']!r}, not {name!r}")
    ids = [e["benign_id"] for e in d["entries"]]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{draft_path(name)}: duplicate benign ids")
    return d


def check_drafts() -> dict[str, dict]:
    drafts = {n: load_draft(n) for n in SETS}
    a, b = ({(e["method"], request_target(e), json.dumps(e.get("json_body"), sort_keys=True))
             for e in drafts[n]["entries"]} for n in SETS)
    if a & b:
        raise ValueError(f"holdout and fixture_v2_offline share requests: {sorted(a & b)}")
    return drafts


def line_of(entry: dict, logged: dict) -> dict:
    return {"benign_id": entry["benign_id"], "category": entry["category"],
            "look_alike": entry["look_alike"], "method": logged["method"],
            "path": logged["path"], "query": logged["query"], "body": logged["body"]}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_sealed() -> list[str]:
    """Problems with the sealed files (empty list = fine, or not sealed yet)."""
    problems: list[str] = []
    ts = json.loads(TEST_SET.read_text(encoding="utf-8"))
    problems += [f"config/test_set.json: {e.message}" for e in TEST_SET_SCHEMA.iter_errors(ts)]
    recorded = {s["path"]: s["sha256"] for s in ts["sealed"]}
    drafts = check_drafts()
    for name in SETS:
        p, rel = out_path(name), out_path(name).relative_to(REPO).as_posix()
        if not p.exists():
            if recorded.get(rel) is not None:
                problems.append(f"{rel} is recorded as sealed but missing")
            continue
        data = p.read_text(encoding="utf-8")
        meta = json.loads(meta_path(name).read_text(encoding="utf-8"))
        sha = sha256_text(data)
        if sha != meta["sha256"]:
            problems.append(f"{rel}: sha256 {sha} differs from its meta {meta['sha256']}")
        if recorded.get(rel) != sha:
            problems.append(f"{rel}: sha256 {sha} differs from config/test_set.json "
                            f"{recorded.get(rel)}")
        rows = [json.loads(l) for l in data.splitlines() if l.strip()]
        for i, r in enumerate(rows, start=1):
            problems += [f"{rel} line {i}: {e.message}" for e in LINE.iter_errors(r)]
        want = [(e["benign_id"], e["category"], e["look_alike"]) for e in drafts[name]["entries"]]
        got = [(r.get("benign_id"), r.get("category"), r.get("look_alike")) for r in rows]
        if got != want:
            problems.append(f"{rel}: entries differ from its draft")
        if meta.get("draft_sha256") != hashlib.sha256(draft_path(name).read_bytes()).hexdigest():
            problems.append(f"{rel}: its draft changed after sealing")
    return problems


def git_commit() -> str:
    import subprocess
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent,
                          capture_output=True, text=True, check=True).stdout.strip()


def _read_live(rids: set[str]) -> dict[str, dict]:
    live = match_ops.LIVE / "proxy.jsonl"
    out = {}
    if live.exists():
        for raw in live.read_text(encoding="utf-8").splitlines():
            if raw.strip():
                line = json.loads(raw)
                if line.get("request_id") in rids:
                    out[line["request_id"]] = line
    return out


def capture(settle: float = 1.0, out=print) -> int:
    drafts = check_drafts()
    for name in SETS:
        for p in (out_path(name), meta_path(name)):
            if p.exists():
                raise FileExistsError(f"{p} exists: a sealed file is never overwritten")
    images = match_ops.running_images()  # raises if the stack is not up
    match_ops.check_live_clean(match_ops.LIVE)
    match_ops.acquire_lock(match_ops.LIVE, "holdout-capture")
    try:
        solved = match_ops.reset_target()
        if solved != 0:
            raise RuntimeError(f"Target not clean after reset ({solved} solved)")
        match_ops.rotate_proxy_log(match_ops.LIVE)  # a fresh live log to read
        sent: dict[str, list[tuple[dict, str, int | None]]] = {}
        for name in SETS:
            sent[name] = []
            for e in drafts[name]["entries"]:
                rid = arena_client.new_request_id()
                body = json.dumps(e["json_body"]) if e.get("json_body") is not None else None
                resp = arena_client.send(e["method"], request_target(e), rid, body=body)
                sent[name].append((e, rid, resp.status))
        time.sleep(settle)  # let nginx flush
        logged = _read_live({rid for rows in sent.values() for _, rid, _ in rows})
    finally:
        match_ops.reset_target()  # leave the Target clean
        match_ops.release_lock(match_ops.LIVE)
    missing = [e["benign_id"] for rows in sent.values() for e, rid, _ in rows
               if rid not in logged]
    if missing:
        raise RuntimeError(f"not logged (stray or lost): {missing}; nothing written")
    git = {"commit": git_commit()}
    ts = json.loads(TEST_SET.read_text(encoding="utf-8"))
    for name in SETS:
        lines = [line_of(e, logged[rid]) for e, rid, _ in sent[name]]
        for r in lines:
            LINE.validate(r)
        text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in lines)
        sha = sha256_text(text)
        counts: dict[str, int] = {}
        for r in lines:
            k = r["category"] if r["look_alike"] is None else f"hard_negative {r['look_alike']}"
            counts[k] = counts.get(k, 0) + 1
        meta = {"set": name, "role": drafts[name]["role"],
                "path": out_path(name).relative_to(REPO).as_posix(), "entries": len(lines),
                "sha256": sha, "sealed_at": match_ops.utc_now(), "counts": counts,
                "draft_sha256": hashlib.sha256(draft_path(name).read_bytes()).hexdigest(),
                "capture": {"images": images, "git": git,
                            "statuses": {e["benign_id"]: s for e, _, s in sent[name]}},
                "note": "Captured verbatim from the proxy log outside any match (Stage 6.1, "
                        "D27). Never sent in a match; Blue never reads it."}
        with out_path(name).open("x", encoding="utf-8") as fh:
            fh.write(text)
        with meta_path(name).open("x", encoding="utf-8") as fh:
            fh.write(json.dumps(meta, indent=2) + "\n")
        for s in ts["sealed"]:
            if s["path"] == meta["path"]:
                s["sha256"] = sha
        out(f"sealed {meta['path']}: {len(lines)} entries, sha256 {sha}")
    TEST_SET.write_text(json.dumps(ts, indent=2) + "\n", encoding="utf-8")
    out("Target reset. Commit benign/*.jsonl, benign/*.meta.json and config/test_set.json "
        "in ONE commit before the first train match.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--capture", action="store_true")
    ap.add_argument("--settle", type=float, default=1.0)
    args = ap.parse_args(argv)
    if args.capture:
        return capture(args.settle)
    problems = check_sealed()
    for p in problems:
        print(f"PROBLEM {p}")
    sealed = [n for n in SETS if out_path(n).exists()]
    print(f"drafts valid; sealed: {sealed or 'none yet'}; "
          f"{'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
