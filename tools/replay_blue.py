"""Replay Blue on a FROZEN match (Stage 5.5, D17): run Blue and the full Judge on a
copy of the match's inputs, in a NEW folder. Never writes into the source.

    .venv/bin/python tools/replay_blue.py --match data/golden/ai-red-luna-gate2-match1 \
        --engine claude --rules-mode on            # REAL, PAID calls (Blue only)
    .venv/bin/python tools/replay_blue.py --match <frozen dir> --engine scripted

Why this is equivalent to a live run (D17): Blue is a passive detector. It reads the
proxy log after the match froze it, and its verdicts never change the traffic (Red's
feedback is its own HTTP responses only, D6; the benign schedule is seeded). So Blue
run later on the frozen proxy log sees exactly what it would have seen live.

Steps:
  1. refuse   the source must be a frozen match (match.json, status completed or
              stopped); --out must not exist or be empty, and must not be or lie
              inside any folder holding a match.json or replay.json
  2. verify   every input's sha256 equals the source match.json's artifacts entry
  3. copy     proxy.jsonl, red_attacks.jsonl, benign_requests.jsonl,
              challenge_snapshots.jsonl, red_unsent.jsonl (those the source has).
              NOT copied: verdicts, rounds, landed, results, anomalies, api_calls
              (Red's calls must not count against this replay's Blue budget) and
              match.json; their hashes stay recorded in replay.json source.artifacts
  4. run      judge_fact1 -> blue -> judge_rounds -> judge_benign -> judge_red ->
              judge_rules: the SAME run_match.Ops steps a live match uses, so the
              Judge re-runs completely at the current JUDGE_VERSION
  5. replay.json written LAST (schemas/replay_manifest.schema.json)

Verdicts and rounds keep the SOURCE match_id, so the join works unchanged and the
source's D16 audit applies (tools/audit_match.py reads replay.json source.match_id);
a replay is identified by its replay_id and folder (default data/replays/<replay_id>/,
git-ignored). Blue's information wall is unchanged: it reads only the proxy log.

Exit codes: 0 completed, 1 failed, 2 refused (nothing written), 4 stopped by the
AI budget (same meaning as run_match.py).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import traceback
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from agents import llm_client  # noqa: E402
from blue import claude_engine, run_blue  # noqa: E402
from judge import JUDGE_VERSION, fact4_benign, red_facts, rule_facts  # noqa: E402
from runner import match_ops  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from stats import match_stats  # noqa: E402

REPLAYS = REPO / "data" / "replays"
COPY = ("proxy.jsonl", "red_attacks.jsonl", "benign_requests.jsonl",
        "challenge_snapshots.jsonl", "red_unsent.jsonl")
REQUIRED = ("proxy.jsonl", "red_attacks.jsonl", "challenge_snapshots.jsonl")
STEPS = ("judge_fact1", "blue", "judge_rounds", "judge_benign", "judge_red", "judge_rules")
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "replay_manifest.schema.json")
                                         .read_text(encoding="utf-8")))
EXIT = {"completed": 0, "failed": 1, "stopped": 4}


class Refused(Exception):
    """The source or the output location is not acceptable; nothing was written."""


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(p.resolve())


def check_out_dir(out: Path) -> None:
    out = out.resolve()
    for d in (out, *out.parents):
        for marker in ("match.json", "replay.json"):
            if (d / marker).exists():
                raise Refused(f"refusing to write into {d}: it holds a {marker} (frozen "
                              f"artifacts are immutable)")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise Refused(f"refusing to write into {out}: it exists and is not empty")


def load_source(match_dir: Path) -> tuple[dict, dict[str, str]]:
    """(source match.json, {file: sha256} of the inputs to copy), every hash verified
    against the source's own match.json. Raises Refused."""
    mpath = match_dir / "match.json"
    if not mpath.is_file():
        raise Refused(f"{match_dir} is not a frozen match (no match.json)")
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    errors = run_match.validate_manifest(manifest)
    if errors:
        raise Refused(f"{mpath} is schema-invalid: {errors}")
    if manifest["status"] not in ("completed", "stopped"):
        raise Refused(f"source status is {manifest['status']!r}: only a completed or "
                      f"stopped match can be replayed")
    copied: dict[str, str] = {}
    for name in COPY:
        src = match_dir / name
        recorded = manifest["artifacts"].get(name)
        if recorded is None:
            if src.exists():
                raise Refused(f"{name} exists in the source but is not in its match.json "
                              f"artifacts")
            if name in REQUIRED:
                raise Refused(f"source has no {name}")
            continue
        actual = run_match.sha256_file(src) if src.is_file() else None
        if actual != recorded["sha256"]:
            raise Refused(f"{name}: sha256 {actual} differs from the source match.json "
                          f"({recorded['sha256']}): the frozen match was changed")
        copied[name] = actual
    return manifest, copied


def replay(match_dir: Path, out: Path | None = None, engine: str = "scripted",
           rules_mode: str | None = None, model: str | None = None,
           ops: run_match.Ops | None = None, out_fn=print,
           caching: str | None = None) -> tuple[int, Path | None]:
    """Replay Blue + the Judge. Returns (exit code, replay dir or None if refused)."""
    ops = ops or run_match.Ops()
    try:
        if engine not in run_blue.ENGINE_NAMES:
            raise Refused(f"unknown Blue engine {engine!r}")
        source, copied = load_source(match_dir)
        replay_id = run_match.new_match_id()
        out = out or REPLAYS / replay_id
        check_out_dir(out)
        config, prices, price_ref = ops.llm_setup()
        if caching is not None and engine != "claude":
            raise Refused("--caching needs --engine claude (caching is an AI-call setting)")
        config = llm_client.with_caching(config, "blue", caching)
        if engine == "claude":
            blue_m = run_blue.blue_model(config, model)
            chunk = run_blue.blue_chunk_size(config)
            if chunk != 1:
                raise Refused(f"agents.blue.chunk_size is {chunk}: scored runs are one line "
                              f"per call (D4)")
            blue_params = claude_engine.blue_params(config, blue_m, chunk, rules_mode)
            models = {"blue": {"provider": blue_params["provider"], "model": blue_m}}
            mode = blue_params["rules"]["mode"]
        else:
            if rules_mode not in (None, "off"):
                raise Refused("--rules-mode needs --engine claude")
            blue_m, blue_params, models, mode = None, None, {"blue": None}, None
        git = ops.git_info()
    except (Refused, ValueError, OSError) as exc:
        out_fn(f"REFUSED: {llm_client.redact(str(exc))}")
        return 2, None

    out.mkdir(parents=True, exist_ok=True)
    for name, sha in copied.items():
        shutil.copyfile(match_dir / name, out / name)
        if run_match.sha256_file(out / name) != sha:  # never trust a copy unchecked
            raise OSError(f"copy of {name} does not match its source hash")
    started = match_ops.utc_now()
    mid = source["match_id"]
    out_fn(f"replay {replay_id} of {mid} -> {_rel(out)}  blue={engine}"
           f"{f' rules={mode}' if mode else ''}")

    failed_step = error = None
    step = STEPS[0]
    try:
        ops.judge_fact1(out)
        step = "blue"
        if engine == "claude":
            ops.blue(out, mid, engine, ops.blue_client(config, prices), blue_m, mode)
        else:
            ops.blue(out, mid, engine)
        for step in STEPS[2:]:
            getattr(ops, step)(out)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - finalize on ANY failure
        failed_step = step
        error = llm_client.redact(f"{type(exc).__name__}: {exc}")
        out_fn(f"REPLAY FAILED at step '{step}': {error}")
        out_fn(llm_client.redact(traceback.format_exc().rstrip()))

    calls = cost_stats.read_calls(out / llm_client.API_CALLS)
    stop = llm_client.stopped_by(calls, prices)
    status = "failed" if failed_step else "stopped" if stop is not None else "completed"
    manifest = {
        "schema_version": "0.2", "replay_id": replay_id, "started_at": started,
        "finished_at": match_ops.utc_now(), "status": status, "failed_step": failed_step,
        "error": error, "judge_version": JUDGE_VERSION,
        "source": {"match_id": mid, "path": _rel(match_dir),
                   "match_json_sha256": run_match.sha256_file(match_dir / "match.json"),
                   "status": source["status"], "judge_version": source["judge_version"],
                   "blue_engine": source["blue_engine"],
                   "red_engine": source.get("red_engine", "scripted"),
                   "artifacts": source["artifacts"], "copied": sorted(copied)},
        "blue_engine": engine, "blue_params": blue_params, "git": git, "models": models,
        "budget": {"limits": llm_client.caps_limits(config), "stopped_by": stop},
        "price_table": price_ref, "cost": cost_stats.summarize(calls, prices),
        "artifacts": run_match.artifact_hashes(out),
    }
    errors = [e.message for e in SCHEMA.iter_errors(manifest)]
    (out / "replay.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if errors:
        out_fn(f"BUG: replay.json is schema-invalid: {errors}")
        return 1, out
    out_fn("")
    out_fn(summary(out, manifest, source))
    return EXIT[status], out


def summary(out: Path, manifest: dict, source: dict) -> str:
    """The run_match terminal summary, over the replay folder."""
    view = {**manifest, "match_id": f"{manifest['source']['match_id']} "
                                    f"(replay {manifest['replay_id']})",
            "red_engine": manifest["source"]["red_engine"], "traffic": source.get("traffic")}
    r = match_stats.read_rounds
    return match_stats.format_summary(
        r(out / "rounds.jsonl"), view, benign=r(out / fact4_benign.RESULTS),
        anomalies=r(out / fact4_benign.ANOMALIES), verdicts=r(out / "verdicts.jsonl"),
        red_unsent=r(out / match_ops.RED_UNSENT),
        challenge_map=json.loads(red_facts.CHALLENGE_MAP.read_text(encoding="utf-8")),
        rules=(r(out / "rules.jsonl"), r(out / "rule_rejections.jsonl"),
               r(out / rule_facts.RESULTS)))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--match", type=Path, required=True, help="frozen match folder")
    ap.add_argument("--out", type=Path, default=None,
                    help="new, empty folder (default: data/replays/<replay_id>)")
    ap.add_argument("--engine", choices=run_blue.ENGINE_NAMES, default="scripted")
    ap.add_argument("--rules-mode", choices=("off", "shadow", "on"), default=None,
                    help="claude: rule invention mode (default: config/llm.json)")
    ap.add_argument("--model", default=None, help="claude: Blue model id override")
    ap.add_argument("--caching", choices=("off", "on"), default=None,
                    help="claude: prompt caching (default: config/llm.json agents.blue.caching)")
    args = ap.parse_args(argv)
    code, _ = replay(args.match, args.out, args.engine, args.rules_mode, args.model,
                     caching=args.caching)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
