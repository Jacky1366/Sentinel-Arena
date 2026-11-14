"""Sentinel Arena orchestrator: one complete match, one command.

    .venv/bin/python run_match.py              # requires: docker compose up -d --wait
    .venv/bin/python run_match.py --seed 5202  # reproduce a match's schedule
    .venv/bin/python run_match.py --blue claude   # AI Blue (Stage 5.4; real, paid calls)
    .venv/bin/python run_match.py --blue claude --blue-rules-mode on   # + rule invention (5.5)

The orchestrator is the ONLY thing that sequences components. Components never
call each other; each step reads and writes file artifacts (docs/contract.md).

  1. preflight   both containers Up, juice-shop healthy, live/ has no leftovers,
                 provenance (git commit + dirty, payload + benign-set sha256)
                 readable, benign set valid, seed chosen (--seed or generated);
                 for --blue claude: a Blue model and chunk_size 1 (D4)
  2. lock        live/match.lock (refuse if held; never auto-broken)
  3. match_id    UTC timestamp + 4 hex, e.g. 20261109T153012Z-a1b2
  4. reset       restart the Target, verify 0 solved (refuse if not clean)
  5. rotate      archive the previous live/proxy.jsonl, nginx reopens a fresh one
  6. traffic     Red attacks and benign requests, interleaved one slot at a time
                 by the seeded schedule (both keep their own order), each with
                 before/after snapshots -> data/runs/<match_id>/
  7. freeze      move live/proxy.jsonl into the match dir, nginx reopens
  8. judge_fact1 -> blue -> judge_rounds -> judge_benign (fact 4a + anomalies)
                 -> judge_red (label_mismatch) -> judge_rules (facts 3 + 4b for the
                 rules Blue stored; nothing without rules.jsonl), on the FROZEN
                 directory
  9. match.json  written LAST (status, provenance, traffic seed + schedule,
                 models, blue_params incl. the rules mode, budget, cost, sha256 of
                 every artifact), schema_version 0.6
 10. summary     a pure read of the Judge outputs + match.json: detection is
                 always printed next to the FP rate

If any step from 4 on fails, the match is still finalized: whatever this match
produced is in data/runs/<match_id>/, match.json says status "failed" with the
failed step and error, the lock is released, and the exit code is non-zero. A
failed match never leaves its artifacts in live/. Incomplete data
(snapshot_missing) is not a failure; ambiguous data (the Judge raises) is.

A match is "stopped" when the AI body refused a call (a budget cap, a missing
price or key) or saw usage it cannot price: everything still runs and is
finalized, and match.json says which cap in budget.stopped_by (contract §6.2).
Key values never reach match.json or the terminal (llm_client.redact).

Exit codes (docs/ops.md): 0 completed, 1 match failed, 2 preflight refused,
3 lock held, 4 stopped by the budget. The scripted match makes no AI API calls;
--blue claude makes one Blue call per logged line through agents/llm_client.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
from blue import claude_engine, run_blue  # noqa: E402
from agents import llm_client  # noqa: E402
from benign import send_benign  # noqa: E402
from judge import (JUDGE_VERSION, fact1_landed, fact4_benign, red_facts,  # noqa: E402
                   round_record, rule_facts)
from red import ai_red, scripted_red  # noqa: E402
from runner import match_ops  # noqa: E402
from runner.schedule import Schedule, new_seed  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from stats import match_stats  # noqa: E402


def _schema(name: str) -> dict:
    return json.loads((REPO / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


MANIFEST_VERSION = "0.6"
MANIFEST_SCHEMAS = {"0.1": _schema("match_manifest_v0_1"), "0.2": _schema("match_manifest_v0_2"),
                    "0.3": _schema("match_manifest_v0_3"), "0.4": _schema("match_manifest_v0_4"),
                    "0.5": _schema("match_manifest_v0_5"), "0.6": _schema("match_manifest")}
MANIFEST_SCHEMA = MANIFEST_SCHEMAS[MANIFEST_VERSION]
PRICES_SCHEMA = _schema("prices")
EXIT = {"completed": 0, "failed": 1, "stopped": 4}  # 2 preflight refused, 3 lock held


def validate_manifest(manifest: dict) -> list[str]:
    """Schema errors, dispatching on schema_version (0.1 manifests stay valid)."""
    schema = MANIFEST_SCHEMAS.get(manifest.get("schema_version"))
    if schema is None:
        return [f"unknown match.json schema_version {manifest.get('schema_version')!r}"]
    return [e.message for e in Draft202012Validator(schema).iter_errors(manifest)]


def new_match_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{secrets.token_hex(2)}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_hashes(match_dir: Path) -> dict:
    """{relative name: {sha256, bytes}} for every file in the match dir except
    match.json itself."""
    out = {}
    for p in sorted(match_dir.rglob("*")):
        if p.is_file():
            name = p.relative_to(match_dir).as_posix()
            if name != "match.json":
                out[name] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    return out


def _display_path(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


class Ops:
    """Real implementations of every step. Tests subclass this to inject fakes or
    failures without Docker."""

    def preflight(self) -> dict:
        return match_ops.running_images()

    def git_info(self) -> dict:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, check=True,
                                capture_output=True, text=True).stdout.strip()
        status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO, check=True,
                                capture_output=True, text=True).stdout
        return {"commit": commit, "dirty": bool(status.strip())}

    def llm_setup(self) -> tuple[dict, dict, dict]:
        """(llm config, price table, price-table ref). Read even for a scripted
        match: match.json always records the caps and the table in force."""
        config = llm_client.load_config()
        prices = cost_stats.load_prices()
        Draft202012Validator(PRICES_SCHEMA).validate(prices)
        return config, prices, cost_stats.price_table_ref()

    def reset(self) -> int:
        return match_ops.reset_target()

    def rotate(self, live_dir: Path) -> Path | None:
        return match_ops.rotate_proxy_log(live_dir)

    def traffic(self, match_id: str, match_dir: Path, attacks: list[dict],
                benign_entries: list[dict], schedule: Schedule, settle: float,
                red_driver=None) -> None:
        match_ops.run_traffic(match_id, match_dir, attacks, benign_entries, schedule, settle,
                              red_driver=red_driver)

    def red_client(self, config: dict, prices: dict) -> llm_client.LLMClient:
        """The AI body for --red ai: real adapters, real keys, real (paid) calls.
        A NETWORK step: test fakes must override it."""
        return llm_client.LLMClient(config=config, prices=prices)

    def freeze(self, live_dir: Path, match_dir: Path) -> None:
        match_ops.freeze_proxy_log(live_dir, match_dir)

    def reopen(self, live_dir: Path) -> None:
        match_ops.reopen_and_confirm(live_dir)

    # Pure file steps: each component's own CLI entry point, pointed at the frozen
    # match directory.
    def judge_fact1(self, match_dir: Path) -> None:
        fact1_landed.main(["--run-dir", str(match_dir)])

    def blue_client(self, config: dict, prices: dict) -> llm_client.LLMClient:
        """The AI body for --blue claude: real adapters, real keys, real (paid) calls.
        A NETWORK step: test fakes must override it."""
        return llm_client.LLMClient(config=config, prices=prices)

    def blue(self, match_dir: Path, match_id: str, engine: str, client=None,
             model: str | None = None, rules_mode: str | None = None) -> None:
        argv = ["--engine", engine, "--match-id", match_id, "--run-dir", str(match_dir)]
        if model is not None:
            argv += ["--model", model]
        if rules_mode is not None:
            argv += ["--rules-mode", rules_mode]
        run_blue.main(argv, client=client)

    def judge_rounds(self, match_dir: Path) -> None:
        round_record.main(["--run-dir", str(match_dir)])

    def judge_benign(self, match_dir: Path) -> None:
        fact4_benign.main(["--run-dir", str(match_dir)])

    def judge_red(self, match_dir: Path) -> None:
        red_facts.main(["--run-dir", str(match_dir)])

    def judge_rules(self, match_dir: Path) -> None:
        rule_facts.main(["--run-dir", str(match_dir)])


def _fallback_freeze(ops: Ops, live_dir: Path, match_dir: Path, out) -> str:
    """Finalize after a failed freeze. Never leave this match's log in live/: move it
    with a plain rename if it is still there, then try one best-effort nginx reopen.
    The log is "not frozen" only if that reopen also fails (nginx may then keep
    appending to the moved file until the next rotate). Returns text for `error`."""
    src, dst = live_dir / "proxy.jsonl", match_dir / "proxy.jsonl"
    note = ""
    if src.exists() and not dst.exists():
        try:
            src.replace(dst)
            note += " | fallback: proxy log moved to the match dir"
        except OSError as exc:
            return f" | fallback: proxy log left in live/: {exc}"
    if not dst.exists():
        return note + " | fallback: no proxy log to move"
    try:
        ops.reopen(live_dir)
    except Exception as exc:  # noqa: BLE001
        out(f"WARNING: best-effort nginx reopen failed: {exc}")
        return (note + f" | best-effort nginx reopen failed ({type(exc).__name__}: "
                f"{exc}): proxy log NOT FROZEN, nginx may keep appending to it until "
                f"the next rotate")
    out(f"proxy log frozen by fallback: {_display_path(dst)}")
    return note + " | best-effort nginx reopen succeeded: proxy log frozen"


def run_match(ops: Ops | None = None, live_dir: Path = match_ops.LIVE,
              runs_dir: Path = match_ops.RUNS, payloads: Path = scripted_red.PAYLOADS,
              benign_set: Path = send_benign.BENIGN_SET, seed: int | None = None,
              settle: float = 3.0, engine: str = "scripted", blue_model: str | None = None,
              red_engine: str = "scripted", red_model: str | None = None,
              blue_rules_mode: str | None = None,
              out=print) -> tuple[int, Path | None]:
    """Run one match. Returns (exit_code, match_dir or None if never started)."""
    ops = ops or Ops()

    # 1. Preflight (no match exists yet: on failure, nothing to finalize).
    try:
        images = ops.preflight()
        match_ops.check_live_clean(live_dir)
        llm_config, prices, price_ref = ops.llm_setup()
        attacks = scripted_red.load_attacks(payloads)
        bset = send_benign.load_set(benign_set)  # BenignSetError is a ValueError
        seed_source = "generated" if seed is None else "cli"
        seed = new_seed() if seed is None else seed
        benign_ids = [e["benign_id"] for e in bset["entries"]]
        if red_engine not in ("scripted", "ai"):
            raise ValueError(f"unknown Red engine {red_engine!r}")
        if red_engine == "ai":
            red_m = red_model or llm_config["agents"]["red"]["model"]
            if not red_m:
                raise ValueError("no Red model: set agents.red.model in config/llm.json "
                                 "or pass --red-model")
            n_red = ai_red.round_cap_of(llm_config)
            red_params = ai_red.red_params(llm_config, red_m)
            red_source = None
            red_models = {"red": {"provider": red_params["provider"], "model": red_m}}
        else:
            red_m, red_params = None, None
            n_red = len(attacks)
            red_source = {"path": _display_path(payloads), "sha256": sha256_file(payloads)}
            red_models = {"red": None}
        schedule = Schedule(n_red, benign_ids, seed)  # ValueError on a bad seed
        provenance = {"git": ops.git_info()}
        if engine not in run_blue.ENGINE_NAMES:
            raise ValueError(f"unknown Blue engine {engine!r}")
        if engine == "claude":
            model = run_blue.blue_model(llm_config, blue_model)  # ConfigError: a ValueError
            chunk = run_blue.blue_chunk_size(llm_config)
            if chunk != 1:
                raise ValueError(f"agents.blue.chunk_size is {chunk}: a scored match is one "
                                 f"line per call (D4); chunk_size > 1 is for unscored runs")
            blue_params = claude_engine.blue_params(llm_config, model, chunk,
                                                    blue_rules_mode)  # ValueError: bad mode
            rules_mode = blue_params["rules"]["mode"]
            models = {**red_models, "blue": {"provider": blue_params["provider"],
                                             "model": model}, "analyst": None}
        else:
            if blue_rules_mode not in (None, "off"):
                raise ValueError("--blue-rules-mode needs --blue claude (rule invention is "
                                 "an AI Blue feature)")
            model, blue_params, rules_mode = None, None, None
            models = {**red_models, "blue": None, "analyst": None}
        traffic = {"seed": seed, "seed_source": seed_source,
                   "benign_set": {"path": _display_path(benign_set),
                                  "sha256": sha256_file(benign_set),
                                  "set_version": bset["set_version"]},
                   "schedule": schedule.planned_labels()}
    except (match_ops.PreflightError, OSError, subprocess.CalledProcessError, ValueError,
            ValidationError) as exc:
        out(f"PREFLIGHT FAILED: {llm_client.redact(str(exc))}")
        return 2, None

    # 2-3. Lock, then the match exists.
    match_id = new_match_id()
    try:
        match_ops.acquire_lock(live_dir, match_id)
    except match_ops.LockHeld as exc:
        out(f"REFUSING TO START: {exc}")
        return 3, None

    match_dir = runs_dir / match_id
    try:
        match_dir.mkdir(parents=True, exist_ok=False)
    except OSError:
        match_ops.release_lock(live_dir)
        raise
    started_at = match_ops.utc_now()
    out(f"match {match_id} -> {_display_path(match_dir)}")
    out(f"seed {seed} ({seed_source}): {len(attacks)} Red + {len(benign_ids)} benign slots")

    failed_step: str | None = None
    error: str | None = None
    rotated = frozen = False
    step = "reset"
    try:
        solved = ops.reset()
        out(f"target reset: {solved} challenges solved")
        if solved != 0:
            raise RuntimeError(f"refusing to run: target not clean after reset "
                               f"({solved} challenges still solved)")

        step = "rotate"
        archived = ops.rotate(live_dir)
        rotated = True
        if archived is not None:
            out(f"previous proxy log archived: {_display_path(archived)}")

        step = "traffic"
        red_driver = None
        if red_engine == "ai":
            red = ai_red.AIRed(ops.red_client(llm_config, prices), red_m, match_dir,
                               match_id, n_red)
            red_driver = match_ops.AIDriver(red)
        ops.traffic(match_id, match_dir, attacks, bset["entries"], schedule, settle,
                    red_driver=red_driver)

        step = "freeze"
        ops.freeze(live_dir, match_dir)
        frozen = True
        out(f"proxy log frozen: {_display_path(match_dir / 'proxy.jsonl')}")

        step = "judge_fact1"
        ops.judge_fact1(match_dir)
        step = "blue"
        if engine == "claude":
            ops.blue(match_dir, match_id, engine, ops.blue_client(llm_config, prices), model,
                     rules_mode)
        else:
            ops.blue(match_dir, match_id, engine)
        step = "judge_rounds"
        ops.judge_rounds(match_dir)
        step = "judge_benign"
        ops.judge_benign(match_dir)
        step = "judge_red"
        ops.judge_red(match_dir)
        step = "judge_rules"
        ops.judge_rules(match_dir)
        step = "done"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - finalize on ANY failure
        failed_step = step
        error = llm_client.redact(f"{type(exc).__name__}: {exc}")
        out(f"MATCH FAILED at step '{step}': {error}")
        out(llm_client.redact(traceback.format_exc().rstrip()))
        # Only this match's artifacts move. The proxy log is this match's once it was
        # rotated; before that, live/proxy.jsonl is earlier traffic and stays for the
        # next rotation to archive.
        if rotated and not frozen:
            try:
                ops.freeze(live_dir, match_dir)
                out(f"proxy log moved to {_display_path(match_dir / 'proxy.jsonl')}")
            except Exception as fexc:  # noqa: BLE001
                error += llm_client.redact(f" | finalize could not freeze the proxy log: "
                                           f"{type(fexc).__name__}: {fexc}")
                out(f"WARNING: could not freeze the proxy log: {llm_client.redact(str(fexc))}")
                error += llm_client.redact(_fallback_freeze(ops, live_dir, match_dir, out))

    # 9. match.json, written LAST, then release the lock.
    try:
        calls = cost_stats.read_calls(match_dir / llm_client.API_CALLS)
        stop = llm_client.stopped_by(calls, prices)
        status = "failed" if failed_step is not None else \
            "stopped" if stop is not None else "completed"
        manifest = {
            "schema_version": MANIFEST_VERSION,
            "match_id": match_id,
            "started_at": started_at,
            "finished_at": match_ops.utc_now(),
            "status": status,
            "failed_step": failed_step,
            "error": error,
            "judge_version": JUDGE_VERSION,
            "blue_engine": engine,
            "blue_params": blue_params,
            "red_engine": red_engine,
            "red_params": red_params,
            "red_source": red_source,
            **provenance,
            "traffic": traffic,
            "images": images,
            # Scripted components call no model; AI Blue fills models.blue (5.4).
            "models": models,
            "budget": {"limits": llm_client.caps_limits(llm_config), "stopped_by": stop},
            "price_table": price_ref,
            "cost": cost_stats.summarize(calls, prices),
            "artifacts": artifact_hashes(match_dir),
        }
        (match_dir / "match.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                              encoding="utf-8")
        schema_errors = validate_manifest(manifest)
    finally:
        match_ops.release_lock(live_dir)

    if schema_errors:
        out(f"BUG: match.json is schema-invalid: {schema_errors}")
        return 1, match_dir

    # 10. Summary: pure read of the frozen artifacts.
    out("")
    out(match_stats.format_summary(
        match_stats.read_rounds(match_dir / "rounds.jsonl"), manifest,
        benign=match_stats.read_rounds(match_dir / fact4_benign.RESULTS),
        anomalies=match_stats.read_rounds(match_dir / fact4_benign.ANOMALIES),
        verdicts=match_stats.read_rounds(match_dir / "verdicts.jsonl"),
        red_unsent=match_stats.read_rounds(match_dir / match_ops.RED_UNSENT),
        challenge_map=json.loads(red_facts.CHALLENGE_MAP.read_text(encoding="utf-8")),
        rules=(match_stats.read_rounds(match_dir / "rules.jsonl"),
               match_stats.read_rounds(match_dir / "rule_rejections.jsonl"),
               match_stats.read_rounds(match_dir / rule_facts.RESULTS))))
    return EXIT[manifest["status"]], match_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one complete match.")
    parser.add_argument("--payloads", type=Path, default=scripted_red.PAYLOADS)
    parser.add_argument("--benign-set", type=Path, default=send_benign.BENIGN_SET)
    parser.add_argument("--seed", type=int, default=None,
                        help="schedule seed (0..2^32-1); reproduces a match's interleaving. "
                             "Without it a seed is generated and recorded in match.json")
    parser.add_argument("--blue", choices=run_blue.ENGINE_NAMES, default="scripted",
                        help="Blue engine: scripted signatures, or claude (AI Blue: real, "
                             "paid API calls through agents/llm_client.py)")
    parser.add_argument("--blue-model", default=None,
                        help="claude: model id (default: config/llm.json agents.blue.model)")
    parser.add_argument("--blue-rules-mode", choices=("off", "shadow", "on"), default=None,
                        help="claude: rule invention mode (default: config/llm.json "
                             "agents.blue.rules.mode). off = prompt v1 (Stage 5.4); shadow = "
                             "prompt v2, rules recorded and scored, never applied; on = "
                             "prompt v2, rules hot-loaded")
    parser.add_argument("--red", choices=("scripted", "ai"), default="scripted",
                        help="Red engine: scripted payload set, or ai (OpenAI; real, paid "
                             "API calls through agents/llm_client.py)")
    parser.add_argument("--red-model", default=None,
                        help="ai: model id (default: config/llm.json agents.red.model)")
    parser.add_argument("--settle", type=float, default=3.0,
                        help="max seconds to wait for a solve to register")
    args = parser.parse_args(argv)
    code, _ = run_match(payloads=args.payloads, benign_set=args.benign_set, seed=args.seed,
                        settle=args.settle, engine=args.blue, blue_model=args.blue_model,
                        red_engine=args.red, red_model=args.red_model,
                        blue_rules_mode=args.blue_rules_mode)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
