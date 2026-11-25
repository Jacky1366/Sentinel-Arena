"""The analyst report (Stage 7 #17; D53-D57, D60). PAID + TEST-SET: every real mode needs the
designer's exact GO token for that mode.

    ARENA_GO=manual-analyst-probe  .venv/bin/python tools/build_report.py --probe
    ARENA_GO=manual-analyst-report .venv/bin/python tools/build_report.py --run [--model M]
    .venv/bin/python tools/build_report.py --render <report folder>      # zero token

--probe   builds the summary (D59 + GO), then ONE analyst call per candidate in order
          (gpt-6.1-sol, gpt-6.1-terra, gpt-5.6-sol, then the claude-sonnet-5-5 fallback),
          stopping at the first schema-valid draft. Writes data/runs/analyst/probe-<ts>/.
--run     builds the summary, runs the analyst loop (draft -> grounding check -> retry with
          the errors, max 3), renders the report and writes data/runs/analyst/report-<ts>/.
          It is committed under data/golden/analyst-report-7/ only after the designer has
          read the text (D60 c).
--render  re-renders report.html from a report folder (summary + draft + grounding + meta).

The analyst cap is $1 for the whole run folder (D53): agents.analyst and the match cap are
both set to $1 for analyst runs. Every call goes through agents/llm_client.py.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from agents import llm_client as lc  # noqa: E402
from analyst import draft as draft_mod  # noqa: E402
from analyst import grounding, render  # noqa: E402
from analyst import summary as summary_mod  # noqa: E402
from judge import JUDGE_VERSION  # noqa: E402
import run_match  # noqa: E402  (new_match_id: ledger lines need a match-id-shaped id)
from runner import go_token  # noqa: E402
from stats import cost as cost_mod  # noqa: E402
from tools import build_summary  # noqa: E402

OUT = REPO / "data" / "runs" / "analyst"
DASH_REPORT = REPO / "dashboard" / "public" / "report"
PROBE_TOKEN, RUN_TOKEN = "manual-analyst-probe", "manual-analyst-report"
CANDIDATES = [  # designer Q1 (2026-11-24): this order, stop at the first that accepts
    {"model": "gpt-6.1-sol", "provider": "openai", "request": {"effort": "medium"}},
    {"model": "gpt-6.1-terra", "provider": "openai", "request": {"effort": "medium"}},
    {"model": "gpt-5.6-sol", "provider": "openai", "request": {"effort": "medium"}},
    {"model": "claude-sonnet-5-5", "provider": "anthropic",
     "request": {"thinking": "between_tools"}},  # Sonnet rejects "disabled" (6.3 Gate A)
]
# designer (2026-11-24): gpt-6.1-sol, falling back in order to gpt-6.1-terra, then claude-sonnet-5-5
REPORT_ORDER = ("gpt-6.1-sol", "gpt-6.1-terra", "claude-sonnet-5-5")
ANALYST_CAP = {"max_calls": 12, "max_tokens": 600000, "max_usd": 1.0}


class LedgerPreflightError(ValueError):
    """A ledger record for this run would be refused: raised BEFORE any paid call."""


def preflight_ledger(run_id: str, cands, prices: dict | None = None) -> None:
    """Validate complete api_calls.jsonl records (success and failure shapes) for every
    model this run may call, against api_call.schema.json, BEFORE any client is built.
    Root-cause fix for the 2026-11-24 incident: a paid call whose ledger line was refused
    afterwards went unrecorded. agents/llm_client.py is unchanged; this mirrors its lines."""
    prices = prices if prices is not None else cost_mod.load_prices()
    ts = lc.utc_now()
    for cand in cands:
        base = {"schema_version": "0.2", "match_id": run_id, "timestamp": ts, "agent": "analyst",
                "provider": cand["provider"], "model": cand["model"], "round": None,
                "log_seq_first": None, "log_seq_last": None, "attempt": 1,
                "prompt_sha256": draft_mod.prompt_sha256()}
        entry = cost_mod.entry_for(prices, cand["model"])
        if entry is None or entry.get("verified") is not True:
            raise LedgerPreflightError(f"{cand['model']}: no verified price entry")
        if entry.get("peak") is not None:
            base["rate_window"] = cost_mod.rate_window(entry, ts)
        ok = {**base, "ok": True, "error_type": None, "http_status": 200, "refusal": None,
              "stop_reason": "end_turn", "input_tokens": 1, "cached_input_tokens": 0,
              "cache_write_tokens": 0, "unpriced_cache_write_tokens": 0, "output_tokens": 1,
              "latency_ms": 1}
        fail = {**base, "ok": False, "error_type": "timeout", "http_status": None, "refusal": None,
                "stop_reason": None, "input_tokens": None, "cached_input_tokens": None,
                "cache_write_tokens": None, "unpriced_cache_write_tokens": None,
                "output_tokens": None, "error_excerpt": "x", "latency_ms": 1}
        for line in (ok, fail):
            errors = [e.message for e in lc.API_CALL_SCHEMA.iter_errors(line)]
            if errors:
                raise LedgerPreflightError(
                    f"REFUSED before any paid call: a ledger record for {cand['model']} would be "
                    f"invalid: {errors[:3]}")
MAX_OUTPUT = 16384
TIMEOUT_S = 300


def analyst_config(base: dict, cand: dict) -> dict:
    cfg = copy.deepcopy(base)
    a = cfg["agents"]["analyst"]
    a.update(provider=cand["provider"], model=cand["model"], request=dict(cand["request"]),
             max_output_tokens=MAX_OUTPUT, timeout_s=TIMEOUT_S, caching="off")
    cfg["caps"]["analyst"] = dict(ANALYST_CAP)
    cfg["caps"]["match"] = {**cfg["caps"]["match"], "max_usd": ANALYST_CAP["max_usd"]}
    return cfg


def now_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write(p: Path, obj) -> None:
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_the_summary(manifest: Path, env, run_dir: Path) -> dict:
    m = json.loads(manifest.read_text(encoding="utf-8"))
    refusal = build_summary.gate(m, env)
    if refusal:
        raise PermissionError(refusal)
    doc = summary_mod.build(m, prices=cost_mod.load_prices(), git=build_summary._git(),
                            judge_version=JUDGE_VERSION, manifest_path=manifest)
    errs = build_summary.validate(doc)
    if errs:
        raise RuntimeError(f"summary is schema-invalid: {errs[:3]}")
    _write(run_dir / "summary.json", doc)
    return doc


def _calls_for(run_dir: Path, model: str, prices: dict) -> dict:
    calls = [c for c in cost_mod.read_calls(run_dir / lc.API_CALLS) if c["model"] == model]
    s = cost_mod.summarize(calls, prices)
    return {"attempts": s["attempts"], "usd": s["total_usd"], "tokens": s["tokens"]}


def probe(env=None, manifest: Path = build_summary.MANIFEST, out: Path = OUT,
          client_factory=None, summary: dict | None = None) -> dict:
    """One call per candidate; stop at the first schema-valid draft. client_factory (tests):
    cfg -> client."""
    env = os.environ if env is None else env
    msg = go_token.check(PROBE_TOKEN, env)
    if msg:
        raise PermissionError(msg)
    run_id = run_match.new_match_id()  # api_call.schema.json: a match-id-shaped id
    preflight_ledger(run_id, CANDIDATES)  # before any folder, summary read or paid call
    run_dir = out / f"probe-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    summary = summary if summary is not None else build_the_summary(manifest, env, run_dir)
    prices = cost_mod.load_prices()
    base = lc.load_config()
    results, chosen = [], None
    for cand in CANDIDATES:
        cfg = analyst_config(base, cand)
        client = client_factory(cfg) if client_factory else lc.LLMClient(config=cfg, prices=prices)
        o = draft_mod.run(client, cand["model"], summary, run_dir, max_attempts=1,
                          match_id=run_id)
        codes = sorted({e["code"] for e in (o.grounding or {}).get("errors", [])})
        schema_valid = o.draft is not None and o.grounding is not None and "schema" not in codes
        r = {"model": cand["model"], "provider": cand["provider"], "request": cand["request"],
             "stop": o.stop, "schema_valid": schema_valid,
             "grounding_ok": bool(o.grounding and o.grounding["ok"]),
             "grounding_error_codes": codes,
             "grounding_errors": len((o.grounding or {}).get("errors", [])),
             "log": o.log, **_calls_for(run_dir, cand["model"], prices)}
        results.append(r)
        if o.draft is not None:
            _write(run_dir / f"draft-{cand['model']}.json", o.draft)
        if o.grounding is not None:
            _write(run_dir / f"grounding-{cand['model']}.json", o.grounding)
        if schema_valid:
            chosen = cand["model"]
            break
    total = cost_mod.summarize(cost_mod.read_calls(run_dir / lc.API_CALLS), prices)["total_usd"]
    doc = {"probe_id": run_dir.name, "run_id": run_id, "go_token": PROBE_TOKEN, "chosen": chosen,
           "prompt_version": draft_mod.PROMPT_VERSION,
           "prompt_sha256": draft_mod.prompt_sha256(), "results": results,
           "total_usd": total, "summary_figures": len(summary["figures"])}
    _write(run_dir / "probe.json", doc)
    return {**doc, "run_dir": str(run_dir)}


def report(env=None, models=None, manifest: Path = build_summary.MANIFEST,
           out: Path = OUT, client_factory=None, summary: dict | None = None,
           publish: bool = False, dash: Path = DASH_REPORT) -> dict:
    """The report run: the analyst loop (max 3 attempts per model) with the designer's
    fallback order, all inside ONE run folder (one $1 cap). Renders on the first grounded
    draft. publish=False by default: nothing in the repo changes until the designer has read
    the report (then --render <folder> --publish)."""
    env = os.environ if env is None else env
    msg = go_token.check(RUN_TOKEN, env)
    if msg:
        raise PermissionError(msg)
    models = list(models or REPORT_ORDER)
    cands = []
    for m in models:
        c = next((c for c in CANDIDATES if c["model"] == m), None)
        if c is None:
            raise ValueError(f"unknown analyst model {m!r}")
        cands.append(c)
    run_id = run_match.new_match_id()
    preflight_ledger(run_id, cands)  # before any folder, summary read or paid call
    run_dir = out / f"report-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    summary = summary if summary is not None else build_the_summary(manifest, env, run_dir)
    if not (run_dir / "summary.json").exists():
        _write(run_dir / "summary.json", summary)
    prices = cost_mod.load_prices()
    base = lc.load_config()
    tried, o, cand = [], None, None
    for cand in cands:
        cfg = analyst_config(base, cand)
        client = client_factory(cfg) if client_factory else lc.LLMClient(config=cfg, prices=prices)
        o = draft_mod.run(client, cand["model"], summary, run_dir, match_id=run_id)
        tried.append({"model": cand["model"], "stop": o.stop, "attempts": o.attempts, "log": o.log,
                      **_calls_for(run_dir, cand["model"], prices)})
        if o.draft is not None:
            _write(run_dir / f"draft-{cand['model']}.json", o.draft)
        if o.ok or o.stop == "refused" and o.log and o.log[-1].get("refusal"):
            break  # accepted, or the body's cap refused: no point trying the next model
    meta = {"report_id": run_dir.name, "run_id": run_id, "model": cand["model"],
            "provider": cand["provider"], "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "prompt_version": draft_mod.PROMPT_VERSION, "prompt_sha256": draft_mod.prompt_sha256(),
            "attempts": o.attempts, "stop": o.stop, "go_token": RUN_TOKEN, "tried": tried,
            "cost_usd": cost_mod.summarize(cost_mod.read_calls(run_dir / lc.API_CALLS),
                                           prices)["total_usd"],
            "template_sha256": render.template_sha256()}
    _write(run_dir / "meta.json", meta)
    if o.ok:
        _write(run_dir / "draft.json", o.draft)
        _write(run_dir / "grounding_result.json", o.grounding)
        html = render.render(summary, o.draft, o.grounding, meta)
        brief = render.render(summary, o.draft, o.grounding, meta, brief=True)
        (run_dir / "report.html").write_text(html, encoding="utf-8")
        (run_dir / "brief.html").write_text(brief, encoding="utf-8")
        if publish:
            publish_dashboard(html, meta, dash, brief)
    elif o.grounding is not None:
        _write(run_dir / "grounding_result.json", o.grounding)
    return {**meta, "ok": o.ok, "run_dir": str(run_dir)}


def publish_dashboard(html: str, meta: dict, dash: Path = DASH_REPORT, brief: str = "") -> None:
    """brief.html + report.html (each opened by its "print / save PDF" link) + report.js
    (window.ARENA_REPORT = {meta, brief, html}, a classic script read by the Report tab)."""
    dash.mkdir(parents=True, exist_ok=True)
    (dash / "report.html").write_text(html, encoding="utf-8")
    (dash / "brief.html").write_text(brief, encoding="utf-8")
    keep = {k: meta[k] for k in ("report_id", "model", "provider", "date", "attempts",
                                 "cost_usd", "prompt_sha256", "template_sha256")}
    js = ("// GENERATED by tools/build_report.py — do not edit.\n"
          f"window.ARENA_REPORT = {json.dumps({'meta': keep, 'brief': brief, 'html': html}, ensure_ascii=False)};\n")
    (dash / "report.js").write_text(js, encoding="utf-8")


def rerender(folder: Path, publish: bool = False, dash: Path = DASH_REPORT) -> Path:
    j = lambda n: json.loads((folder / n).read_text(encoding="utf-8"))  # noqa: E731
    args = (j("summary.json"), j("draft.json"), j("grounding_result.json"), j("meta.json"))
    html, brief = render.render(*args), render.render(*args, brief=True)
    (folder / "report.html").write_text(html, encoding="utf-8")
    (folder / "brief.html").write_text(brief, encoding="utf-8")
    if publish:
        publish_dashboard(html, j("meta.json"), dash, brief)
    return folder / "report.html"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="The analyst report (Stage 7 #17).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--probe", action="store_true")
    g.add_argument("--run", action="store_true")
    g.add_argument("--render", type=Path, default=None)
    ap.add_argument("--models", default=None,
                    help="comma-separated fallback order (default: gpt-6.1-sol,gpt-6.1-terra,claude-sonnet-5-5)")
    ap.add_argument("--publish", action="store_true", help="--render: also update the dashboard")
    args = ap.parse_args(argv)
    try:
        if args.render:
            print(f"rendered {rerender(args.render, args.publish)}")
            return 0
        if args.probe:
            r = probe()
            for x in r["results"]:
                print(f"  {x['model']:<18} stop={x['stop']:<17} schema_valid={x['schema_valid']} "
                      f"grounding_ok={x['grounding_ok']} errors={x['grounding_errors']} "
                      f"{x['grounding_error_codes']} ${x['usd']:.6f}")
            print(f"probe {r['probe_id']}: chosen={r['chosen']} total ${r['total_usd']:.6f} -> {r['run_dir']}")
            return 0 if r["chosen"] else 1
        r = report(models=args.models.split(",") if args.models else None)
        for t in r["tried"]:
            print(f"  {t['model']:<18} stop={t['stop']:<17} attempts={t['attempts']} ${t['usd']:.6f}")
        print(f"report {r['report_id']}: ok={r['ok']} model={r['model']} ${r['cost_usd']:.6f} -> {r['run_dir']}")
        return 0 if r["ok"] else 1
    except PermissionError as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
