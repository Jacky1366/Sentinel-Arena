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
ANALYST_CAP = {"max_calls": 12, "max_tokens": 600000, "max_usd": 1.0}
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


def report(env=None, model: str | None = None, manifest: Path = build_summary.MANIFEST,
           out: Path = OUT, client_factory=None, summary: dict | None = None,
           publish: bool = True, dash: Path = DASH_REPORT) -> dict:
    env = os.environ if env is None else env
    msg = go_token.check(RUN_TOKEN, env)
    if msg:
        raise PermissionError(msg)
    base = lc.load_config()
    model = model or base["agents"]["analyst"].get("model")
    cand = next((c for c in CANDIDATES if c["model"] == model), None)
    if cand is None:
        raise ValueError(f"no analyst model (set agents.analyst.model or --model); got {model!r}")
    run_id = run_match.new_match_id()
    run_dir = out / f"report-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    summary = summary if summary is not None else build_the_summary(manifest, env, run_dir)
    if not (run_dir / "summary.json").exists():
        _write(run_dir / "summary.json", summary)
    prices = cost_mod.load_prices()
    cfg = analyst_config(base, cand)
    client = client_factory(cfg) if client_factory else lc.LLMClient(config=cfg, prices=prices)
    o = draft_mod.run(client, model, summary, run_dir, match_id=run_id)
    meta = {"report_id": run_dir.name, "run_id": run_id, "model": model, "provider": cand["provider"],
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "prompt_version": draft_mod.PROMPT_VERSION, "prompt_sha256": draft_mod.prompt_sha256(),
            "attempts": o.attempts, "stop": o.stop, "go_token": RUN_TOKEN, "log": o.log,
            "cost_usd": cost_mod.summarize(cost_mod.read_calls(run_dir / lc.API_CALLS),
                                           prices)["total_usd"],
            "template_sha256": render.template_sha256()}
    _write(run_dir / "meta.json", meta)
    if o.draft is not None:
        _write(run_dir / "draft.json", o.draft)
    if o.grounding is not None:
        _write(run_dir / "grounding_result.json", o.grounding)
    if not o.ok:
        return {**meta, "ok": False, "run_dir": str(run_dir)}
    html = render.render(summary, o.draft, o.grounding, meta)
    (run_dir / "report.html").write_text(html, encoding="utf-8")
    if publish:
        publish_dashboard(html, meta, dash)
    return {**meta, "ok": True, "run_dir": str(run_dir)}


def publish_dashboard(html: str, meta: dict, dash: Path = DASH_REPORT) -> None:
    """report.html (opened by "print / save PDF") + report.js (window.ARENA_REPORT, a
    classic script read by the Report tab)."""
    dash.mkdir(parents=True, exist_ok=True)
    (dash / "report.html").write_text(html, encoding="utf-8")
    keep = {k: meta[k] for k in ("report_id", "model", "provider", "date", "attempts",
                                 "cost_usd", "prompt_sha256", "template_sha256")}
    js = ("// GENERATED by tools/build_report.py — do not edit.\n"
          f"window.ARENA_REPORT = {json.dumps({'meta': keep, 'html': html}, ensure_ascii=False)};\n")
    (dash / "report.js").write_text(js, encoding="utf-8")


def rerender(folder: Path, publish: bool = False, dash: Path = DASH_REPORT) -> Path:
    j = lambda n: json.loads((folder / n).read_text(encoding="utf-8"))  # noqa: E731
    html = render.render(j("summary.json"), j("draft.json"), j("grounding_result.json"), j("meta.json"))
    (folder / "report.html").write_text(html, encoding="utf-8")
    if publish:
        publish_dashboard(html, j("meta.json"), dash)
    return folder / "report.html"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="The analyst report (Stage 7 #17).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--probe", action="store_true")
    g.add_argument("--run", action="store_true")
    g.add_argument("--render", type=Path, default=None)
    ap.add_argument("--model", default=None)
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
        r = report(model=args.model)
        print(f"report {r['report_id']}: ok={r['ok']} stop={r['stop']} attempts={r['attempts']} "
              f"${r['cost_usd']:.6f} -> {r['run_dir']}")
        return 0 if r["ok"] else 1
    except PermissionError as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
