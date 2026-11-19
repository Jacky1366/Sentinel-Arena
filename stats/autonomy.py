"""The autonomy table (Stage 6.2, M6). PURE: no network, no file access; the caller
(tools/autonomy_table.py) loads the frozen folders. Zero tokens.

One table per ARM (a list of frozen match / replay folders), rows CWE-89 / CWE-79 /
CWE-22 / total:

  detection          raw, and the D16 audited view (null when any folder's audit is
                     incomplete); attack rounds Red labelled with the row's CWE
                     (match_stats.detection_rate: orphans and instrument failures excluded)
  type_correct       match_stats.type_accuracy over the same rounds (raw)
  verdict_fp         benign lines whose verdict is the row's CWE, over all scored benign
                     lines (match_stats.fp_rate denominator); total row = any FP
  rule_coverage      share of verdicts with source "rule", split by rule_origin
                     (library / match; a pre-0.4 rule verdict has no origin and counts as
                     match). CWE row: verdicts on that CWE's attack lines; total row: every
                     verdict line, attack and benign
  ai_calls, cost_usd CWE row: Blue calls attributed to a line via log_seq_first (chunk
                     size 1, D4); total row: every sent call of every agent (Red too)

Every rate is k/n; for k = 0 the exact Clopper-Pearson 95% (two-sided) upper bound,
1 - 0.025^(1/n), is added. Nothing here judges: every input is a Judge or Blue artifact.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from rules import engine
from rules import library as rule_library
from stats import cost as cost_mod
from stats import match_stats as ms

CWES = ("CWE-89", "CWE-79", "CWE-22")
TABLE_VERSION = "1"


@dataclass
class Folder:
    name: str                        # display path
    rounds: list[dict]               # rounds.jsonl
    benign: list[dict]               # benign_results.jsonl
    verdicts: list[dict]             # verdicts.jsonl
    calls: list[dict]                # api_calls.jsonl ([] for scripted Blue)
    audit_rows: list[dict]           # D16 audit lines ([] when none)
    scripted: set[int] = field(default_factory=set)   # valid by construction
    anomalies: list[dict] = field(default_factory=list)


def cp_upper_zero(n: int) -> float:
    """Exact Clopper-Pearson two-sided 95% upper bound for 0 successes in n trials."""
    return 1.0 - 0.025 ** (1.0 / n)


def rate(k: int, n: int) -> dict:
    out = {"k": k, "n": n, "pct": None if n == 0 else round(100.0 * k / n, 1)}
    if k == 0 and n > 0:
        out["upper95"] = round(cp_upper_zero(n), 4)
    return out


def _sum(rates: list[ms.Rate]) -> tuple[int, int]:
    return sum(r.num for r in rates), sum(r.den for r in rates)


def _audited(f: Folder) -> list[dict] | None:
    return ms.apply_audit(f.rounds, f.audit_rows, f.scripted)["rounds"]


def _labels(f: Folder) -> dict[str, str]:
    """request_id -> Red label (attack lines) or "benign"."""
    out = {r["request_id"]: r["label"] for r in f.rounds}
    out.update({b["request_id"]: "benign" for b in f.benign})
    return out


def _coverage(verdicts: list[dict]) -> dict:
    rule = [v for v in verdicts if v.get("source") == "rule"]  # 0.1 rows: no source
    lib = sum(v.get("rule_origin") == "library" for v in rule)
    n = len(verdicts)
    return {"rule": rate(len(rule), n), "library": rate(lib, n),
            "match": rate(len(rule) - lib, n)}


def arm_table(folders: list[Folder], prices: dict) -> dict:
    """{"rows": {CWE..., "total"}, "tripwires": {...}} for one arm."""
    rows: dict[str, dict] = {}
    audited = [_audited(f) for f in folders]
    audit_complete = all(a is not None for a in audited)
    for cwe in (*CWES, "total"):
        keep = (lambda r: True) if cwe == "total" else (lambda r, c=cwe: r["label"] == c)
        det = _sum([ms.detection_rate([r for r in f.rounds if keep(r)]) for f in folders])
        typ = _sum([ms.type_accuracy([r for r in f.rounds if keep(r)]) for f in folders])
        det_a = _sum([ms.detection_rate([r for r in a if keep(r)]) for a in audited]) \
            if audit_complete else None
        fp_n = sum(ms.fp_rate(f.benign).den for f in folders)
        fp_k = sum(1 for f in folders for b in f.benign if b["fp_reason"] is None
                   and b["false_positive"] is True and (cwe == "total" or b["verdict"] == cwe))
        verdicts, calls, usd = [], 0, 0.0
        for f in folders:
            labels = _labels(f)
            vs = [v for v in f.verdicts
                  if cwe == "total" or labels.get(v["request_id"]) == cwe]
            verdicts += vs
            if cwe == "total":
                s = cost_mod.summarize(f.calls, prices)
                calls += s["attempts"]
                usd += s["total_usd"]
                continue
            seq_label = {v["log_seq"]: labels.get(v["request_id"]) for v in f.verdicts}
            for c in f.calls:
                if c["agent"] == "blue" and cost_mod.is_sent(c) \
                        and seq_label.get(c.get("log_seq_first")) == cwe:
                    calls += 1
                    usd += cost_mod.call_cost(c, prices)["usd"]
        rows[cwe] = {"detection_raw": rate(*det),
                     "detection_audited": None if det_a is None else rate(*det_a),
                     "type_correct": rate(*typ), "verdict_fp": rate(fp_k, fp_n),
                     "rule_coverage": _coverage(verdicts),
                     "ai_calls": calls, "cost_usd": round(usd, 6)}
    counts: Counter = Counter()
    kinds: Counter = Counter()
    for f in folders:
        counts.update(ms.counts(f.rounds))
        kinds.update(a["kind"] for a in f.anomalies)
    return {"folders": [f.name for f in folders], "audit_complete": audit_complete,
            "rows": rows, "tripwires": {"counts": dict(sorted(counts.items())),
                                        "anomalies": dict(sorted(kinds.items()))}}


def library_fp(lib: rule_library.Library, sets: dict[str, list[dict]]) -> dict:
    """Per library rule: hits on each offline benign set (rows with method/path/query/
    body and benign_id). A hit is the rule ALONE firing (no hot-load)."""
    forms = {name: [(r["benign_id"], engine.forms(engine.Request.from_log(r))) for r in rows]
             for name, rows in sets.items()}
    out = {}
    for e in lib.entries:
        row: dict = {"cwe": e.cwe}
        for name, fs in forms.items():
            hits = [bid for bid, fm in fs if engine.fires(e.validated, fm)]
            row[name] = {**rate(len(hits), len(fs)), "hits": hits}
        out[e.library_id] = row
    return out


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------

def fmt_rate(r: dict | None) -> str:
    if r is None:
        return "—"
    if r["n"] == 0:
        return "0/0"
    s = f"{r['k']}/{r['n']} ({r['pct']:.0f}%)"
    if "upper95" in r:
        s += f" ≤{100 * r['upper95']:.1f}%"
    return s


def markdown(doc: dict) -> str:
    out = [f"# {doc['title']}", "",
           f"*Generated by `tools/autonomy_table.py` (table version {doc['table_version']}, "
           f"zero tokens). Every rate is k/n; for 0/n, `≤x%` is the exact Clopper–Pearson "
           f"95% upper bound. Definitions: `stats/autonomy.py`, contract §6.13.*", ""]
    for name, arm in doc["arms"].items():
        out += [f"## {name}", "", f"Folders: {', '.join(f'`{x}`' for x in arm['folders'])}",
                "", "| | detection raw | detection audited | type-correct | verdict FP | "
                "rule coverage (library / match) | AI calls | cost |",
                "|---|---|---|---|---|---|---|---|"]
        for row, r in arm["rows"].items():
            cov = r["rule_coverage"]
            out.append(f"| {row} | {fmt_rate(r['detection_raw'])} | "
                       f"{fmt_rate(r['detection_audited'])} | {fmt_rate(r['type_correct'])} | "
                       f"{fmt_rate(r['verdict_fp'])} | {fmt_rate(cov['rule'])} "
                       f"({cov['library']['k']} / {cov['match']['k']}) | {r['ai_calls']} | "
                       f"${r['cost_usd']:.6f} |")
        t = arm["tripwires"]
        out += ["", f"Tripwires (existing checks, read-only): counts {t['counts']}; "
                    f"anomalies {t['anomalies'] or '{}'}", ""]
    if doc.get("library_fp"):
        lf = doc["library_fp"]
        sets = list(next(iter(lf["rules"].values())).keys() - {"cwe"}) if lf["rules"] else []
        sets = [s for s in ("holdout_v1", "fixture_v1", "fixture_v2_offline") if s in sets]
        out += [f"## Library rule FPs on offline benign sets ({lf['library']})", "",
                "| rule | cwe | " + " | ".join(sets) + " |",
                "|---|---|" + "---|" * len(sets)]
        for lid, r in lf["rules"].items():
            out.append(f"| {lid} | {r['cwe']} | " + " | ".join(
                fmt_rate(r[s]) + (f" {r[s]['hits']}" if r[s]["hits"] else "") for s in sets)
                + " |")
        out.append("")
    return "\n".join(out)
