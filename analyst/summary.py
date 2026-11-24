"""Build summary.json (#16; D53, D55, D60): every figure the analyst report may cite, computed
by code from frozen evidence, each with its sources, basis and confidence. Reads only; writes
nothing (tools/build_summary.py writes the file).

Figures reuse the existing pure stats, so they equal the committed tables:
  taxonomy groups  stats/autonomy.arm_table (the autonomy table's "total" row): detection
                   (audited view when the group is audited and the audit is complete, else
                   raw), raw detection, verdict FP over unique benign requests, AI calls,
                   cost; stats/match_stats.landing_rate for landing
  freeplay groups  stats/free_play.summary: binary detection over audited attack attempts,
                   landed rounds
  fp_check groups  fp_verdicts.jsonl (the D42 2c prompt-FP check): FP over unique requests

Descriptive fields (D53): model ids, run dates, and in free-play the Red `technique`
strings (cleaned, <= 120 chars) with the challenge name / category of landed rounds. Never a
payload, path, body, header value or rationale.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from analyst.confidence import LEVELS, cp95, figure_confidence
from stats import autonomy
from stats import free_play
from stats import match_stats as ms
from stats import test_data
from tools import audit_match, autonomy_table
from tools import free_play as free_play_tool

REPO = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "0.2"
# designer, 2026-11-24: no percentage without its baseline in the name
CHANGE_KEY = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+_change_vs_[a-z0-9_]+$")
TEXT_MAX = 120
KINDS = ("taxonomy", "freeplay", "fp_check")
ARTIFACTS = ("match.json", "replay.json", "rounds.jsonl", "benign_results.jsonl",
             "verdicts.jsonl", "api_calls.jsonl", "proxy.jsonl", "red_attacks.jsonl",
             "challenge_catalog.json", "fp_verdicts.jsonl")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _rel(p: Path, repo: Path = REPO) -> str:
    try:
        return Path(p).resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return Path(p).as_posix()


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def clean_text(s: str | None) -> str | None:
    """Descriptive free text: control characters removed, whitespace collapsed, cut."""
    if s is None:
        return None
    s = " ".join(CONTROL.sub(" ", str(s)).split())
    return s if len(s) <= TEXT_MAX else s[:TEXT_MAX - 1] + "…"


def _manifest_of(d: Path) -> dict:
    for name in ("match.json", "replay.json"):
        if (d / name).is_file():
            return json.loads((d / name).read_text(encoding="utf-8"))
    return {}


def _source(gid: str, i: int, d: Path, registry, extra: list[Path] = ()) -> dict:
    m = _manifest_of(d)
    v = test_data.classify(d, registry)
    arts = {name: _sha(d / name) for name in ARTIFACTS if (d / name).is_file()}
    for p in extra:
        if p is not None and Path(p).is_file():
            arts[_rel(p)] = _sha(Path(p))
    return {"id": f"{gid}#{i}", "path": _rel(d),
            "match_id": m.get("match_id") or (m.get("source") or {}).get("match_id"),
            "replay_id": m.get("replay_id"), "purpose": m.get("purpose"),
            "test_data": v.kind, "sha256": arts}


def _fig_rate(k: int, n: int, basis: str, group: dict, sources: list[str], definition: str,
              unit: str) -> dict:
    lo, hi = cp95(k, n)
    return {"kind": "rate", "value": round(k / n, 4), "k": k, "n": n,
            "pct": round(100.0 * k / n, 1), "ci_low": lo, "ci_high": hi, "unit": unit,
            "basis": basis, "blue": group.get("blue"),
            "confidence": figure_confidence(basis, n, group.get("blue") == "open"),
            "source_ids": sources, "definition": definition}


def _fig_value(kind: str, value, n: int, unit: str, group: dict, sources: list[str],
               definition: str) -> dict:
    return {"kind": kind, "value": value, "n": n, "unit": unit, "basis": "measured",
            "blue": group.get("blue"),
            "confidence": figure_confidence("measured", n, group.get("blue") == "open"),
            "source_ids": sources, "definition": definition}


def _models(dirs: list[Path]) -> dict:
    red, blue, dates = set(), set(), set()
    for d in dirs:
        m = _manifest_of(d)
        models = m.get("models") or {}
        if (models.get("red") or {}).get("model"):
            red.add(models["red"]["model"])
        if (models.get("blue") or {}).get("model"):
            blue.add(models["blue"]["model"])
        if m.get("started_at"):
            dates.add(m["started_at"][:10])
    return {"red_models": sorted(red), "blue_models": sorted(blue), "dates": sorted(dates)}


def _taxonomy(g: dict, dirs: list[Path], sids: list[str], prices: dict, audits) -> tuple:
    folders = [autonomy_table.load_folder(d, audits) for d in dirs]
    table = autonomy.arm_table(folders, prices)
    total = table["rows"]["total"]
    gid, figs, notes = g["id"], {}, []
    raw = total["detection_raw"]
    audited = total["detection_audited"]
    if g.get("basis") == "audited" and audited is not None and audited["n"]:
        figs[f"{gid}.detection"] = _fig_rate(
            audited["k"], audited["n"], "audited", g, sids,
            "Attack rounds Blue flagged as an attack, over the rounds left after the "
            "designer's label audit (orphans and instrument failures excluded).", "rounds")
    elif raw["n"]:
        if g.get("basis") == "audited":
            notes.append("audit incomplete: detection reported raw")
        figs[f"{gid}.detection"] = _fig_rate(
            raw["k"], raw["n"], "raw", g, sids,
            "Attack rounds Blue flagged as an attack, over all scored rounds; Red's labels "
            "are not audited.", "rounds")
    if raw["n"]:
        figs[f"{gid}.detection_raw"] = _fig_rate(
            raw["k"], raw["n"], "raw", g, sids,
            "Attack rounds Blue flagged as an attack, over all scored rounds (before any "
            "label audit).", "rounds")
    fp = total["verdict_fp"]
    uk, un = (fp["unique"]["k"], fp["unique"]["n"]) if "unique" in fp else (fp["k"], fp["n"])
    if un:
        figs[f"{gid}.fp"] = _fig_rate(
            uk, un, "ground_truth", g, sids,
            "Benign requests Blue flagged as an attack, over the unique benign requests "
            "sent (a request sent in several matches counts once).", "unique benign requests")
    k = n = 0
    for f in folders:
        r = ms.landing_rate(f.rounds)
        k, n = k + r.num, n + r.den
    if n:
        figs[f"{gid}.landed"] = _fig_rate(
            k, n, "measured", g, sids,
            "Attack rounds that solved their mapped challenge, over the rounds where "
            "landing was measurable.", "rounds")
    units = len(dirs)
    figs[f"{gid}.matches"] = _fig_value("count", units, units, "matches", g, sids,
                                        "Frozen matches or replays in this group.")
    figs[f"{gid}.ai_calls"] = _fig_value("count", total["ai_calls"], units, "calls", g, sids,
                                         "AI calls of every agent (sent attempts).")
    figs[f"{gid}.cost_usd"] = _fig_value("usd", round(total["cost_usd"], 6), units, "USD", g,
                                         sids, "Total AI cost, each call priced by "
                                         "stats/cost.py (D39 time-of-day rates).")
    figs[f"{gid}.cost_per_match_usd"] = _fig_value(
        "usd", round(total["cost_usd"] / units, 6), units, "USD per match", g, sids,
        "Total AI cost divided by the number of matches or replays.")
    audit_files = [audit_match.audit_path(audit_match.match_id_of(d), audits) for d in dirs]
    return figs, notes, {"audit_files": audit_files}


def _freeplay(g: dict, dirs: list[Path], sids: list[str], audits) -> tuple:
    gid, figs, notes = g["id"], {}, []
    per, rounds_desc, audit_files = [], [], []
    for d in dirs:
        m = _manifest_of(d)
        mid = m.get("match_id") or (m.get("source") or {}).get("match_id")
        ap = (Path(audits) / f"{mid}.freeplay.jsonl") if audits else free_play_tool.audit_path(mid)
        audit_files.append(ap)
        per.append(free_play.summary(d, ap if ap.is_file() else None))
        for r in free_play.rows(d, ap if ap.is_file() else None):
            rounds_desc.append({"match_id": mid, "round": r["round"], "label": r["label"],
                                "technique": clean_text(r["technique"]),
                                "attack_attempt": r["attack_attempt"],
                                "detected": r["detected"],
                                "solved": [{"challenge": s["challenge"],
                                            "category": s["category"]}
                                           for s in r["newly_solved"]]})
    total_rounds = sum(p["rounds"] for p in per)
    if all(p["audited"] for p in per) and per:
        k = sum(p["detection"]["num"] for p in per if p["detection"])
        n = sum(p["detection"]["den"] for p in per if p["detection"])
        if n:
            figs[f"{gid}.detection"] = _fig_rate(
                k, n, "audited", g, sids,
                "Attack attempts (designer's binary audit) that Blue flagged as an attack, "
                "any label; ordinary browsing excluded.", "audited attack attempts")
        figs[f"{gid}.attack_attempts"] = _fig_value(
            "count", sum(p["attack_attempts"] for p in per), total_rounds, "attempts", g, sids,
            "Red rounds the designer audited as attack attempts.")
    else:
        notes.append("free-play audit incomplete: no detection figure")
    figs[f"{gid}.landed_rounds"] = _fig_value(
        "count", sum(p["landed_rounds"] for p in per), total_rounds, "rounds", g, sids,
        "Red rounds that solved any Juice Shop challenge (free-play landing, D41).")
    figs[f"{gid}.rounds"] = _fig_value("count", total_rounds, total_rounds, "rounds", g, sids,
                                       "Red rounds sent in this group.")
    return figs, notes, {"rounds": rounds_desc, "audit_files": audit_files}


def _fp_check(g: dict, dirs: list[Path], sids: list[str]) -> tuple:
    gid, figs = g["id"], {}
    keys: dict[tuple, bool] = {}
    for d in dirs:
        for line in ms.read_rounds(d / "fp_verdicts.jsonl"):
            key = (line.get("set"), line.get("benign_id"))
            keys[key] = keys.get(key, False) or line.get("false_positive") is True
    if keys:
        figs[f"{gid}.fp"] = _fig_rate(
            sum(keys.values()), len(keys), "ground_truth", g, sids,
            "Sealed benign requests (holdout + fixture) the prompt alone labelled as an "
            "attack, one AI call per request, no rules (D42 2c).", "unique benign requests")
    return figs, [], {}


def build(manifest: dict, *, prices: dict, registry: test_data.Registry | None = None,
          git: dict | None = None, judge_version: str | None = None,
          manifest_path: Path | None = None, repo: Path = REPO,
          built_at: str | None = None) -> dict:
    registry = registry if registry is not None else test_data.load_registry()
    groups, sources, figures, descriptive = [], [], {}, {"groups": {}}
    for g in manifest["groups"]:
        if g["kind"] not in KINDS:
            raise ValueError(f"group {g['id']}: unknown kind {g['kind']!r}")
        dirs = [(repo / p) if not Path(p).is_absolute() else Path(p) for p in g["folders"]]
        for d in dirs:
            if not d.is_dir():
                raise FileNotFoundError(f"group {g['id']}: no folder {d}")
        sids = [f"{g['id']}#{i}" for i in range(1, len(dirs) + 1)]
        audits = g.get("audits")
        audits = (repo / audits) if audits and not Path(audits).is_absolute() else audits
        if g["kind"] == "taxonomy":
            figs, notes, desc = _taxonomy(g, dirs, sids, prices, audits)
        elif g["kind"] == "freeplay":
            figs, notes, desc = _freeplay(g, dirs, sids, audits)
        else:
            figs, notes, desc = _fp_check(g, dirs, sids)
        extra = desc.pop("audit_files", [])
        for i, d in enumerate(dirs, start=1):
            sources.append(_source(g["id"], i, d, registry,
                                   [extra[i - 1]] if i <= len(extra) else []))
        dup = set(figs) & set(figures)
        if dup:
            raise ValueError(f"duplicate figure keys: {sorted(dup)}")
        figures.update(figs)
        groups.append({"id": g["id"], "label": g.get("label", g["id"]), "kind": g["kind"],
                       "blue": g.get("blue"), "basis": g.get("basis"),
                       "folders": len(dirs), "notes": notes})
        descriptive["groups"][g["id"]] = {**_models(dirs), **desc}
    for c in manifest.get("comparisons", []):
        if c["id"] in figures:
            raise ValueError(f"duplicate figure key {c['id']!r}")
        figures[c["id"]] = comparison(c, figures)
    return {
        "schema_version": SCHEMA_VERSION,
        "built_at": built_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "git": git, "judge_version": judge_version, "confidence_rules": "D60",
        "manifest": None if manifest_path is None else
        {"path": _rel(manifest_path, repo), "sha256": _sha(Path(manifest_path))},
        "groups": groups, "sources": sources, "figures": dict(sorted(figures.items())),
        "descriptive": descriptive,
    }


def comparison(c: dict, figures: dict) -> dict:
    """A change figure from two existing figures. mode relative: (of - vs) / vs (costs,
    calls); points: the difference in percentage points of two rates. The key must name the
    baseline (`..._change_vs_<baseline>`); confidence is the lower of the two (D60)."""
    key = c["id"]
    if not CHANGE_KEY.match(key):
        raise ValueError(f"comparison {key!r}: the key must name its baseline "
                         f"(<group>.<metric>_change_vs_<baseline>)")
    for ref in (c["of"], c["vs"]):
        if ref not in figures:
            raise ValueError(f"comparison {key!r}: unknown figure {ref!r}")
    a, b = figures[c["of"]], figures[c["vs"]]
    mode = c["mode"]
    if mode == "points":
        if a["kind"] != "rate" or b["kind"] != "rate":
            raise ValueError(f"comparison {key!r}: points need two rates")
        ov, vv = a["value"], b["value"]
        value, unit = round(100.0 * (ov - vv), 1), "percentage points"
    elif mode == "relative":
        if a["kind"] == "rate" or b["kind"] == "rate":
            raise ValueError(f"comparison {key!r}: a relative change compares counts or costs")
        ov, vv = a["value"], b["value"]
        if not vv:
            raise ValueError(f"comparison {key!r}: the baseline is zero")
        value, unit = round((ov - vv) / vv, 4), "relative change"
    else:
        raise ValueError(f"comparison {key!r}: unknown mode {mode!r}")
    conf = min((a["confidence"], b["confidence"]), key=LEVELS.index)
    basis = "raw" if "raw" in (a["basis"], b["basis"]) else a["basis"]
    return {"kind": "change", "mode": mode, "value": value, "of": c["of"], "vs": c["vs"],
            "baseline": c["baseline"], "of_value": ov, "vs_value": vv,
            "n": min(a["n"], b["n"]), "unit": unit, "basis": basis,
            "blue": a.get("blue") if a.get("blue") == b.get("blue") else None,
            "confidence": conf,
            "source_ids": sorted(set(a["source_ids"]) | set(b["source_ids"])),
            "definition": c.get("definition") or
            f"{c['of']} compared with {c['vs']} (baseline: {c['baseline']})."}


def model_ids(summary: dict) -> set[str]:
    """Every model id in the summary (the grounding check allows them in prose)."""
    out = set()
    for g in summary.get("descriptive", {}).get("groups", {}).values():
        out.update(g.get("red_models", []))
        out.update(g.get("blue_models", []))
    return out
