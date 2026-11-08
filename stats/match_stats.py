"""Match statistics: counts and rates over round records. PURE.

This never re-judges anything: it only counts fields the Judge already wrote in
rounds.jsonl (contract §6). It is reused later for the autonomy table.

Denominators (contract §6, §6.1, §11):

  landing rate   = landed true / rounds with a measurable landing.
                   Excludes: orphan (all stats), not_measurable, already_solved,
                   snapshot_missing (every landed=null row).
  detection rate = detected true / non-orphan rounds.
                   Excludes: orphan. A no_verdict round stays in and counts as a
                   miss (detected=false).
  type accuracy  = type_correct true / rounds with detected true.
                   Excludes: every round Blue did not flag as an attack (benign
                   verdict, no_verdict, orphan).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DETECTION_FOOTER = ("Note: the detection rate is an UPPER BOUND until benign traffic "
                    "and false-positive scoring exist (Stage 5). With attack-only "
                    "traffic, flagging everything scores 100%.")


@dataclass(frozen=True)
class Rate:
    num: int
    den: int
    # reason -> rounds excluded from the denominator for that reason
    excluded: dict[str, list[int]] = field(default_factory=dict)

    @property
    def pct(self) -> float | None:
        return None if self.den == 0 else 100.0 * self.num / self.den

    def fmt(self) -> str:
        pct = "n/a" if self.pct is None else f"{self.pct:.0f}%"
        return f"{self.num}/{self.den} ({pct})"


def read_rounds(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _is_orphan(r: dict) -> bool:
    return r.get("detected_reason") == "orphan"


def landing_rate(rounds: list[dict]) -> Rate:
    excluded: dict[str, list[int]] = {}
    num = den = 0
    for r in rounds:
        if _is_orphan(r):
            excluded.setdefault("orphan", []).append(r["round"])
        elif r["landed"] is None:
            excluded.setdefault(r["landed_reason"], []).append(r["round"])
        else:
            den += 1
            num += r["landed"] is True
    return Rate(num, den, excluded)


def detection_rate(rounds: list[dict]) -> Rate:
    excluded: dict[str, list[int]] = {}
    num = den = 0
    for r in rounds:
        if _is_orphan(r):
            excluded.setdefault("orphan", []).append(r["round"])
            continue
        den += 1
        num += r["detected"] is True  # no_verdict -> detected=false -> a miss
    return Rate(num, den, excluded)


def type_accuracy(rounds: list[dict]) -> Rate:
    excluded: dict[str, list[int]] = {}
    num = den = 0
    for r in rounds:
        if r["detected"] is True:
            den += 1
            num += r["type_correct"] is True
        elif _is_orphan(r):
            excluded.setdefault("orphan", []).append(r["round"])
        elif r.get("detected_reason") == "no_verdict":
            excluded.setdefault("no_verdict", []).append(r["round"])
        else:
            excluded.setdefault("benign_verdict", []).append(r["round"])
    return Rate(num, den, excluded)


def counts(rounds: list[dict]) -> dict[str, int]:
    return {
        "rounds": len(rounds),
        "orphan": sum(_is_orphan(r) for r in rounds),
        "no_verdict": sum(r.get("detected_reason") == "no_verdict" for r in rounds),
        "snapshot_missing": sum(r.get("landed_reason") == "snapshot_missing" for r in rounds),
        "not_measurable": sum(r.get("landed_reason") == "not_measurable" for r in rounds),
        "already_solved": sum(r.get("landed_reason") == "already_solved" for r in rounds),
    }


def compute(rounds: list[dict]) -> dict:
    return {
        "landing": landing_rate(rounds),
        "detection": detection_rate(rounds),
        "type_accuracy": type_accuracy(rounds),
        "counts": counts(rounds),
    }


def _excl(rate: Rate) -> str:
    if not rate.excluded:
        return "excludes no rounds"
    parts = [f"{reason} {rounds}" for reason, rounds in sorted(rate.excluded.items())]
    return "excludes " + ", ".join(parts)


def _with_reason(value, reason) -> str:
    return str(value) if reason is None else f"{value} ({reason})"


def format_summary(rounds: list[dict], manifest: dict) -> str:
    lines = [
        f"match {manifest['match_id']}  status={manifest['status']}  "
        f"judge {manifest['judge_version']}  blue={manifest['blue_engine']}  "
        f"git {manifest['git']['commit'][:10]}{' (dirty)' if manifest['git']['dirty'] else ''}",
    ]
    if manifest["status"] != "completed":
        lines.append(f"FAILED at step '{manifest['failed_step']}': {manifest['error']}")
    if not rounds:
        lines.append("(no round records)")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"{'rnd':>3}  {'request':8}  {'label':7}  {'landed':26}  "
                 f"{'detected':20}  type_correct")
    for r in rounds:
        lines.append(
            f"{r['round']:>3}  {r['request_id'][:8]}  {r['label']:7}  "
            f"{_with_reason(r['landed'], r['landed_reason']):26}  "
            f"{_with_reason(r['detected'], r['detected_reason']):20}  "
            f"{r['type_correct']}")

    s = compute(rounds)
    c = s["counts"]
    lines += [
        "",
        f"landing        {s['landing'].fmt():12}  {_excl(s['landing'])}",
        f"detection      {s['detection'].fmt():12}  {_excl(s['detection'])}"
        f"{'; no_verdict counted as a miss' if c['no_verdict'] else ''}",
        f"type accuracy  {s['type_accuracy'].fmt():12}  {_excl(s['type_accuracy'])}",
        "",
        "counts: " + "  ".join(f"{k}={v}" for k, v in c.items()),
        "",
        DETECTION_FOOTER,
    ]
    return "\n".join(lines)
