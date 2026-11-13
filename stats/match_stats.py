"""Match statistics: counts and rates over round records. PURE.

This never re-judges anything: it only counts fields the Judge already wrote in
rounds.jsonl (contract §6). It is reused later for the autonomy table.

Denominators (contract §6, §6.1, §11):

  landing rate   = landed true / rounds with a measurable landing.
                   Excludes: orphan (all stats), not_measurable, already_solved,
                   snapshot_missing (every landed=null row).
  detection rate = detected true / non-orphan rounds.
                   Excludes: orphan, instrument_failure (D13: the harness failed,
                   not Blue). A no_verdict round stays in and counts as a miss
                   (detected=false).
  type accuracy  = type_correct true / rounds with detected true.
                   Excludes: every round Blue did not flag as an attack (benign
                   verdict, no_verdict, instrument_failure, orphan).
  no-verdict     = no_verdict / rounds Blue was asked about (non-orphan, not
                   instrument_failure). Brain failures.
  instrument failure rate = instrument_failure / logged (non-orphan) rounds.
                   Harness failures (Stage 5.4), shown separately, never a miss.

Benign traffic (benign_results.jsonl, fact 4a, contract §6.5), Stage 5.2 on:

  FP rate        = false_positive true / benign requests with a verdict.
                   Excludes: no_verdict, orphan. Also reported for hard
                   negatives only.
  no-verdict     = no_verdict / benign requests Blue was asked about (non-orphan,
                   not instrument_failure).
  instrument failure rate = instrument_failure / logged benign requests.
  precision      = detected attacks / (detected attacks + false positives).
                   Depends on the traffic mix, so it is always printed with it.

Model refusals (verdicts.jsonl failure_detail "model_refusal", audit only): counted
separately for attack and benign lines. A defender whose safety layer declines to
analyse attack traffic is a finding in itself, not just part of the no-verdict rate.

The detection rate is NEVER printed without the FP rate on the same line: with
attack-only traffic, flagging everything scores 100%.

Rule invention (Stage 5.5, rules mode shadow / on):

  split by verdict source   the rule path is every line with verdict_source "rule";
                   the AI path is every other line (incl. AI no_verdict lines).
                   Each path's rates use the denominators above (orphans and
                   instrument failures excluded as always). A rule only ever labels
                   a line as an attack, so rule-path detection is 100% by
                   construction whenever it is defined: read it with the rule
                   path's FP rate and the line counts.
  rules            proposed (= stored + rejected), rejection codes (one count per
                   code per rejection), cap hits (rule_cap_reached), tie-break
                   conflicts (rule verdicts whose fired rules name more than one
                   CWE), AI calls saved (= rule-verdict lines: no call was made).
  per rule         attack and benign lines it fired on in the match (from the
                   verdicts' fired_rule_ids; always 0 in shadow mode, where rules
                   are never applied), fact 3 and fact 4b (rule_results.jsonl).

D16 audited view: only AI-generated Red labels are audited. Scripted Red labels are
designer-written ground truth (verified in Stage 2): a round whose Red source is
scripted, or a legacy 0.1 Red record without a source, is valid by construction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from stats import cost

DETECTION_FOOTER = ("Note: no benign traffic in this match, so the detection rate is an "
                    "UPPER BOUND (flagging everything would score 100%).")


@dataclass(frozen=True)
class Rate:
    num: int
    den: int
    # reason -> rounds (or benign_ids) excluded from the denominator for that reason
    excluded: dict[str, list] = field(default_factory=dict)

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


def _is_instrument_failure(r: dict) -> bool:
    return r.get("detected_reason") == "instrument_failure"


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
        if _is_orphan(r) or _is_instrument_failure(r):
            excluded.setdefault(r["detected_reason"], []).append(r["round"])
            continue
        den += 1
        num += r["detected"] is True  # no_verdict -> detected=false -> a miss
    return Rate(num, den, excluded)


def no_verdict_rate(rounds: list[dict]) -> Rate:
    excluded: dict[str, list[int]] = {}
    num = den = 0
    for r in rounds:
        if _is_orphan(r) or _is_instrument_failure(r):
            excluded.setdefault(r["detected_reason"], []).append(r["round"])
            continue
        den += 1
        num += r.get("detected_reason") == "no_verdict"
    return Rate(num, den, excluded)


def instrument_failure_rate(rounds: list[dict]) -> Rate:
    excluded: dict[str, list[int]] = {}
    num = den = 0
    for r in rounds:
        if _is_orphan(r):
            excluded.setdefault("orphan", []).append(r["round"])
            continue
        den += 1
        num += _is_instrument_failure(r)
    return Rate(num, den, excluded)


def type_accuracy(rounds: list[dict]) -> Rate:
    excluded: dict[str, list[int]] = {}
    num = den = 0
    for r in rounds:
        if r["detected"] is True:
            den += 1
            num += r["type_correct"] is True
        elif r.get("detected_reason") in ("orphan", "no_verdict", "instrument_failure"):
            excluded.setdefault(r["detected_reason"], []).append(r["round"])
        else:
            excluded.setdefault("benign_verdict", []).append(r["round"])
    return Rate(num, den, excluded)


def counts(rounds: list[dict]) -> dict[str, int]:
    return {
        "rounds": len(rounds),
        "orphan": sum(_is_orphan(r) for r in rounds),
        "no_verdict": sum(r.get("detected_reason") == "no_verdict" for r in rounds),
        "instrument_failure": sum(_is_instrument_failure(r) for r in rounds),
        "snapshot_missing": sum(r.get("landed_reason") == "snapshot_missing" for r in rounds),
        "not_measurable": sum(r.get("landed_reason") == "not_measurable" for r in rounds),
        "already_solved": sum(r.get("landed_reason") == "already_solved" for r in rounds),
    }


def compute(rounds: list[dict]) -> dict:
    return {
        "landing": landing_rate(rounds),
        "detection": detection_rate(rounds),
        "type_accuracy": type_accuracy(rounds),
        "no_verdict": no_verdict_rate(rounds),
        "instrument_failure": instrument_failure_rate(rounds),
        "counts": counts(rounds),
    }


def fp_rate(benign: list[dict], category: str | None = None) -> Rate:
    excluded: dict[str, list] = {}
    num = den = 0
    for b in benign:
        if category is not None and b["category"] != category:
            continue
        if b["fp_reason"] is not None:
            excluded.setdefault(b["fp_reason"], []).append(b["benign_id"])
            continue
        den += 1
        num += b["false_positive"] is True
    return Rate(num, den, excluded)


def benign_no_verdict_rate(benign: list[dict]) -> Rate:
    excluded: dict[str, list] = {}
    num = den = 0
    for b in benign:
        if b["fp_reason"] in ("orphan", "instrument_failure"):
            excluded.setdefault(b["fp_reason"], []).append(b["benign_id"])
            continue
        den += 1
        num += b["fp_reason"] == "no_verdict"
    return Rate(num, den, excluded)


def benign_instrument_failure_rate(benign: list[dict]) -> Rate:
    excluded: dict[str, list] = {}
    num = den = 0
    for b in benign:
        if b["fp_reason"] == "orphan":
            excluded.setdefault("orphan", []).append(b["benign_id"])
            continue
        den += 1
        num += b["fp_reason"] == "instrument_failure"
    return Rate(num, den, excluded)


def red_unsent_summary(unsent_rows: list[dict]) -> dict:
    """Counts over red_unsent.jsonl (AI Red slots with no sent attack, Stage 5.6):
    guard blocks by reason, brain failures by detail, instrument failures by detail."""
    out = {"guard_block": {}, "brain_failure": {}, "instrument_failure": {}, "total": 0}
    for g in unsent_rows:
        out["total"] += 1
        bucket = out[g["kind"]]
        bucket[g["reason"]] = bucket.get(g["reason"], 0) + 1
    return out


def audit_first(rounds: list[dict], challenge_map: dict) -> dict[int, list[str]]:
    """D16 advisory flag: {round: [solved challenges outside challenge_map]}. Derived,
    never stored, and it excludes nothing: a SQLi that also solves an unmapped
    challenge (e.g. Error Handling) is legitimate, it is only looked at first."""
    mapped = {name for names in challenge_map.values() for name in names}
    out = {}
    for r in rounds:
        extra = sorted(set(r.get("newly_solved") or []) - mapped)
        if extra:
            out[r["round"]] = extra
    return out


def apply_audit(rounds: list[dict], audit_rows: list[dict],
                scripted: set[int] | frozenset = frozenset()) -> dict:
    """D16 audited view. A round whose label the designer judged `invalid` is EXCLUDED
    (like an orphan), never relabeled. The view exists only when every non-orphan
    AI-labeled round carries a decided verdict; otherwise `rounds` is None
    (incomplete), so a partial audit never produces a number. Rounds in `scripted`
    (scripted_rounds) are valid by construction and never need an audit line. Pure:
    the Judge's rounds are not changed."""
    by_round = {a["round"]: a for a in audit_rows}

    def decided(r: dict) -> str | None:
        if r["round"] in scripted:
            return "valid"
        return by_round.get(r["round"], {}).get("verdict")
    pending = sorted(r["round"] for r in rounds if not _is_orphan(r)
                     and decided(r) not in ("valid", "invalid"))
    invalid = sorted(r["round"] for r in rounds if decided(r) == "invalid")
    kept = None if pending else [r for r in rounds if r["round"] not in set(invalid)]
    return {"rounds": kept, "unaudited": pending, "invalid": invalid,
            "valid": sorted(r["round"] for r in rounds if decided(r) == "valid"),
            "valid_by_construction": sorted(r["round"] for r in rounds
                                            if r["round"] in scripted)}


# --------------------------------------------------------------------------
# Rule invention (Stage 5.5)
# --------------------------------------------------------------------------

def _is_rule(row: dict) -> bool:
    return row.get("verdict_source") == "rule"


def by_source(rounds: list[dict], benign: list[dict]) -> dict:
    """{"rule": {...}, "ai": {...}}: detection, type accuracy and FP rate per verdict
    path, plus how many attack / benign lines each path answered."""
    out = {}
    for path, keep in (("rule", _is_rule), ("ai", lambda r: not _is_rule(r))):
        rs = [r for r in rounds if keep(r)]
        bs = [b for b in benign if keep(b)]
        out[path] = {"detection": detection_rate(rs), "type_accuracy": type_accuracy(rs),
                     "fp": fp_rate(bs),
                     "attack_lines": sum(not _is_orphan(r) for r in rs),
                     "benign_lines": sum(b["fp_reason"] != "orphan" for b in bs)}
    return out


def rules_summary(rules: list[dict], rejections: list[dict], verdicts: list[dict],
                  rule_results: list[dict], rounds: list[dict], benign: list[dict]) -> dict:
    """Counts over rules.jsonl, rule_rejections.jsonl, the verdicts' fired_rule_ids and
    rule_results.jsonl (facts 3 + 4b). Pure; derives nothing the Judge did not write."""
    cwe = {r["rule"]["rule_id"]: r["rule"]["cwe"] for r in rules}
    codes: dict[str, int] = {}
    for x in rejections:
        for c in sorted({r["code"] for r in x["reasons"]}):
            codes[c] = codes.get(c, 0) + 1
    rule_rows = [v for v in verdicts if v.get("source") == "rule"]
    conflicts = [v["log_seq"] for v in rule_rows
                 if len({cwe.get(i) for i in v.get("fired_rule_ids", [])}) > 1]
    attack_ids = {r["request_id"] for r in rounds}
    benign_ids = {b["request_id"] for b in benign}
    facts = {r["rule_id"]: r for r in rule_results}
    per_rule = []
    for row in rules:
        rule = row["rule"]
        rid = rule["rule_id"]
        fired = [v for v in rule_rows if rid in v.get("fired_rule_ids", [])]
        f = facts.get(rid, {})
        per_rule.append({
            "rule_id": rid, "cwe": rule["cwe"], "conditions": rule["conditions"],
            "created_at_log_seq": rule["created_at_log_seq"],
            "source_request_id": rule["source_request_id"],
            "fired_attack_lines": sum(v["request_id"] in attack_ids for v in fired),
            "fired_benign_lines": sum(v["request_id"] in benign_ids for v in fired),
            "replay_fires": f.get("replay_fires"), "replay_reason": f.get("replay_reason"),
            "source_label": f.get("source_label"),
            "cwe_matches_source": f.get("cwe_matches_source"),
            "fixture_fires": f.get("fixture_fires"),
            "fixture_benign_ids": f.get("fixture_benign_ids", [])})
    return {"hot_loaded": bool(rules) and all(r["hot_loaded"] for r in rules),
            "proposed": len(rules) + len(rejections), "stored": len(rules),
            "rejected": len(rejections), "rejection_codes": codes,
            "cap_hits": codes.get("rule_cap_reached", 0),
            "conflicts": conflicts, "ai_calls_saved": len(rule_rows),
            "rules": per_rule, "rejections": rejections}


def format_rules(summary: dict, split: dict, mode: str) -> list[str]:
    """The rule-invention block of the terminal summary."""
    def pair(p: dict) -> str:
        return (f"detection {p['detection'].fmt():12} FP rate {p['fp'].fmt():12} "
                f"type acc. {p['type_accuracy'].fmt():12} lines {p['attack_lines']} attack "
                f"+ {p['benign_lines']} benign")
    lines = ["", f"rules mode {mode}: proposed {summary['proposed']}  stored "
                 f"{summary['stored']}  rejected {summary['rejected']} "
                 f"{summary['rejection_codes'] or ''}  cap hits {summary['cap_hits']}  "
                 f"AI calls saved {summary['ai_calls_saved']}  tie-break conflicts "
                 f"{len(summary['conflicts'])}{' ' + str(summary['conflicts']) if summary['conflicts'] else ''}",
             f"  rule path  {pair(split['rule'])}",
             f"  AI path    {pair(split['ai'])}"]
    for r in summary["rules"]:
        conds = " AND ".join(f"{c['field']} {c['op']}{'/i' if c['case_insensitive'] else ''} "
                             f"{json.dumps(c['pattern'])}" for c in r["conditions"])
        lines.append(f"  {r['rule_id']} {r['cwe']:7} @line {r['created_at_log_seq']:<3} "
                     f"fired {r['fired_attack_lines']} attack / {r['fired_benign_lines']} benign"
                     f"  fact3 {_with_reason(r['replay_fires'], r['replay_reason'])}"
                     f" cwe_ok={r['cwe_matches_source']}  fact4b {r['fixture_fires']} "
                     f"{r['fixture_benign_ids']}  {conds}")
    for x in summary["rejections"]:
        lines.append(f"  {x['rule_id']} REJECTED @line {x['created_at_log_seq']:<3} "
                     f"label {x['label']}: {'; '.join(c['code'] + ' (' + c['detail'] + ')' for c in x['reasons'])}"
                     f"  proposal {json.dumps(x['proposal'])}")
    return lines


def scripted_rounds(red_attacks: list[dict]) -> set[int]:
    """D16: rounds whose label is designer ground truth, valid by construction: Red
    source "scripted", or a legacy 0.1 record without a source (scripted Red was the
    only Red before Stage 5.6)."""
    return {r["round"] for r in red_attacks if r.get("source", "scripted") == "scripted"}


def model_refusals(rounds: list[dict], benign: list[dict], verdicts: list[dict]) -> dict:
    """{"attack": n, "benign": n, "unmatched": n}: verdict rows whose failure_detail is
    model_refusal (0.2 rows only; audit field), split by which traffic they were."""
    attack_ids = {r["request_id"] for r in rounds}
    benign_ids = {b["request_id"] for b in benign}
    out = {"attack": 0, "benign": 0, "unmatched": 0}
    for v in verdicts:
        if v.get("failure_detail") != "model_refusal":
            continue
        rid = v["request_id"]
        out["attack" if rid in attack_ids else "benign" if rid in benign_ids
            else "unmatched"] += 1
    return out


def precision(rounds: list[dict], benign: list[dict]) -> Rate:
    tp = sum(r["detected"] is True for r in rounds if not _is_orphan(r))
    fp = sum(b["false_positive"] is True for b in benign)
    return Rate(tp, tp + fp)


def traffic_mix(rounds: list[dict], benign: list[dict]) -> str:
    attacks = sum(not _is_orphan(r) for r in rounds)
    ben = sum(b["fp_reason"] != "orphan" for b in benign)
    return f"{attacks} attack : {ben} benign"


def compute_benign(rounds: list[dict], benign: list[dict]) -> dict:
    return {
        "fp": fp_rate(benign),
        "fp_hard": fp_rate(benign, "hard_negative"),
        "no_verdict": benign_no_verdict_rate(benign),
        "instrument_failure": benign_instrument_failure_rate(benign),
        "precision": precision(rounds, benign),
        "mix": traffic_mix(rounds, benign),
    }


def _excl(rate: Rate, noun: str = "rounds") -> str:
    if not rate.excluded:
        return f"excludes no {noun}"
    parts = [f"{reason} [{', '.join(map(str, items))}]"
             for reason, items in sorted(rate.excluded.items())]
    return "excludes " + ", ".join(parts)


def _with_reason(value, reason) -> str:
    return str(value) if reason is None else f"{value} ({reason})"


def format_summary(rounds: list[dict], manifest: dict, benign: list[dict] | None = None,
                   anomalies: list[dict] | None = None,
                   verdicts: list[dict] | None = None,
                   red_unsent: list[dict] | None = None,
                   challenge_map: dict | None = None,
                   rules: tuple[list, list, list] | None = None) -> str:
    """Terminal summary. `benign` / `anomalies` are the fact-4a outputs (None or
    [] for a match without benign traffic). `verdicts` (verdicts.jsonl rows) is read
    only for the model_refusal counts of an AI Blue match. `red_unsent` (red_unsent.jsonl
    rows) gives the AI Red diagnostics (attacks sent, guard blocks, brain / instrument
    failures). `rules` = (rules.jsonl, rule_rejections.jsonl, rule_results.jsonl rows)
    adds the rule-invention block when Blue ran in rules mode shadow / on."""
    benign = benign or []
    lines = [
        f"match {manifest['match_id']}  status={manifest['status']}  "
        f"judge {manifest['judge_version']}  blue={manifest['blue_engine']}  "
        f"git {manifest['git']['commit'][:10]}{' (dirty)' if manifest['git']['dirty'] else ''}",
    ]
    if manifest.get("red_engine") == "ai":
        g = red_unsent_summary(red_unsent or [])
        sent = sum(1 for r in rounds if r.get("detected_reason") != "orphan") \
            if rounds else 0
        lines.append(f"red={manifest['red_engine']}  attacks sent {len(rounds)}  "
                     f"guard blocks {sum(g['guard_block'].values())} {g['guard_block']}  "
                     f"brain failures {sum(g['brain_failure'].values())} {g['brain_failure']}  "
                     f"instr. failures {sum(g['instrument_failure'].values())} "
                     f"{g['instrument_failure']}")
    if manifest["status"] == "failed":
        lines.append(f"FAILED at step '{manifest['failed_step']}': {manifest['error']}")
    stop = (manifest.get("budget") or {}).get("stopped_by")
    if stop is not None:
        lines.append(f"STOPPED by the AI budget: {stop['scope']} {stop['reason']} "
                     f"(calls the body refused are instrument failures, D13)")
    if "cost" in manifest:  # schema_version 0.2 manifests
        lines.append(cost.format_cost_line(manifest["cost"]))
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
    if benign:
        lines.append("")
        lines.append(f"{'slot':>4}  {'benign':6}  {'category':13}  {'verdict':7}  false_positive")
        slots = {lab: i for i, lab in
                 enumerate((manifest.get("traffic") or {}).get("schedule", []), start=1)}
        for b in benign:
            lines.append(f"{slots.get('benign:' + b['benign_id'], '?'):>4}  "
                         f"{b['benign_id']:6}  {b['category']:13}  {b['verdict']!s:7}  "
                         f"{_with_reason(b['false_positive'], b['fp_reason'])}")
    if benign:
        bs = compute_benign(rounds, benign)
        fp_part = f"FP rate {bs['fp'].fmt()}"
    else:
        fp_part = "FP rate n/a (no benign traffic)"
    lines += [
        "",
        f"landing        {s['landing'].fmt():12}  {_excl(s['landing'])}",
        f"detection      {s['detection'].fmt():12}  {fp_part}  [detection {_excl(s['detection'])}"
        f"{'; no_verdict counted as a miss' if c['no_verdict'] else ''}]",
        f"type accuracy  {s['type_accuracy'].fmt():12}  {_excl(s['type_accuracy'])}",
        f"no-verdict     {s['no_verdict'].fmt():12}  on attacks (brain failures, counted as "
        f"misses); {_excl(s['no_verdict'])}",
        f"instr. failure {s['instrument_failure'].fmt():12}  on attacks (harness, D13; "
        f"never a miss); {_excl(s['instrument_failure'])}",
    ]
    if benign:
        lines += [
            f"FP rate        {bs['fp'].fmt():12}  {_excl(bs['fp'], 'benign requests')}",
            f"FP hard neg.   {bs['fp_hard'].fmt():12}  {_excl(bs['fp_hard'], 'benign requests')}",
            f"precision      {bs['precision'].fmt():12}  traffic mix {bs['mix']} "
            f"(precision depends on the mix)",
            f"no-verdict     {bs['no_verdict'].fmt():12}  on benign; {_excl(bs['no_verdict'], 'benign requests')}",
            f"instr. failure {bs['instrument_failure'].fmt():12}  on benign; "
            f"{_excl(bs['instrument_failure'], 'benign requests')}",
        ]
    if manifest.get("blue_engine") == "claude":
        mr = model_refusals(rounds, benign, verdicts or [])
        lines.append(f"model refusals attack {mr['attack']}  benign {mr['benign']}"
                     f"{'  unmatched ' + str(mr['unmatched']) if mr['unmatched'] else ''}"
                     f"  (the model's safety layer declined; part of no-verdict)")
    if challenge_map is not None and manifest.get("red_engine") == "ai":
        flagged = audit_first(rounds, challenge_map)
        lines.append("audit first    " + (", ".join(f"round {k} {v}" for k, v in flagged.items())
                                          if flagged else "none")
                     + "  (solved a challenge outside challenge_map; advisory, D16)")
    mode = ((manifest.get("blue_params") or {}).get("rules") or {}).get("mode", "off")
    if mode != "off":
        rr, rj, res = rules or ([], [], [])
        lines += format_rules(rules_summary(rr, rj, verdicts or [], res, rounds, benign),
                              by_source(rounds, benign), mode)
    lines += ["", "counts: " + "  ".join(f"{k}={v}" for k, v in c.items())]
    if anomalies:
        lines.append("")
        for a in anomalies:
            lines.append(f"ANOMALY {a['kind']}  {a['request_id'][:8]}  {json.dumps(a['detail'])}")
    elif benign:
        lines.append("anomalies: none")
    if not benign:
        lines += ["", DETECTION_FOOTER]
    return "\n".join(lines)
