"""Part F (Stage 5.3), REPORT ONLY: can the rule format express scripted Blue?

Translates every signature in blue/signatures.py into rules (one per field
path/query/body: a rule cannot OR across fields; alternation inside one regex is
allowed), runs them through the rule engine on every line of both golden matches,
and derives a verdict the way classify() does (first CWE in signatures.PRIORITY
with a firing rule, else benign). Then probes the known semantic differences with
synthetic inputs. Scripted Blue and the rule format are NOT changed to make
anything fit: gaps are findings about what an AI Blue can write in 5.5.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from blue import signatures  # noqa: E402
from rules import engine, validator  # noqa: E402

GOLDEN = [REPO / "data" / "golden" / m for m in
          ("scripted-baseline-match", "scripted-baseline-benign-match")]
SRC = "00000000-0000-4000-8000-000000000000"


def translate() -> tuple[list[validator.Validated], list[str]]:
    rules, n = [], 0
    for cwe, pats in signatures.SIGNATURES.items():
        for pat in pats:
            for field in ("path", "query", "body"):
                n += 1
                rules.append({"rule_id": f"r-{n:03d}", "cwe": cwe, "source_request_id": SRC,
                              "created_at_log_seq": 1, "note": f"{cwe} {pat.pattern!r} on {field}",
                              "conditions": [{"field": field, "op": "regex",
                                              "pattern": pat.pattern,
                                              "case_insensitive": bool(pat.flags & re.IGNORECASE)}]})
    checked = validator.validate_rules(rules)
    rejected = [f"{v.rule['note']}: {[r['code'] for r in v.reasons]}" for v in checked if not v.valid]
    return checked, rejected


def verdict(rules, method, path, query, body) -> str:
    fired = set(engine.fire(rules, engine.Request(method, path, query, body)))
    cwes = {v.rule["cwe"] for v in rules if v.rule_id in fired}
    return next((c for c in signatures.PRIORITY if c in cwes), "benign")


PROBES = [
    ("cross-field: Blue joins fields with a newline, rules match one field",
     "/x'", "--y", ""),
    ("Unicode \\b: Python re treats 'é' as a word char, RE2 \\b is ASCII-only",
     "/", "q=éor 1=1", ""),
    ("Unicode \\s: Python re matches NBSP (\\xa0), RE2 \\s is ASCII-only",
     "/", "q=x' or\xa01=1", ""),
    ("Unicode \\d: Python re matches Arabic-Indic digits, RE2 \\d is ASCII-only",
     "/", "q=x or ١=١", ""),
]


def main() -> int:
    rules, rejected = translate()
    n_sig = sum(len(p) for p in signatures.SIGNATURES.values())
    print(f"{n_sig} signatures -> {len(rules)} rules; rejected by the validator: "
          f"{rejected or 'none'}")
    lines = mismatch = 0
    for d in GOLDEN:
        golden = {v["request_id"]: v["verdict"]
                  for v in map(json.loads, (d / "verdicts.jsonl").read_text().splitlines())}
        for l in map(json.loads, (d / "proxy.jsonl").read_text().splitlines()):
            lines += 1
            got = verdict(rules, l["method"], l["path"], l["query"], l["body"])
            want = signatures.classify(l["path"], l["query"], l["body"])
            if got != want or want != golden[l["request_id"]]:
                mismatch += 1
                print(f"  MISMATCH {d.name} {l['request_id'][:8]}: rules={got} classify={want}")
    print(f"golden lines: {lines}, rules reproduce classify(): {lines - mismatch}/{lines}")
    print("\nsemantic probes (synthetic inputs, not from any match):")
    for desc, path, query, body in PROBES:
        a = signatures.classify(path, query, body)
        b = verdict(rules, "GET", path, query, body)
        print(f"  {'DIFFERS' if a != b else 'same   '}  classify={a:7} rules={b:7}  {desc}")
    print("\nnot a rule concept: classify() returns ONE label by fixed priority "
          f"{signatures.PRIORITY}; the engine returns every firing rule. Turning firing "
          "rules into one verdict is D9's job (5.5).")
    return 0 if mismatch == 0 and not rejected else 1


if __name__ == "__main__":
    raise SystemExit(main())
