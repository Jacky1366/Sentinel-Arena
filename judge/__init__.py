"""Sentinel Arena Judge: pure deterministic scoring over artifacts (no network, no LLM)."""

# Bump on ANY change to how the Judge computes facts or round records. A bump means
# earlier match results were scored by different logic; record which version scored
# what (match.json carries judge_version).
JUDGE_VERSION = "0.7.0"  # 6.1: library rules preloaded in rules/hotload.py (live from
#                          line 1, first in the tie-break); rule-verdict cross-check with
#                          the library snapshot and verdicts 0.4 (rule_origin); the
#                          above-root predicate moved to rules/paths.py (D32); retention
#                          (judge/retention.py) and the variant mutator (judge/variants.py)
# 0.6.0  5.5: rule-verdict cross-check (rules/hotload.py), the
#                          instrument_failure exemption for rule verdicts, facts 3 + 4b
#                          inside the match (judge_rules), rounds + benign results 0.3
# 0.5.0  5.6: label_mismatch tripwire (D5); AI Red artifacts
# 0.3.0  5.3: facts 3 + 4b; rules/ package (normalization v2)
