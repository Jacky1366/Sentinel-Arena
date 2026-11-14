"""Sentinel Arena Judge: pure deterministic scoring over artifacts (no network, no LLM)."""

# Bump on ANY change to how the Judge computes facts or round records. A bump means
# earlier match results were scored by different logic; record which version scored
# what (match.json carries judge_version).
JUDGE_VERSION = "0.6.0"  # 5.5: rule-verdict cross-check (rules/hotload.py), the
#                          instrument_failure exemption for rule verdicts, facts 3 + 4b
#                          inside the match (judge_rules), rounds + benign results 0.3
# 0.5.0  5.6: label_mismatch tripwire (D5); AI Red artifacts
# 0.3.0  5.3: facts 3 + 4b; rules/ package (normalization v2)
