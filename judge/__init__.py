"""Sentinel Arena Judge: pure deterministic scoring over artifacts (no network, no LLM)."""

# Bump on ANY change to how the Judge computes facts or round records. A bump means
# earlier match results were scored by different logic; record which version scored
# what (match.json carries judge_version).
JUDGE_VERSION = "0.4.0"  # 5.4: instrument_failure (D13) + api_calls cross-check; rounds /
#                          benign results 0.2; reads 0.1 and 0.2 verdicts
# 0.3.0  5.3: facts 3 + 4b; rules/ package (normalization v2)
