"""Sentinel Arena Judge: pure deterministic scoring over artifacts (no network, no LLM)."""

# Bump on ANY change to how the Judge computes facts or round records. A bump means
# earlier match results were scored by different logic; record which version scored
# what (match.json carries judge_version).
JUDGE_VERSION = "0.2.0"  # 5.2: fact 4a; unmatched verdicts -> anomalies
