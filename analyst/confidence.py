"""D60 (a): confidence of report figures and findings, as code. PURE.

Pre-registered in docs/stage7_decisions.md before any summary was built. The analyst never
sets a confidence (D55); this module does.

  basis audited | ground_truth | measured, n >= 20 -> High
  basis audited | ground_truth | measured, n <  20 -> Moderate
  basis raw (unaudited AI-Red labels)            -> Low, whatever n
  open Blue (v3-open, D42/D44)                   -> capped at Moderate
  a finding                                      -> the lowest of the figures it cites

n is the number of independent units: unique requests for benign rates (pseudo-replication,
stats/autonomy.py), audited attempts / rounds for Red rates, matches for per-match counts
and costs. The n >= 20 threshold was set knowing the sample sizes (free-play 19, Gate B 28);
it puts free-play at Moderate, against our own headline (D60 disclosure).
"""

from __future__ import annotations

import math

BASES = ("audited", "ground_truth", "raw", "measured")
LEVELS = ("Low", "Moderate", "High")   # ascending
THRESHOLD = 20


def figure_confidence(basis: str, n: int, open_blue: bool = False) -> str:
    if basis not in BASES:
        raise ValueError(f"unknown basis {basis!r}")
    if not isinstance(n, int) or isinstance(n, bool) or n < 1:
        raise ValueError(f"n must be a positive integer, not {n!r}")
    if basis == "raw":
        level = "Low"
    else:
        level = "High" if n >= THRESHOLD else "Moderate"
    if open_blue and level == "High":
        level = "Moderate"
    return level


def finding_confidence(levels: list[str]) -> str:
    """The lowest confidence among the cited figures (at least one is required)."""
    if not levels:
        raise ValueError("a finding cites at least one figure")
    for lv in levels:
        if lv not in LEVELS:
            raise ValueError(f"unknown confidence {lv!r}")
    return min(levels, key=LEVELS.index)


# -- exact Clopper-Pearson 95% interval (two-sided), stdlib only ------------------------

def _binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def _bisect(f, lo: float = 0.0, hi: float = 1.0, iters: int = 80) -> float:
    """Root of a function that goes from > 0 to <= 0 on [lo, hi]."""
    for _ in range(iters):
        mid = (lo + hi) / 2
        if f(mid) > 0:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def cp95(k: int, n: int) -> tuple[float, float]:
    """(lower, upper) exact two-sided 95% Clopper-Pearson interval for k of n."""
    if not (0 <= k <= n) or n < 1:
        raise ValueError(f"need 0 <= k <= n and n >= 1, not {k}/{n}")
    lower = 0.0 if k == 0 else _bisect(lambda p: _binom_cdf(k - 1, n, p) - 0.975)
    upper = 1.0 if k == n else _bisect(lambda p: _binom_cdf(k, n, p) - 0.025)
    return round(lower, 4), round(upper, 4)
