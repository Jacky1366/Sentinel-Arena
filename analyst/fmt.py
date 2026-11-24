"""Report number formats (#17; designer Q4, 2026-11-24). PURE.

  rate     "12/19 (63%)"            a percentage never prints without its count
  ci       "95% CI 38.4–83.7%"
  change   "−26% vs rules off"      a change never prints without its baseline
           "+10.5 pp vs original"   (rates: percentage points)
  usd      "$0.0029" in the body (4 decimals); "$0.002933" in the appendix (stats precision)
  count    "52"
"""

from __future__ import annotations

MINUS = "−"


def _pct_int(x: float) -> int:
    return int(x * 100 + 0.5)  # half up: 10.5% -> 11%


def rate(f: dict) -> str:
    return f"{f['k']}/{f['n']} ({_pct_int(f['k'] / f['n'])}%)"


def ci(f: dict) -> str:
    return f"95% CI {100 * f['ci_low']:.1f}–{100 * f['ci_high']:.1f}%"


def change(f: dict) -> str:
    v = f["value"]
    sign = "+" if v > 0 else MINUS if v < 0 else "±"
    if f["mode"] == "points":
        return f"{sign}{abs(v):.1f} pp vs {f['baseline']}"
    return f"{sign}{int(abs(v) * 100 + 0.5)}% vs {f['baseline']}"


def usd(v: float, appendix: bool = False) -> str:
    return f"${v:.6f}" if appendix else f"${v:.4f}"


def figure(f: dict, field: str | None = None, appendix: bool = False) -> str:
    """The text a {{key}} / {{key.field}} placeholder renders to."""
    kind = f["kind"]
    if field == "ci":
        return ci(f)
    if field == "k":
        return str(f["k"])
    if field == "n":
        return str(f["n"])
    if kind == "rate":          # value / pct / bare: always with the count
        return rate(f)
    if kind == "change":
        return change(f)
    if kind == "usd":
        return usd(f["value"], appendix)
    return str(int(f["value"]))
