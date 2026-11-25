"""Report number formats (#17; designer Q4, 2026-11-24). PURE.

  rate     "12/19 (63.2%)"          a percentage never prints without its count
  ci       "95% CI 38.4–83.7%"
  change   "−25.7% vs <baseline>"   a change never prints without its baseline
           "+10.5 percentage points vs <baseline>"   (rates; spelled out, #17 review)
  Every percentage has ONE decimal, so a rate and a change of it agree (#17 review).
  usd      "$0.0029" in the body (4 decimals); "$0.002933" in the appendix (stats precision)
  count    "52"
"""

from __future__ import annotations

MINUS = "−"


def _pct1(x: float) -> str:
    return f"{100 * x:.1f}%"


def rate(f: dict) -> str:
    return f"{f['k']}/{f['n']} ({_pct1(f['k'] / f['n'])})"


def ci(f: dict) -> str:
    return f"95% CI {100 * f['ci_low']:.1f}–{100 * f['ci_high']:.1f}%"


def change(f: dict) -> str:
    v = f["value"]
    sign = "+" if v > 0 else MINUS if v < 0 else "±"
    if f["mode"] == "points":
        return f"{sign}{abs(v):.1f} percentage points vs {f['baseline']}"
    return f"{sign}{100 * abs(v):.1f}% vs {f['baseline']}"


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
