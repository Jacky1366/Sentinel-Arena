"""D60 (a) as code: analyst/confidence.py. Every row of the pre-registered table."""

from __future__ import annotations

import pytest

from llm_fakes import REPO  # noqa: F401 (repo on sys.path)
from analyst.confidence import THRESHOLD, cp95, figure_confidence, finding_confidence
from stats.autonomy import cp_upper_zero


@pytest.mark.parametrize("basis", ["audited", "ground_truth", "measured"])
def test_n_at_least_20_is_high_below_is_moderate(basis):
    assert THRESHOLD == 20
    assert figure_confidence(basis, 20) == "High"
    assert figure_confidence(basis, 28) == "High"      # Gate B
    assert figure_confidence(basis, 19) == "Moderate"  # free-play (against our headline)
    assert figure_confidence(basis, 3) == "Moderate"   # 3 matches: counts and costs too


@pytest.mark.parametrize("n", [1, 19, 20, 500])
def test_raw_is_low_whatever_n(n):
    assert figure_confidence("raw", n) == "Low"


def test_open_blue_is_capped_at_moderate():
    assert figure_confidence("ground_truth", 57, open_blue=True) == "Moderate"
    assert figure_confidence("audited", 19, open_blue=True) == "Moderate"
    assert figure_confidence("raw", 57, open_blue=True) == "Low"   # a cap never raises


def test_finding_is_the_lowest_cited():
    assert finding_confidence(["High", "Moderate", "High"]) == "Moderate"
    assert finding_confidence(["High", "Low"]) == "Low"
    assert finding_confidence(["High"]) == "High"
    with pytest.raises(ValueError):
        finding_confidence([])
    with pytest.raises(ValueError):
        finding_confidence(["Certain"])


@pytest.mark.parametrize("basis,n", [("guess", 20), ("audited", 0), ("audited", 2.5),
                                     ("audited", True)])
def test_bad_inputs_are_refused(basis, n):
    with pytest.raises(ValueError):
        figure_confidence(basis, n)


def test_clopper_pearson_matches_committed_figures():
    assert cp95(6, 57) == (0.0396, 0.2152)              # 2c open FP, progress.md [3.96%, 21.5%]
    assert cp95(0, 57)[1] == round(cp_upper_zero(57), 4)  # same as the autonomy table
    assert cp95(0, 17) == (0.0, round(cp_upper_zero(17), 4))
    lo, hi = cp95(12, 19)
    assert lo < 12 / 19 < hi and cp95(28, 28)[1] == 1.0
