"""Test the stage3_check tripwire: a scripted run must never produce a round with
landed_reason == "snapshot_missing" (contract §6.1). No Docker."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
import sys  # noqa: E402
sys.path.insert(0, str(REPO))
_spec = importlib.util.spec_from_file_location("stage3_check", REPO / "tools" / "stage3_check.py")
stage3_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage3_check)


def _round(rnd, landed_reason=None):
    return {"round": rnd, "landed_reason": landed_reason}


def test_no_snapshot_missing_passes():
    rounds = [_round(1), _round(2, "already_solved"), _round(3, "not_measurable")]
    assert stage3_check.tripwire_failures(rounds) == []


def test_one_snapshot_missing_fails():
    rounds = [_round(1), _round(2, "snapshot_missing")]
    fails = stage3_check.tripwire_failures(rounds)
    assert len(fails) == 1
    assert "snapshot_missing" in fails[0] and "[2]" in fails[0]


def test_multiple_snapshot_missing_all_reported():
    rounds = [_round(1, "snapshot_missing"), _round(2), _round(3, "snapshot_missing")]
    fails = stage3_check.tripwire_failures(rounds)
    assert len(fails) == 1
    assert "[1, 3]" in fails[0]
