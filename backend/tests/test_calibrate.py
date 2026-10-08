"""Shadow-mode operating-point calibration (closes the no-safe-default gap)."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import calibrate  # noqa: E402


def test_picks_lowest_thresholds_within_budget():
    # Mostly-benign traffic: a few requests score moderately. At budget 1%,
    # the tool must pick thresholds that keep block rate <= 1%.
    scored = [(0.0, 0.0)] * 980 + [(12.0, 5.0)] * 20  # 2% score 12/5
    rec = calibrate.recommend(scored, budget_pct=1.0)
    assert rec is not None
    t1, t2, rate = rec
    # To get under 1%, S1 must exceed 12 or S2 exceed 5 for those 20.
    assert rate <= 1.0
    assert t1 > 12 or t2 > 5.0


def test_returns_none_when_nothing_fits_budget():
    # Half the traffic scores very high -> no threshold in the grid gets the
    # block rate under a 1% budget. The tool must refuse, not invent a point.
    scored = [(50.0, 10.0)] * 500 + [(0.0, 0.0)] * 500
    assert calibrate.recommend(scored, budget_pct=1.0) is None


def test_looser_budget_allows_more_sensitive_thresholds():
    scored = [(0.0, 0.0)] * 950 + [(12.0, 0.0)] * 50  # 5% score S1=12
    tight = calibrate.recommend(scored, budget_pct=1.0)
    loose = calibrate.recommend(scored, budget_pct=6.0)
    assert tight is not None and loose is not None
    # A looser budget tolerates the 5%, so it can keep the lower S1 threshold.
    assert loose[0] <= tight[0]
