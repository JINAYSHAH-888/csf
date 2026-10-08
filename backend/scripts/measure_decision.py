#!/usr/bin/env python3
"""Phase 7: which decision policy should combine the stages?

The cascade currently blocks on the FIRST non-allow verdict (disjunctive
fusion). Phase 5/6 measured what that costs on an unseen application: S1 OR S2
reaches 96.5% recall at 67.14% FPR, which is not a deployable system.

This compares candidate policies on IDENTICAL cached scores. Every policy is
tuned on CSIC and evaluated on ECML, because a policy tuned on the corpus it
is scored against is not a policy, it is a fit.
"""
from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.score_cache import ROOT, load_or_build  # noqa: E402

CLAIMED = {"sqli", "xss", "cmdi", "traversal"}

# Grids. S1 is a CRS anomaly score (unbounded, 5 per critical rule); S2 is a
# sum of named structural findings. They are NOT on the same scale and are
# never added together without being thresholded first -- see ADR-0011.
S1_GRID = [0, 3, 5, 8, 11, 15, 20, 25, 30, 35, 40, 50, 60, 80]
S2_GRID = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 12.0]

Policy = Callable[[dict], bool]


def rates(rows: list[dict], fires: Policy) -> tuple[float, float]:
    """(recall on claimed classes, FPR on benign), both as percentages."""
    claimed = [r for r in rows if r["label"] in CLAIMED]
    benign = [r for r in rows if r["label"] == "benign"]
    rec = sum(1 for r in claimed if fires(r)) / len(claimed) * 100
    fpr = sum(1 for r in benign if fires(r)) / len(benign) * 100
    return rec, fpr


# --- the candidate policies ----------------------------------------------
#
# Named after the fusion-rule taxonomy in the IDS alert-fusion literature:
# disjunctive (any), conjunctive (all), and cautious rules in between.

def disjunctive(t1: float, t2: float) -> Policy:
    """Block if EITHER stage blocks. What the gateway does today."""
    return lambda r: r["s1"] >= t1 or r["s2"] >= t2


def conjunctive(t1: float, t2: float) -> Policy:
    """Block only if BOTH stages block. Maximally cautious."""
    return lambda r: r["s1"] >= t1 and r["s2"] >= t2


def s1_only(t1: float, _t2: float) -> Policy:
    return lambda r: r["s1"] >= t1


def s2_only(_t1: float, t2: float) -> Policy:
    return lambda r: r["s2"] >= t2


def corroborated(t1_hi: float, t2_hi: float, t1_lo: float,
                 t2_lo: float) -> Policy:
    """Either stage ALONE when it is confident, or both together when neither is.

    This is the window-deferral idea from the cascade literature applied to
    fusion: a stage short-circuits only when its evidence is strong enough to
    stand by itself. Between the low and high marks it is corroborating
    evidence, not proof, and the decision waits for the other stage.
    """
    return lambda r: (
        r["s1"] >= t1_hi
        or r["s2"] >= t2_hi
        or (r["s1"] >= t1_lo and r["s2"] >= t2_lo)
    )


def sweep(name: str, build: Callable[..., Policy], params_list: list[tuple],
          csic: list[dict], ecml: list[dict]) -> list[dict]:
    """Characterise a policy across its parameter range on BOTH corpora.

    Deliberately not an optimiser. A search that maximises recall subject to a
    false-positive budget ON THE DEVELOPMENT CORPUS always selects the most
    aggressive S1 threshold available, because S1 has the higher in-corpus
    recall -- and S1 is precisely the stage measured not to transfer. The
    search would therefore pick the policy that collapses on an unseen
    application, every time, and report it as optimal.

    So the policy is not chosen by this script. It is chosen in ADR-0011 from
    a stated principle, and this shows what that principle costs.
    """
    rows = []
    print(f"\n  --- {name} ---")
    print(f"  {'params':<22} {'CSIC rec':>9} {'CSIC FPR':>9} | "
          f"{'ECML rec':>9} {'ECML FPR':>9}")
    for params in params_list:
        policy = build(*params)
        c_rec, c_fpr = rates(csic, policy)
        e_rec, e_fpr = rates(ecml, policy)
        print(f"  {str(params):<22} {c_rec:>8.1f}% {c_fpr:>8.2f}% | "
              f"{e_rec:>8.1f}% {e_fpr:>8.2f}%")
        rows.append({"policy": name, "params": list(params),
                     "csic_recall": c_rec, "csic_fpr": c_fpr,
                     "ecml_recall": e_rec, "ecml_fpr": e_fpr})
    return rows


def main() -> int:
    corpora = load_or_build()
    csic, ecml = corpora["CSIC"], corpora["ECML"]

    # S2's threshold is FIXED at the value the gateway already ships
    # (S2Config.tau_block). It was calibrated in Phase 6b and transfers: 57.7%
    # CSIC vs 56.3% ECML, a 1.4pp gap. Re-tuning it here would be fitting a
    # number that is already settled.
    TAU2 = 4.0
    # Thresholds of 0 are excluded: "score >= 0" always fires, which makes the
    # term vacuous and silently collapses conjunctive and corroborated into
    # disjunctive. The first version of this script did exactly that and
    # reported all five policies as identical.
    s1_points = [5, 8, 11, 15, 20, 25, 30, 40, 50]

    print("=" * 84)
    print("DECISION POLICY CHARACTERISATION")
    print("  S2 fixed at its shipped tau_block = 4.0; S1 threshold swept.")
    print("  No policy is selected here -- see ADR-0011.")
    print("=" * 84)

    all_rows: list[dict] = []
    all_rows += sweep("s1_only", s1_only, [(t, 0.0) for t in s1_points],
                      csic, ecml)
    all_rows += sweep("s2_only", s2_only, [(0, TAU2)], csic, ecml)
    all_rows += sweep("disjunctive (current gateway)", disjunctive,
                      [(t, TAU2) for t in s1_points], csic, ecml)
    all_rows += sweep("conjunctive", conjunctive,
                      [(t, TAU2) for t in s1_points], csic, ecml)
    # Corroborated: S1 may block alone only when very confident; otherwise it
    # must be seconded by S2. The low mark is where S1 stops being ignorable.
    all_rows += sweep("corroborated (s1_hi, 99, s1_lo, tau2)", corroborated,
                      [(hi, 99.0, 5, TAU2) for hi in [20, 25, 30, 40, 50, 99]],
                      csic, ecml)

    out = ROOT / "docs" / "benchmarks" / "decision-policy.json"
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "protocol": "characterisation on both corpora; no selection performed",
        "s2_tau_block": TAU2,
        "rows": all_rows,
    }, indent=2, sort_keys=True))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
