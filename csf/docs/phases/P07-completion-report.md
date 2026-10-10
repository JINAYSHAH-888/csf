# Phase 7 — Decision Engine — Completion Report

**Date:** 2026-10-07 · **Deliverable:** `csf/decision.py` (S4), wired into the
gateway · **ADR:** ADR-0011

---

## 1. What the phase was for

The gateway decided inline: walk the detectors, take the first verdict that is
not ALLOW, stop. Phase 7 asked whether a better rule exists.

The answer is mostly no — and finding that out is the result.

## 2. Research

Three strands from the literature framed the work:

- **Anomaly scoring** (what CRS itself does): accumulate weighted points from
  many weak signals, compare to a threshold. Already in use inside S1.
- **Alert-fusion rules for IDS**: disjunctive (any), conjunctive (all), and
  cautious rules between them; weighted voting; Dempster-Shafer evidence
  combination, reported to lift detection 75% → 93.8% without raising FPR.
- **Cascade deferral**: a deferral rule decides whether to invoke the next
  stage. The finding that mattered: *only samples near the decision boundary
  should be evaluated by more costly stages.* CSF's rule was the inverse — it
  stopped on FLAG, the most uncertain verdict it has.

## 3. Method

`scripts/score_cache.py` caches per-request S1 and S2 scores for both corpora.
`scripts/measure_decision.py` then compares policies over those cached scores,
so every policy is evaluated on **identical inputs** and a difference between
policies cannot be a difference in the traffic they saw.

**The first version of that script was an optimiser and it was wrong.** It
maximised recall subject to a false-positive budget on the development corpus.
Two failures:

1. Thresholds of 0 were in the grid. `s2 >= 0` always fires, which silently
   collapsed conjunctive and corroborated into disjunctive — all five policies
   reported identical numbers.
2. More fundamentally, a search on CSIC **always** selects the most aggressive
   S1 threshold, because S1 has the higher in-corpus recall. It chose `s1≥8`,
   the single worst setting on an unseen application, and labelled it optimal.

The script was rewritten as a characterisation that selects nothing. The policy
is chosen in ADR-0011 from a stated principle, and the script shows the cost.

## 4. Results

| policy | params | CSIC rec | CSIC FPR | ECML rec | ECML FPR |
|---|---|---|---|---|---|
| disjunctive | s1≥8 (**shipped default**) | 90.3% | 0.00% | 99.8% | **96.71%** |
| disjunctive | s1≥11 | 88.8% | 0.00% | 96.4% | 67.14% |
| disjunctive | s1≥25 | 83.1% | 0.00% | 82.5% | 6.43% |
| disjunctive | s1≥30 | 78.4% | 0.00% | 77.1% | 4.00% |
| conjunctive | s1≥20 | 53.0% | 0.00% | 51.6% | 1.71% |
| corroborated | s1_hi=30 | 77.7% | 0.00% | 77.1% | 4.00% |
| S2 alone | — | 57.7% | 0.00% | 56.3% | 3.43% |

**The Pareto frontier of the unseen application contains only `disjunctive`
and `s1_only`.** Conjunctive never reaches it. Corroborated is numerically
indistinguishable from disjunctive, because S2 rarely fires where S1 is silent.

**Every policy measured 0.00% FPR on CSIC** while the same settings ranged to
96.71% on ECML. That is the phase's headline: the development corpus carries no
information about the choice that determines whether CSF is deployable.

## 5. What was built

1. **`csf/decision.py`** — `DecisionEngine`: disjunctive fusion, deferral,
   evidence collection, block-rate budget. Pure `decide()`, separate
   `observe()`, so a decision can be evaluated without polluting statistics.
2. **Deferral fixed** — only BLOCK short-circuits; FLAG continues to the next
   stage.
3. **Block-rate budget** — rolling-window observed block rate, surfaced in
   `/statusz` and gateway readiness. **Reports, never de-escalates**: an
   automatic "too many blocks, stop blocking" rule is an off switch an attacker
   pulls for free.
4. **Richer audit** — every objecting stage and every skipped stage, not just
   the first objector.
5. **`csf/verdict.py`** — `Decision`/`Stage`/`Verdict` extracted to break the
   gateway↔engine import cycle.
6. **`decision` config section**, validated, in both example configs.

## 6. The defect fixed, sized honestly

FLAG was terminal, so a weak signal from a cheap stage suppressed every later
stage and the request was allowed having been seen by one detector.

Measured impact: **2 of 421 claimed attacks on CSIC (0.5%), 0 of 2800 on
ECML.** Small. It is fixed because it is a silent logic error whose size is a
function of threshold configuration, not because it moved a benchmark. The
regression test was verified to fail against the old rule before being kept.

## 7. Exit gates

| gate | result |
|---|---|
| A decision policy chosen on measurement, not intuition | **PASS** — three fusion rules characterised on both corpora |
| The chosen policy is on the Pareto frontier of the unseen application | **PASS** — disjunctive is; conjunctive and corroborated are not |
| Deferral rule does not suppress later stages | **PASS** — regression test verified to fail against the old rule |
| Operating point is observable at runtime | **PASS** — block rate in `/statusz` and readiness |
| No automatic de-escalation under load | **PASS** — asserted by test; verified in container (202/202 still blocked at 96.19% rate) |
| Cost-ordering preserved | **PASS** — BLOCK still short-circuits |
| **A decision policy that is safe by default on an unseen application** | **FAIL** — see below |

## 8. The gate that failed

**The shipped S1 default blocks 96.71% of an unseen application's benign
traffic.** Phase 7 did not fix this, and deliberately did not paper over it.

Raising the default to `s1≥30` would make the ECML number look good (4.00%
FPR). It was rejected: ECML is one corpus, generated, with known label-quality
problems. Choosing a shipped default by fitting it to a single unseen corpus is
the same methodological error as fitting it to the development corpus, and this
phase exists to argue against exactly that.

So the honest position is: **CSF has no safe default operating point, and
cannot have one that is derived from the two corpora available.** What Phase 7
delivers instead is the machinery to discover the right one per application
during shadow mode, and to refuse to call the system ready for enforcement
until that has been done. The default remains unsafe if someone enables
enforcement without a shadow period; the guard makes that visible, not
impossible.

## 9. Verification

- **503 tests** (473 before; 30 added), `ruff` clean, `mypy --strict` clean.
- Regression test confirmed to fail against the old deferral rule.
- Verified in the **containerised** gateway: engine logs its policy at startup,
  `/statusz` reports the live block rate, the guard correctly declines to judge
  at 10 samples (`conclusive: false`), fires at 210 samples, and the gateway
  keeps blocking throughout.

## 10. Carried forward

- No safe default operating point (§8).
- Budget is one global rate; no per-route budgets.
- The guard cannot distinguish a misconfiguration from an attack campaign —
  tolerable only because it reports rather than acts.
- `RATE_LIMIT` and `CHALLENGE` remain unproduced; rate limiting is still not
  implemented.
- Frozen CSIC test holdout still untouched.
