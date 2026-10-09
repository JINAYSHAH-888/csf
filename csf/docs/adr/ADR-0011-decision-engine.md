# ADR-0011 — Disjunctive fusion, deferral on FLAG, and a block-rate budget

**Status:** Accepted (Phase 7) · **Date:** 2026-10-07

## Context

The gateway decided inline: walk the detectors, take the first verdict that is
not ALLOW, stop. Phase 7 asked whether a better decision rule exists, and
measured candidate rules on both corpora using cached per-request S1/S2 scores
so that every policy saw identical inputs.

## The measurement that decided it

Tuned nothing. Characterised each fusion rule across S1's threshold range with
S2 fixed at its shipped `tau_block = 4.0`:

| policy | params | CSIC rec | CSIC FPR | ECML rec | ECML FPR |
|---|---|---|---|---|---|
| disjunctive | s1≥8 (**shipped default**) | 90.3% | 0.00% | 99.8% | **96.71%** |
| disjunctive | s1≥11 | 88.8% | 0.00% | 96.4% | 67.14% |
| disjunctive | s1≥30 | 78.4% | 0.00% | 77.1% | 4.00% |
| conjunctive | s1≥20 | 53.0% | 0.00% | 51.6% | 1.71% |
| conjunctive | s1≥25 | 50.6% | 0.00% | 46.1% | 0.57% |
| corroborated | s1_hi=30 | 77.7% | 0.00% | 77.1% | 4.00% |
| S2 alone | — | 57.7% | 0.00% | 56.3% | 3.43% |

Two findings, and the second is the important one.

**1. The fusion rule is not the lever.** The Pareto frontier of the unseen
application contains only `disjunctive` and `s1_only`. Conjunctive never
reaches it — at a comparable false-positive rate it gives 51.6% recall where
disjunctive gives 77.1%. Corroborated fusion is numerically indistinguishable
from disjunctive, because S2 almost never fires where S1 is silent (measured
earlier: S2-only catches 0.4% on ECML). A cleverer rule was built, measured,
and rejected.

**2. The development corpus cannot choose the operating point.** Every policy
at every setting measured **0.00% FPR on CSIC**. The same settings range from
0% to 96.71% FPR on an unseen application. There is no threshold search over
the development corpus that would have found this, and an optimiser that
maximises recall subject to a CSIC false-positive budget selects `s1≥8` —
the single worst setting on the unseen application — and reports it as optimal.
The first version of the Phase 7 script did exactly that.

## Decisions

### 1. Fusion stays disjunctive
Any stage that blocks, blocks. Not for simplicity — because the alternatives
were measured and are worse. Scores from different stages are **never added**:
a CRS anomaly score and a sum of grammar findings are different scales, and
summing them would invent a quantity neither stage computed.

### 2. FLAG defers; only BLOCK short-circuits
"First non-ALLOW wins" treated FLAG as terminal, so a stage reporting partial
suspicion suppressed every later stage and the request was allowed having been
seen by one detector. This inverts the deferral rule from the cascade
literature, where a sample near the decision boundary is exactly the one worth
spending a later stage on.

Measured impact, stated honestly: **2 of 421 claimed attacks on CSIC (0.5%)
and 0 of 2800 on ECML** were blocked by S2 but never reached it. Small. It is
fixed because it is a silent logic error whose size is a function of threshold
configuration, not because it moved a benchmark.

### 3. The S1 default is NOT changed on this evidence
`s1≥8` gives 96.71% FPR on ECML and the temptation is to raise it to 30.
Rejected: ECML is one corpus, generated, with known label-quality problems
(Phase 6b §5). Choosing a shipped default by fitting it to a single unseen
corpus is the same error as choosing it by fitting to the development corpus,
and this ADR would be arguing against itself. The operating point is
application-specific and is set during shadow mode.

### 4. A block-rate budget, reported and never self-applied
Since no corpus can supply the operating point, the system observes it.
`DecisionEngine` tracks the block rate over a rolling window and reports
`enforcement_blockers()` when it exceeds the configured budget. This surfaces
in `/statusz` and in gateway readiness, so enabling enforcement is gated by an
observation rather than by hope.

**It never de-escalates automatically.** An "if the block rate is high, stop
blocking" rule is an off switch an attacker pulls for free by sending attacks.
A breach is loud and gates a human action; it does not change what the engine
decides. `test_budget_breach_never_changes_the_decision` asserts this.

## Consequences

- `Decision`, `Stage` and `Verdict` moved to `csf/verdict.py`. The engine needs
  them and the gateway needs the engine, which is an import cycle while they
  live together; a `Verdict` has nothing to do with ASGI anyway.
  `csf.gateway` re-exports all three.
- The audit record now carries **every** objecting stage and the stages skipped
  by the short circuit, not only the first stage to object.
- `RATE_LIMIT` and `CHALLENGE` remain in the enum and unproduced. The engine
  passes them through rather than rounding them to BLOCK: an audit log that
  claims an action the gateway never took is worse than no audit log. Rate
  limiting remains an unimplemented gap.

## Known limitations

- **The budget guard cannot distinguish a misconfiguration from an attack
  campaign.** A real flood of attacks raises the block rate exactly as a bad
  threshold does, so the guard will report "over budget" during an incident.
  That is tolerable precisely because it only reports; it would be dangerous
  if it acted. Verified in the container: 200 attack requests drove the rate
  to 96.19%, the blocker fired, and the gateway kept blocking all 202.
- The budget is a single global rate. Per-route budgets would be more useful
  on an application whose endpoints differ wildly in traffic mix; not built.
- Fusion is fixed at disjunctive in code rather than configurable. Making it
  configurable would invite deploying a rule this ADR measured as worse.
