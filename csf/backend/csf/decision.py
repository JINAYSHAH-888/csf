"""S4: the decision engine — how stage verdicts become one action.

Why this is a module and not an `if` in the request path
--------------------------------------------------------
The gateway used to decide inline: walk the detectors, take the first verdict
that is not ALLOW, stop. Two things were wrong with that, and only one of them
is about code structure.

**The logic error.** "First non-ALLOW wins" treats FLAG as terminal. FLAG means
*allow and record*, so a stage reporting partial suspicion silently suppressed
every later stage and the request was allowed having been seen by one detector.
The cascade literature says the opposite: a sample near the decision boundary
is exactly the one worth spending a later stage on. Measured impact on the
corpora in hand: 2 of 421 claimed attacks on CSIC (0.5%) and 0 of 2800 on ECML
were blocked by S2 but never reached it. Small — recorded as small — but it is
a silent hole whose size depends entirely on how the thresholds are set.

**The thing that actually matters.** Phase 7 compared fusion rules
(disjunctive, conjunctive, corroborated) across both corpora and found the
fusion rule is not the lever. Only disjunctive and S1-alone appear on the
Pareto frontier of the unseen application; conjunctive costs recall without
buying enough FPR. What decides whether CSF is deployable is the **operating
point** — and the development corpus cannot choose it, because every policy
measured 0.00% FPR there while the same settings ranged from 0% to 96.71% FPR
on an unseen application.

So the engine's real job is not cleverness about combining scores. It is to
make the operating point explicit, observable, and hard to get catastrophically
wrong without noticing. See ADR-0011.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from csf.verdict import Decision, Stage, Verdict

__all__ = [
    "BudgetState",
    "DecisionConfig",
    "DecisionEngine",
    "Outcome",
    "StageEvidence",
]


@dataclass(frozen=True, slots=True)
class StageEvidence:
    """What one stage concluded. Kept per stage rather than collapsed, so the
    audit record can say *everything* that contributed rather than only the
    stage that happened to be consulted first."""

    stage: Stage
    decision: Decision
    score: float = 0.0
    reason: str = ""


@dataclass(frozen=True, slots=True)
class DecisionConfig:
    """Policy. Every field here is an operating-point choice, not a tuning
    constant: the measurements say these cannot be inferred from a corpus."""

    #: Stop the cascade as soon as a stage BLOCKs. Later stages cannot change
    #: a disjunctive outcome, so consulting them only costs latency.
    #:
    #: FLAG never stops the cascade. That is the fix described in the module
    #: docstring, and it is also the deferral rule the cascade literature
    #: recommends: spend later stages on the uncertain cases, not the settled
    #: ones.
    short_circuit_on_block: bool = True

    #: Expected ceiling on the fraction of traffic this configuration blocks,
    #: as a percentage. This is NOT a detection threshold — it is the operator
    #: stating what a sane block rate looks like for their application, so the
    #: system can notice when its thresholds do not fit the traffic.
    #:
    #: Measured justification: the shipped S1 threshold blocks 0.00% of the
    #: development corpus and 96.71% of an unseen application's benign
    #: traffic. Nothing in the detector can tell those two apart; only the
    #: observed rate can.
    max_block_rate_pct: float = 5.0

    #: Don't judge the rate until this many requests have been seen. A block
    #: rate computed over 10 requests is noise.
    budget_min_samples: int = 200

    #: Rolling window for the observed rate.
    budget_window: int = 2000


@dataclass(slots=True)
class Outcome:
    """The engine's answer, plus everything needed to explain it."""

    decision: Decision = Decision.ALLOW
    #: The stage whose verdict determined the action.
    stage: Stage = Stage.NONE
    reason: str = ""
    score: float = 0.0
    #: Every stage that was consulted and returned something other than ALLOW.
    contributing: list[StageEvidence] = field(default_factory=list)
    #: Stages that were never consulted because the cascade stopped early.
    skipped: tuple[Stage, ...] = ()

    def explain(self) -> str:
        if not self.contributing:
            return "no stage objected"
        return " | ".join(
            f"{e.stage}={e.decision}({e.score:g}): {e.reason}"
            for e in self.contributing
        )


@dataclass(slots=True)
class BudgetState:
    """Observed block rate against the configured budget."""

    observed_pct: float = 0.0
    samples: int = 0
    over_budget: bool = False
    #: False until enough traffic has been seen to judge.
    conclusive: bool = False


class DecisionEngine:
    """Combines stage verdicts and watches the resulting block rate.

    Fusion is **disjunctive**: any stage that blocks, blocks. That is not a
    default chosen for simplicity — Phase 7 measured conjunctive and
    corroborated fusion on both corpora and neither reaches the Pareto
    frontier of the unseen application. Conjunctive at a matched false-positive
    rate gives 51.6% recall where disjunctive gives 77.1%. A more elaborate
    rule was tried, measured, and rejected.
    """

    def __init__(self, config: DecisionConfig | None = None) -> None:
        self._cfg = config or DecisionConfig()
        self._recent: deque[bool] = deque(maxlen=self._cfg.budget_window)
        self.decisions = 0
        self.blocks = 0
        self.flags = 0
        self.budget_breaches = 0

    @property
    def config(self) -> DecisionConfig:
        return self._cfg

    def defers(self, verdict: Verdict) -> bool:
        """Should the cascade continue after this verdict?

        Only a BLOCK can end it. ALLOW obviously continues; FLAG continues
        because a partial signal is the case a later stage is most likely to
        resolve, and because FLAG does not stop the request anyway.
        """
        return not (verdict.decision is Decision.BLOCK
                    and self._cfg.short_circuit_on_block)

    def decide(self, evidence: list[StageEvidence],
               skipped: tuple[Stage, ...] = ()) -> Outcome:
        """Fuse the collected evidence into one action.

        Pure: it records nothing and mutates nothing. ``observe`` does the
        counting, so a caller can evaluate a decision without polluting the
        budget statistics — which is what the offline policy comparison needs.
        """
        contributing = [e for e in evidence if e.decision is not Decision.ALLOW]

        blocking = [e for e in contributing if e.decision is Decision.BLOCK]
        if blocking:
            # The strongest blocking stage is named as the cause. Ties go to
            # the earliest, which is the cheapest stage that was sufficient.
            top = max(blocking, key=lambda e: e.score)
            return Outcome(Decision.BLOCK, top.stage, top.reason, top.score,
                           contributing, skipped)

        flagging = [e for e in contributing if e.decision is Decision.FLAG]
        if flagging:
            top = max(flagging, key=lambda e: e.score)
            return Outcome(Decision.FLAG, top.stage, top.reason, top.score,
                           contributing, skipped)

        # RATE_LIMIT and CHALLENGE are defined in the Decision enum but no
        # stage produces them yet, and nothing here invents them. They are
        # carried as an unimplemented gap rather than quietly mapped onto
        # BLOCK, which would make the audit log claim an action the gateway
        # never took.
        if contributing:
            first = contributing[0]
            return Outcome(first.decision, first.stage, first.reason,
                           first.score, contributing, skipped)

        return Outcome(skipped=skipped)

    def observe(self, outcome: Outcome) -> None:
        """Record an outcome against the block-rate budget."""
        self.decisions += 1
        is_block = outcome.decision is Decision.BLOCK
        if is_block:
            self.blocks += 1
        elif outcome.decision is Decision.FLAG:
            self.flags += 1
        self._recent.append(is_block)
        state = self.budget()
        if state.over_budget:
            self.budget_breaches += 1

    def budget(self) -> BudgetState:
        """Observed block rate over the rolling window."""
        n = len(self._recent)
        if n == 0:
            return BudgetState()
        pct = sum(self._recent) / n * 100
        conclusive = n >= self._cfg.budget_min_samples
        return BudgetState(
            observed_pct=pct,
            samples=n,
            over_budget=conclusive and pct > self._cfg.max_block_rate_pct,
            conclusive=conclusive,
        )

    def enforcement_blockers(self) -> list[str]:
        """Why enforcing would be unsafe right now, if it would be.

        Consulted when an operator turns enforcement ON. It is deliberately
        **not** consulted per request.

        An automatic "block rate is high, so stop enforcing" rule would be a
        vulnerability, not a safety feature: an attacker who can raise the
        block rate — by sending attacks, which is free — could switch the
        firewall off. So a breach is surfaced loudly and gates a human action;
        it never changes behaviour on its own.
        """
        state = self.budget()
        if not state.over_budget:
            return []
        return [
            f"observed block rate {state.observed_pct:.2f}% over "
            f"{state.samples} requests exceeds the configured budget of "
            f"{self._cfg.max_block_rate_pct:.2f}%; these thresholds do not "
            f"fit this application's traffic and enforcing them would block "
            f"legitimate requests"
        ]

    def snapshot(self) -> dict[str, float | int | bool]:
        state = self.budget()
        return {
            "decisions": self.decisions,
            "blocks": self.blocks,
            "flags": self.flags,
            "block_rate_pct": round(state.observed_pct, 4),
            "block_rate_samples": state.samples,
            "block_rate_conclusive": state.conclusive,
            "over_budget": state.over_budget,
            "budget_breaches": self.budget_breaches,
        }
