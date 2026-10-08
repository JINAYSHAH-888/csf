"""S4 decision engine: fusion, deferral, and the block-rate budget."""

from __future__ import annotations

import pytest

from csf.decision import DecisionConfig, DecisionEngine, StageEvidence
from csf.verdict import Decision, Stage, Verdict


def ev(stage: Stage, decision: Decision, score: float = 0.0, reason: str = "") -> StageEvidence:
    return StageEvidence(stage=stage, decision=decision, score=score, reason=reason)


# -- deferral --------------------------------------------------------------
#
# The rule that was wrong before this module existed. FLAG means "allow and
# record"; treating it as terminal allowed requests after consulting exactly
# one stage.


def test_block_stops_the_cascade():
    engine = DecisionEngine()
    assert not engine.defers(Verdict(Decision.BLOCK, Stage.RULES))


@pytest.mark.parametrize("decision", [Decision.ALLOW, Decision.FLAG])
def test_allow_and_flag_both_continue_the_cascade(decision):
    engine = DecisionEngine()
    assert engine.defers(Verdict(decision, Stage.RULES)), (
        "a non-blocking verdict must not suppress later stages"
    )


def test_short_circuit_can_be_disabled():
    engine = DecisionEngine(DecisionConfig(short_circuit_on_block=False))
    assert engine.defers(Verdict(Decision.BLOCK, Stage.RULES))


# -- fusion ----------------------------------------------------------------
#
# Disjunctive, and that is a measured choice (ADR-0011): conjunctive and
# corroborated fusion were compared on both corpora and neither reaches the
# Pareto frontier of the unseen application.


def test_any_blocking_stage_blocks():
    engine = DecisionEngine()
    out = engine.decide([ev(Stage.RULES, Decision.ALLOW),
                         ev(Stage.SEMANTIC, Decision.BLOCK, 7.0, "sqli")])
    assert out.decision is Decision.BLOCK
    assert out.stage is Stage.SEMANTIC


def test_strongest_blocking_stage_is_named_as_the_cause():
    engine = DecisionEngine()
    out = engine.decide([ev(Stage.RULES, Decision.BLOCK, 12.0, "crs"),
                         ev(Stage.SEMANTIC, Decision.BLOCK, 40.0, "grammar")])
    assert out.stage is Stage.SEMANTIC
    assert out.score == 40.0


def test_flag_only_evidence_yields_a_flag_not_a_block():
    engine = DecisionEngine()
    out = engine.decide([ev(Stage.RULES, Decision.FLAG, 3.0),
                         ev(Stage.SEMANTIC, Decision.FLAG, 2.0)])
    assert out.decision is Decision.FLAG, (
        "two weak signals must not be summed into a block; the engine fuses "
        "verdicts, it does not add scores from different scales"
    )


def test_no_objection_is_an_allow():
    assert DecisionEngine().decide([ev(Stage.RULES, Decision.ALLOW)]).decision \
        is Decision.ALLOW


def test_empty_evidence_is_an_allow():
    assert DecisionEngine().decide([]).decision is Decision.ALLOW


# -- explainability --------------------------------------------------------


def test_every_objecting_stage_is_recorded_not_just_the_decisive_one():
    engine = DecisionEngine()
    out = engine.decide([ev(Stage.RULES, Decision.FLAG, 3.0, "weak crs"),
                         ev(Stage.SEMANTIC, Decision.BLOCK, 7.0, "sqli")])
    assert [e.stage for e in out.contributing] == [Stage.RULES, Stage.SEMANTIC]
    assert "weak crs" in out.explain() and "sqli" in out.explain()


def test_allowing_stages_are_not_listed_as_contributing():
    out = DecisionEngine().decide([ev(Stage.RULES, Decision.ALLOW),
                                   ev(Stage.SEMANTIC, Decision.BLOCK, 7.0)])
    assert [e.stage for e in out.contributing] == [Stage.SEMANTIC]


def test_skipped_stages_are_reported():
    out = DecisionEngine().decide([ev(Stage.RULES, Decision.BLOCK, 9.0)],
                                  skipped=(Stage.SEMANTIC, Stage.MODEL))
    assert out.skipped == (Stage.SEMANTIC, Stage.MODEL)


def test_unimplemented_actions_are_not_silently_mapped_to_block():
    """RATE_LIMIT exists in the enum and no stage produces it.

    If one did, the engine must pass it through rather than rounding it to
    BLOCK -- an audit log that claims an action the gateway never took is
    worse than no audit log.
    """
    out = DecisionEngine().decide([ev(Stage.RULES, Decision.RATE_LIMIT, 1.0)])
    assert out.decision is Decision.RATE_LIMIT


# -- block-rate budget -----------------------------------------------------
#
# The operating point cannot be chosen from the development corpus: Phase 7
# measured 0.00% FPR there for every policy, while the same settings ranged
# to 96.71% FPR on an unseen application. The only thing that can tell an
# operator their thresholds do not fit is the observed rate.


def _run(engine: DecisionEngine, blocks: int, allows: int) -> None:
    for _ in range(blocks):
        engine.observe(engine.decide([ev(Stage.RULES, Decision.BLOCK, 9.0)]))
    for _ in range(allows):
        engine.observe(engine.decide([ev(Stage.RULES, Decision.ALLOW)]))


def test_block_rate_is_not_judged_before_enough_samples():
    engine = DecisionEngine(DecisionConfig(max_block_rate_pct=5.0,
                                           budget_min_samples=200))
    _run(engine, blocks=10, allows=0)          # 100% block rate, n=10
    state = engine.budget()
    assert state.observed_pct == 100.0
    assert not state.conclusive
    assert not state.over_budget, "10 requests cannot establish a block rate"


def test_block_rate_over_budget_is_detected():
    engine = DecisionEngine(DecisionConfig(max_block_rate_pct=5.0,
                                           budget_min_samples=100))
    _run(engine, blocks=50, allows=150)        # 25%
    state = engine.budget()
    assert state.conclusive
    assert state.over_budget
    assert engine.enforcement_blockers()


def test_block_rate_within_budget_reports_ready():
    engine = DecisionEngine(DecisionConfig(max_block_rate_pct=5.0,
                                           budget_min_samples=100))
    _run(engine, blocks=4, allows=196)         # 2%
    assert not engine.budget().over_budget
    assert engine.enforcement_blockers() == []


def test_budget_breach_never_changes_the_decision():
    """The security property. An automatic "too many blocks, stop blocking"
    rule would be an off switch an attacker can pull for free by sending
    attacks. A breach is reported and gates a human action; it must not alter
    what the engine decides."""
    engine = DecisionEngine(DecisionConfig(max_block_rate_pct=1.0,
                                           budget_min_samples=10))
    _run(engine, blocks=500, allows=0)
    assert engine.budget().over_budget
    out = engine.decide([ev(Stage.SEMANTIC, Decision.BLOCK, 7.0, "sqli")])
    assert out.decision is Decision.BLOCK, (
        "the engine de-escalated under load: an attacker can disable it"
    )


def test_window_is_bounded():
    engine = DecisionEngine(DecisionConfig(budget_window=100,
                                           budget_min_samples=10))
    _run(engine, blocks=100, allows=100)
    assert engine.budget().samples == 100, "the rolling window must stay bounded"
    assert engine.budget().observed_pct == 0.0, "window should hold only the recent allows"


def test_snapshot_exposes_the_rate_for_operators():
    engine = DecisionEngine(DecisionConfig(max_block_rate_pct=5.0,
                                           budget_min_samples=10))
    _run(engine, blocks=10, allows=90)
    snap = engine.snapshot()
    assert snap["decisions"] == 100
    assert snap["blocks"] == 10
    assert snap["block_rate_pct"] == 10.0
    assert snap["over_budget"] is True
