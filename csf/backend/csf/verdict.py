"""The vocabulary every stage and the decision engine share.

Extracted from ``csf.gateway`` when the decision engine was introduced: the
engine needs these types and the gateway needs the engine, which is a cycle
while they live together. They belong here anyway — a ``Verdict`` is what a
detector produces, and detectors have nothing to do with ASGI.

``csf.gateway`` re-exports all three, so existing imports keep working.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["Decision", "Stage", "Verdict"]


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "allow_and_flag"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"


class Stage(StrEnum):
    """Which stage produced a verdict. Required in the audit log so an
    operator can diagnose a block without reading source."""

    NONE = "none"
    FRAMING = "s0_framing"
    LIMITS = "s0_limits"
    AUTH = "s0_auth"
    RULES = "s1_rules"
    SEMANTIC = "s2_semantic"
    MODEL = "s3_model"
    DECISION = "s4_decision"


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision = Decision.ALLOW
    stage: Stage = Stage.NONE
    reason: str = ""
    #: The stage's graded signal, where it has one.
    score: float = 0.0
