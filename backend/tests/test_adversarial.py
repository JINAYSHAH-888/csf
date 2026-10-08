"""Phase 8 adversarial findings, as permanent regression tests.

The threat model requires every vulnerability found to become a regression
test. Phase 8's black-box mutation harness found one class: an unterminated
``/*`` comment that sqlglot (hence S2) failed to parse while sqlite still
executed the attack behind it — a parser differential, the bypass class T3
calls the most likely real one. Thirty-one mutated payloads evaded S2 this way;
all are the same shape and all are fixed by the backend-tolerant comment view
in csf/semantic/sql.py.

These tests also pin the harness itself: a mutation oracle that drifts would
silently stop finding evasions, and a green suite would then mean nothing.
"""

from __future__ import annotations

import pytest

from csf.adversarial import (
    SQL_OPERATORS,
    Mutator,
    sqlite_attack_survives,
)
from csf.semantic.sql import analyze_sql

BLOCK = 4.0


# -- the found vulnerability: unterminated /* parser differential ----------
#
# Each payload below evaded S2 (score 0) before the fix while still executing
# as an attack in sqlite. They are the distinct shapes from the 31 evasions.

DANGLING_COMMENT_EVASIONS = [
    "x' UNION SELECT NULL,NULL/*",
    "x'/**/UNION SELECT NULL,NULL/*",
    "x' UNION\tSELECT NULL,NULL/*",
    "x'/**/UNION\tSELECT NULL,NULL/*",
    "x'/**/UNION/**/SELECT NULL,NULL/*",
    "1' UNiOn ALL SeLeCt @@version/*",
    "1e0' UNiOn ALL SeLeCt @@version/*",
    "x' UNiOn\tSeleCT Null,nuLl/*",
    "x' OR 'a'='a' /*",          # the case S2's own docstring flagged years ago
    "1' OR '1'='1'/*",
]


@pytest.mark.parametrize("payload", DANGLING_COMMENT_EVASIONS)
def test_dangling_comment_evasions_are_blocked(payload):
    """The parser differential is closed: S2 now analyses the backend-tolerant
    reading of a dangling /* and blocks what executes behind it."""
    assert analyze_sql(payload).score >= BLOCK


@pytest.mark.parametrize("payload", DANGLING_COMMENT_EVASIONS)
def test_dangling_comment_evasions_really_were_attacks(payload):
    """Guards the measurement, not the code. If the oracle ever stops seeing
    these as attacks, the evasion rate they drove would be meaningless, so the
    'fixed' claim would be hollow. sqlite — an independent parser — must still
    execute each as an injection."""
    assert sqlite_attack_survives(payload)


# -- the fix must not flag benign values that merely contain /* ------------

@pytest.mark.parametrize("value", [
    "a/*b",
    "rate 3/4 */ day",
    "/* promo */ sale",
    "comment /* todo */ here",
    "path/to/*.js",
    "SELECT a size/*",      # SQL-ish prose with a dangling /*, still benign
    "my cat/*dog",
    "x/*y",
])
def test_benign_values_with_comment_syntax_stay_inert(value):
    assert analyze_sql(value).score == 0.0


# -- the mutation oracle itself --------------------------------------------
#
# The whole harness rests on sqlite_attack_survives telling attacks from
# broken strings. If it drifts, a 0% evasion rate means nothing.

@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "alice' -- ",
    "'; UPDATE t SET secret='x' -- ",
    "' OR c='bob' -- ",
    "' UNION SELECT c,secret FROM t -- ",
])
def test_oracle_recognises_real_attacks(payload):
    assert sqlite_attack_survives(payload)


@pytest.mark.parametrize("value", [
    "alice", "bob", "nomatch", "just text", "a normal product name",
])
def test_oracle_rejects_non_attacks(value):
    """A legitimate value is NOT an evasion no matter how the analyser scores
    it; counting these would inflate the evasion rate with harmless noise."""
    assert not sqlite_attack_survives(value)


# -- the mutators preserve the attack --------------------------------------

def test_mutator_only_yields_surviving_variants():
    """Every variant the mutator yields must still be an attack per the
    oracle — otherwise the harness would test the analyser against strings
    that are not attacks and call a miss an evasion."""
    mut = Mutator(SQL_OPERATORS, sqlite_attack_survives, seed=3)
    variants = list(mut.variants("1' OR '1'='1", depth=2, per_depth=5))
    assert variants, "mutator produced nothing to check"
    assert all(sqlite_attack_survives(v.payload) for v in variants)


def test_mutations_change_the_payload():
    mut = Mutator(SQL_OPERATORS, sqlite_attack_survives, seed=3)
    seed = "x' UNION SELECT NULL,NULL-- "
    assert all(v.payload != seed for v in mut.variants(seed, depth=1, per_depth=6))
