"""Semantics-preserving mutation operators for adversarial evaluation (A3/A4).

Why this module exists
----------------------
The threat model (T1) commits to measured evasion targets rather than a claim
of unevadability: ≤15% for black-box mutation (A3, the WAF-A-MoLE class) and
≤20% for generated SQLi (A4). You cannot report a number you cannot produce, so
this is the generator that produces it.

The one invariant that makes a result meaningful
------------------------------------------------
A mutation is only an evasion if the payload **still attacks**. A transformation
that slips past the analyser by no longer being valid SQL/HTML/shell is not a
bypass, it is a broken string, and counting it would inflate the evasion rate
with harmless noise — exactly the kind of fabricated-positive result the build
rules forbid.

So every SQL mutation is checked for semantic preservation the only way we
honestly can without a live database: the mutated payload, injected into the
same template the analyser probes, must still parse to a tree that contains the
attack construct (a tautology, a UNION, a stacked statement, a comment
truncation). Mutations that destroy the attack are discarded before they ever
count. This is a *necessary* condition, not a sufficient one — parsing is not
execution — and §limitations in the Phase 8 report says so.

Scope
-----
These operators run only against our own analysers and our own gateway on
localhost. The module generates strings; it does not send them anywhere. The
harness that does send them (`scripts/measure_adversarial.py`) targets the
loopback gateway only.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import sqlglot

__all__ = ["Mutation", "Mutator", "sql_attack_survives",
           "sqlite_attack_survives", "SQL_OPERATORS"]


@dataclass(frozen=True, slots=True)
class Mutation:
    """One mutated payload and the operator chain that produced it."""

    payload: str
    operators: tuple[str, ...]

    def with_op(self, name: str, new_payload: str) -> Mutation:
        return Mutation(new_payload, (*self.operators, name))


# --------------------------------------------------------------------------
# Semantic-preservation oracle for SQL
# --------------------------------------------------------------------------
#
# The analyser's own contexts, abbreviated. A payload "still attacks" if, in
# at least one dialect and one context, it parses AND the parse contains a
# construct a benign leaf could not produce. We reuse sqlglot exactly as the
# analyser does, so the oracle and the thing under test agree on what "parses"
# means.

# ruff: noqa: S608 - these are injection PROBES by design, mirroring
# csf/semantic/sql.py. None of these strings ever reach a database; they are
# parsed in-process to ask whether a mutation preserved the attack.
_SENTINEL = "ZZSENTINELZZ"
_PROBES = (
    f"SELECT a FROM t WHERE c = '{{}}' AND d = '{_SENTINEL}'",
    f"SELECT a FROM t WHERE c = {{}} AND d = '{_SENTINEL}'",
    "SELECT a FROM t WHERE c = {}",
)
_DIALECTS = ("mysql", "postgres", "tsql")


def sql_attack_survives(payload: str) -> bool:
    """True if `payload` still realises an injection in some dialect/context.

    Deliberately conservative: it asks whether the payload can still escape a
    leaf position into query structure, which is the same question the analyser
    asks. A payload that only survives as an inert string literal returns False.
    """
    from sqlglot import exp  # local: keep import cost off module load

    for template in _PROBES:
        injected = template.format(payload)
        for dialect in _DIALECTS:
            try:
                statements = [s for s in sqlglot.parse(injected, dialect=dialect)
                              if s is not None]
            except Exception:  # noqa: BLE001, S112 - parse failure == variant
                # did not survive in this dialect; try the next. Nothing to log.
                continue
            if not statements:
                continue
            # More than one statement => stacked injection survived.
            if len(statements) > 1:
                return True
            tree = statements[0]
            # A UNION, a write, or a tautology (literal OP equal literal) that a
            # bound parameter could never introduce.
            if list(tree.find_all(exp.Union)):
                return True
            if list(tree.find_all(exp.Insert, exp.Update, exp.Delete, exp.Drop)):
                return True
            for node in tree.find_all(exp.EQ, exp.NEQ, exp.GT, exp.LT):
                left, right = node.left, node.right
                if isinstance(left, exp.Literal) and isinstance(right, exp.Literal):
                    return True
            # Comment truncation: the sentinel that follows the injection point
            # was swallowed, so the payload terminated the query early.
            if _SENTINEL in template and not any(
                str(lit.this) == _SENTINEL for lit in tree.find_all(exp.Literal)
            ):
                return True
    return False


def sqlite_attack_survives(payload: str) -> bool:
    """True if `payload` still realises an injection when EXECUTED by sqlite3.

    This is the honest oracle. ``sql_attack_survives`` above asks sqlglot --
    the very parser S2 uses -- whether the attack parses, so it can never find
    a mutation that evades S2, because "evades S2" and "sqlglot sees no attack"
    are the same event. An oracle coupled to the detector measures nothing.

    sqlite3 is a DIFFERENT parser. A mutation that sqlite still executes as an
    attack but that sqlglot (hence S2) reads as a benign leaf is a genuine
    parser differential -- the bypass class the threat model (T3) calls the
    most likely real one. Executing against a throwaway in-memory database is
    the only way to settle "does this still attack" without asking the thing
    under test.

    The fixture: a two-row table; the benign query matches nothing. The attack
    survives if the injected query returns a row (tautology/UNION), executes a
    second statement, or reaches data a bound parameter could not.
    """
    import sqlite3

    def _fixture() -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            "CREATE TABLE t (c TEXT, secret TEXT);"
            "INSERT INTO t VALUES ('alice','pw1'),('bob','pw2');")
        return conn

    template = "SELECT c, secret FROM t WHERE c = '{}'"

    # Baseline: the payload bound as a PARAMETER, i.e. treated as data. This is
    # what a safe application does, and it is the thing an injection is defined
    # against -- an injection is exactly a payload whose meaning as SQL differs
    # from its meaning as data.
    def _as_data() -> object:
        conn = _fixture()
        try:
            try:
                rows = conn.execute("SELECT c, secret FROM t WHERE c = ?",
                                    (payload,)).fetchall()
            except sqlite3.Error as exc:
                return ("error", type(exc).__name__)
            return ("rows", tuple(sorted(rows)))
        finally:
            conn.close()

    # Injected: the payload interpolated into the query, as a vulnerable
    # application would. Different outcome => the payload left its data
    # position and changed the query. That is the injection, proven by a parser
    # (sqlite) entirely independent of the one S2 detects with (sqlglot).
    def _as_sql() -> object:
        conn = _fixture()
        try:
            sql = template.format(payload)
            try:
                rows = conn.execute(sql).fetchall()
            except sqlite3.Error:
                # execute() runs one statement; a stacked or malformed payload
                # raises. Retry as a script to tell "stacked attack" (runs)
                # from "broken string" (still fails).
                conn2 = _fixture()
                try:
                    conn2.executescript(sql)
                    return ("stacked", True)
                except sqlite3.Error as exc:
                    return ("error", type(exc).__name__)
                finally:
                    conn2.close()
            return ("rows", tuple(sorted(rows)))
        finally:
            conn.close()

    return _as_data() != _as_sql()


# --------------------------------------------------------------------------
# SQL mutation operators
# --------------------------------------------------------------------------
#
# Each takes a payload and an RNG and returns a variant, or the input unchanged
# when it does not apply. All are intended to be semantics-preserving; the
# oracle above is the backstop that enforces it regardless of intent.

_WS = re.compile(r" ")
_KEYWORD = re.compile(r"\b(OR|AND|UNION|SELECT|FROM|WHERE|NULL|LIKE)\b", re.IGNORECASE)


def op_case_swap(p: str, rng: random.Random) -> str:
    """Randomise keyword case. `OR`→`oR`. Parsers are case-insensitive; many
    naive signatures are not."""
    def swap(m: re.Match[str]) -> str:
        return "".join(c.upper() if rng.random() < 0.5 else c.lower()
                       for c in m.group(0))
    return _KEYWORD.sub(swap, p)


def op_inline_comment(p: str, rng: random.Random) -> str:
    """Replace a space with an inline comment. `OR 1=1`→`OR/**/1=1`. The lexer
    treats `/**/` as whitespace; a token-boundary regex may not."""
    spaces = [m.start() for m in _WS.finditer(p)]
    if not spaces:
        return p
    i = rng.choice(spaces)
    return p[:i] + "/**/" + p[i + 1:]


def op_whitespace_alt(p: str, rng: random.Random) -> str:
    """Swap a space for another whitespace byte SQL accepts: tab, newline,
    vertical tab, form feed."""
    alt = rng.choice(["\t", "\n", "\x0b", "\x0c", "\r"])
    return _WS.sub(lambda _m: alt if rng.random() < 0.5 else " ", p)


def op_scientific_int(p: str, _rng: random.Random) -> str:
    """`1` as `1e0`. A tautology `1=1` becomes `1=1e0`, numerically equal,
    lexically different."""
    return re.sub(r"\b1\b", "1e0", p, count=1)


def op_paren_wrap(p: str, _rng: random.Random) -> str:
    """Parenthesise a tautology operand: `OR 1=1` → `OR (1)=1`."""
    return re.sub(r"\b(\d+)=", r"(\1)=", p, count=1)


def op_comment_terminator(p: str, rng: random.Random) -> str:
    """Vary the trailing comment: `-- ` ↔ `#` ↔ `-- -`. Different backends,
    different comment syntaxes, same truncation effect."""
    variants = ["-- ", "--", "#", "-- -", "/*"]
    return re.sub(r"(--\s?|#)\s*$", rng.choice(variants), p)


def op_double_encode_space(p: str, _rng: random.Random) -> str:
    """URL-encode a space. Only an evasion if something decodes it before the
    analyser — the harness sends it on the wire, so the gateway's own decode
    stage is what gets tested."""
    return p.replace(" ", "%20", 1)


SQL_OPERATORS: dict[str, Callable[[str, random.Random], str]] = {
    "case_swap": op_case_swap,
    "inline_comment": op_inline_comment,
    "whitespace_alt": op_whitespace_alt,
    "scientific_int": op_scientific_int,
    "paren_wrap": op_paren_wrap,
    "comment_terminator": op_comment_terminator,
}


class Mutator:
    """Applies random operator chains, keeping only variants that still attack.

    This is the A3 black-box model: it does not read the analyser's internals,
    it only mutates and (for SQL) checks that the mutation did not destroy the
    attack. The decision of whether a surviving mutation EVADES is made by the
    harness, which scores it against the real gateway.
    """

    def __init__(self, operators: dict[str, Callable[[str, random.Random], str]],
                 oracle: Callable[[str], bool] | None, seed: int = 0) -> None:
        self._ops = operators
        self._oracle = oracle
        self._rng = random.Random(seed)  # noqa: S311 - fuzzing RNG, not crypto

    def variants(self, payload: str, depth: int, per_depth: int) -> Iterator[Mutation]:
        """Yield semantics-preserving mutations up to `depth` composed operators.

        Breadth-first over operator chains. At each level every surviving
        variant is mutated `per_depth` more ways. Yields only variants the
        oracle accepts (when an oracle is configured); the unmutated payload is
        not yielded (it is not a mutation).
        """
        frontier = [Mutation(payload, ())]
        for _level in range(depth):
            next_frontier: list[Mutation] = []
            for base in frontier:
                for _ in range(per_depth):
                    name = self._rng.choice(list(self._ops))
                    mutated = self._ops[name](base.payload, self._rng)
                    if mutated == base.payload:
                        continue
                    cand = base.with_op(name, mutated)
                    if self._oracle is not None and not self._oracle(mutated):
                        continue
                    next_frontier.append(cand)
                    yield cand
            frontier = next_frontier or frontier
