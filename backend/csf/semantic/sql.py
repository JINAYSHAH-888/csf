"""Grammar-aware SQL injection analysis.

The mechanism
-------------
Not "does this value contain SQL keywords" — that is a regex and it is what
S1 already does. Instead: **inject the candidate value into a template where a
benign value produces a known parse shape, then look for structural
divergence.**

A benign value, whatever it contains, is a *leaf* in the parse tree. It cannot
add predicates, cannot open a new statement, cannot introduce a UNION. A value
that does any of those things has escaped its syntactic position, and that
escape is the attack — independent of which keywords it used to get there.

Why this transfers across applications
---------------------------------------
SQL grammar does not change when the application changes. A regex tuned on one
app's traffic does not transfer (measured: 50.8pp recall drop CSIC→ECML at
matched FPR). A parse tree that gains a second statement is an injection in
any application, in any language, under any parameter name. That is the
hypothesis this stage exists to test.

Why it resists obfuscation
---------------------------
Normalisation and lexing happen before the grammar is applied, so encoding and
comment tricks are consumed by the parser rather than evading it. Measured:
``x'/**/OR/**/1=1`` produces a parse tree *identical* to ``x' OR 1=1``.

What it cannot do
-----------------
It cannot know the real query the application will run. We probe a small set
of plausible injection contexts (string literal, numeric, identifier) rather
than one, but a value that is only dangerous inside a context we do not probe
will be missed. This is a bounded, stated limitation, not a solved problem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import sqlglot
from sqlglot import exp

__all__ = ["SqlFinding", "SqlVerdict", "analyze_sql"]

#: Dialects probed. A payload valid in any of them is a finding, because we do
#: not know the backend. sqlglot parses all of these (verified by
#: dialect_coverage(), asserted in tests).
DIALECTS = ("mysql", "postgres", "tsql")

#: A sentinel clause placed AFTER the injection point. Real queries rarely
#: end at the injected parameter — ``WHERE user='$u' AND pass='$p'`` is the
#: canonical shape — and the classic ``admin'--`` auth bypass works precisely
#: by commenting out what follows. With a single template ending at the
#: injection point, that payload produces a parse tree identical to a benign
#: value and is invisible. Measured: ``admin'--`` scored 0 before this.
SENTINEL = "ZZSENTINELZZ"

#: Injection contexts. A benign value in each is a leaf; anything that changes
#: the structure has escaped its position.
#: Each entry is (name, template, inert_placeholder).
#:
#: Several templates are needed, not one. Beyond the sentinel above, a
#: parenthesised context is required because ``') OR ('a'='a`` only balances
#: inside parentheses — it is a parse error in a bare template and was
#: therefore also scoring 0.
# ruff: noqa: S608 - building SQL by interpolation is the POINT of this
# module: we deliberately construct the injection the application would, so
# the parser can tell us whether the value escaped its position. None of
# these strings ever reach a database.
CONTEXTS: tuple[tuple[str, str, str], ...] = (
    ("string", f"SELECT a FROM t WHERE c = '{{}}' AND d = '{SENTINEL}'", "INERTVALUE"),
    ("numeric", f"SELECT a FROM t WHERE c = {{}} AND d = '{SENTINEL}'", "1"),
    ("paren", f"SELECT a FROM t WHERE (c = '{{}}') AND d = '{SENTINEL}'", "INERTVALUE"),
    ("like", f"SELECT a FROM t WHERE c LIKE '%{{}}%' AND d = '{SENTINEL}'", "INERTVALUE"),
    # No trailing clause. In the sentinel-bearing numeric template,
    # `1; DROP TABLE t AND d = 'ZZ'` is invalid SQL, the parse fails
    # entirely, and the stacked statement is never seen. Comment truncation
    # is not detectable here, but it is scoped to quoted contexts anyway.
    ("numeric_bare", "SELECT a FROM t WHERE c = {}", "1"),
)

#: A value is only plausibly injected into a NUMERIC position if it could
#: have been a number to begin with. Probing the numeric context
#: unconditionally was a measured false-positive source: the HTTP header
#: ``Accept-Language: *;q=0.3`` becomes ``WHERE c = *;q=0.3`` where the
#: semicolon reads as a stacked statement, and that single pattern accounted
#: for 48 of ~70 S2 false positives on ECML benign traffic.
#:
#: Real numeric injections start numerically (``1 OR 1=1``, ``-1 UNION``).
#: Anything else belongs in the string or paren context, which are still
#: probed.
_NUMERIC_START = re.compile(r"^\s*[-+]?\d")

#: Syntax that suggests an injection attempt worth checking in every dialect,
#: even when the primary dialect's parser rejected it outright.
_DIALECT_HINT = re.compile(r"""['";]|--|/\*|\bunion\b|\bexec\b""", re.IGNORECASE)

#: Contexts where the value sits inside quotes. Comment truncation is only
#: meaningful here, and the distinction is not cosmetic.
#:
#: In a QUOTED context, reaching comment syntax requires first closing the
#: quote — that escape IS the injection. In an unquoted numeric context no
#: escape is needed, so any value containing ``--`` trivially produces a
#: comment. Measured: without this distinction, the legitimate part number
#: ``part--123`` and the free-text ``comment -- here`` both scored 5.0 as
#: comment truncation. Scoping the marker to quoted contexts removes both
#: false positives while keeping every real auth-bypass payload.
QUOTED_CONTEXTS = frozenset({"string", "paren", "like"})

#: Functions whose presence in user input is a strong signal regardless of
#: surrounding structure: timing oracles, file access, and shell escapes.
DANGEROUS_FUNCTIONS = frozenset({
    "SLEEP", "BENCHMARK", "PG_SLEEP", "WAITFOR", "DBMS_PIPE",
    "LOAD_FILE", "LOAD DATA", "OUTFILE", "DUMPFILE", "INTO OUTFILE",
    "XP_CMDSHELL", "SP_EXECUTESQL", "EXEC", "EXECUTE",
    "UTL_HTTP", "UTL_FILE", "EXTRACTVALUE", "UPDATEXML",
})

#: Comparison predicates. A predicate whose operands are ALL literals is
#: constant: it evaluates the same for every row, so it cannot be part of the
#: query the application meant to run.
#:
#: The original check looked only for ``exp.EQ`` with two equal literals, which
#: is ``' OR '1'='1`` and nothing else. Measured on an unseen application, 76
#: missed SQLi requests were the same escape expressed through a different
#: operator -- ``' OR 'ns' BETWEEN 'R' AND 'T``, ``' OR 'He' > 'S``,
#: ``' OR '99he' < 'X`` -- which reached only the 3.0 injected_or marker and
#: stayed under tau_block. The operator is incidental; a column-free predicate
#: is the invariant.
COMPARISON_PREDICATES = (exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE,
                         exp.Like, exp.ILike, exp.NullSafeEQ, exp.NullSafeNEQ,
                         exp.Between)

#: Statement types that should never appear from user input in a read path.
WRITE_STATEMENTS = (exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create,
                    exp.Alter, exp.TruncateTable)


@dataclass(slots=True)
class SqlFinding:
    """One structural observation. Carries its own weight and explanation."""

    marker: str
    weight: float
    detail: str
    context: str = ""
    dialect: str = ""

    def __str__(self) -> str:
        where = f" [{self.dialect}/{self.context}]" if self.dialect else ""
        return f"{self.marker}(+{self.weight:g}){where}: {self.detail}"


@dataclass(slots=True)
class SqlVerdict:
    """The analyser's output. Explainable by construction: every point of
    score traces to a named structural finding."""

    score: float = 0.0
    findings: list[SqlFinding] = field(default_factory=list)
    #: True when the value parsed as a leaf in every probed context, i.e. it
    #: behaves like data rather than syntax.
    inert: bool = True

    def add(self, finding: SqlFinding) -> None:
        self.findings.append(finding)
        self.score += finding.weight
        self.inert = False

    def explain(self) -> str:
        if not self.findings:
            return "no structural divergence"
        return "; ".join(str(f) for f in self.findings)


#: Values shorter than this cannot carry meaningful SQL structure and are
#: skipped. Keeps the common case (short IDs, flags, page numbers) cheap.
_MIN_LENGTH = 4

#: Cheap pre-filter, part one: punctuation that can escape a leaf position.
#: This is NOT the detection — it only avoids parsing values that provably
#: cannot be injections, which is the overwhelming majority of real traffic.
_STRUCTURAL_CHARS = re.compile(r"""['"`;()\-=<>|&*/\\]""")

#: Cheap pre-filter, part two: keywords that open a new query or clause.
#:
#: Punctuation alone was an incomplete filter and it silently disabled the
#: whole analyser for an important shape. ``1 UNION SELECT password FROM
#: users`` — the textbook exfiltration payload — contains no quote, operator or
#: separator, so it failed the punctuation test and was never parsed at all,
#: scoring 0. A numeric parameter needs no quote to escape: the keyword IS the
#: escape.
#:
#: The set-operation names are read off sqlglot's expression hierarchy rather
#: than written out, so they track the parser rather than drifting from it.
#: The clause keywords after them are grammar, not tuning: each one can begin
#: a clause that a leaf value must not be able to introduce.
_SET_OPERATIONS = tuple(sorted(
    cls.__name__.upper() for cls in exp.SetOperation.__subclasses__()
))
#: Spelled as sqlglot spells them. ``ORDER`` and ``GROUP`` are deliberately
#: the two-word forms: sqlglot's keyword is ``ORDER BY``, and admitting the
#: bare first word would send every value containing "order" or "group" to the
#: parser -- "order confirmation", "group tour" -- for no possible finding.
#: test_semantic.py asserts each of these is still a keyword sqlglot knows, so
#: a rename upstream surfaces as a test failure instead of a silent dead entry.
_CLAUSE_KEYWORDS = (
    "SELECT", "FROM", "WHERE", "HAVING", "JOIN", "INTO", "EXECUTE",
    "ORDER BY", "GROUP BY", "LIMIT", "OFFSET", "PROCEDURE", "DECLARE",
)

#: Grammar that sqlglot's tokeniser does not name but the backends accept.
#: ``EXEC`` is the T-SQL short form of ``EXECUTE`` and the carrier for
#: ``EXEC xp_cmdshell``; it is listed separately precisely because the
#: assertion above would otherwise fail on it, which is the point of splitting
#: the two lists rather than quietly loosening the check.
_UNPARSED_KEYWORDS = ("EXEC",)

#: Keywords may be multi-word, and an attacker controls the whitespace between
#: them, so the gap is matched as "one or more spaces" rather than literally.
_STRUCTURAL_KEYWORDS = re.compile(
    r"\b(?:"
    + "|".join(kw.replace(" ", r"\s+")
               for kw in _SET_OPERATIONS + _CLAUSE_KEYWORDS + _UNPARSED_KEYWORDS)
    + r")\b",
    re.IGNORECASE)


def _function_name(node: exp.Func | exp.Expression) -> str:
    """Best-effort function name. sqlglot reports unknown functions as
    ``Anonymous`` with the name held in ``this``."""
    if isinstance(node, exp.Anonymous):
        return str(node.this).upper()
    name = getattr(node, "sql_name", None)
    if callable(name):
        try:
            return str(name()).upper()
        except Exception:  # noqa: BLE001, S110 - node APIs vary; fall through
            # Falling back to the node's class name is correct here; there is
            # nothing to log and nothing has failed from the caller's view.
            pass
    return type(node).__name__.upper()


def _predicate_operands(node: exp.Expression) -> list[exp.Literal] | None:
    """Return the operands of a comparison iff every one is a literal.

    A predicate comparing a column to a literal is the normal shape and is not
    reported -- that is what ``WHERE c = 'x'`` is. Only a predicate with no
    column reference at all is constant, and user input cannot legitimately
    introduce one.
    """
    parts: list[Any]
    if isinstance(node, exp.Binary):
        parts = [node.left, node.right]
    else:
        # exp.Between and anything else three-part: operands live in args.
        parts = [node.this, node.args.get("low"), node.args.get("high")]
    if any(p is None or not isinstance(p, exp.Literal) for p in parts):
        return None
    return [p for p in parts if isinstance(p, exp.Literal)]


def _baseline_shape(template: str, inert: str, dialect: str) -> tuple[int, int] | None:
    """Node count and statement count for a benign value in this context."""
    try:
        statements = [s for s in sqlglot.parse(template.format(inert), dialect=dialect)
                      if s is not None]
    except Exception:  # noqa: BLE001, S110 - a failure here means "unknown"
        # Baseline computation failing for one (context, dialect) pair just
        # removes that pair from the probe set; dialect_coverage() reports it.
        return None
    if not statements:
        return None
    nodes = sum(len(list(s.walk())) for s in statements)
    return nodes, len(statements)


# Baselines are fixed per (context, dialect) and cheap to precompute once.
_BASELINES: dict[tuple[str, str], tuple[int, int]] = {}
for _name, _tmpl, _inert in CONTEXTS:
    for _dialect in DIALECTS:
        _shape = _baseline_shape(_tmpl, _inert, _dialect)
        if _shape is not None:
            _BASELINES[(_name, _dialect)] = _shape


def _analyze_one(value: str, context: str, template: str, dialect: str,
                 verdict: SqlVerdict) -> None:
    """Probe one (context, dialect) pair and record findings."""
    baseline = _BASELINES.get((context, dialect))
    if baseline is None:
        return
    base_nodes, base_statements = baseline

    try:
        statements = [s for s in sqlglot.parse(template.format(value), dialect=dialect)
                      if s is not None]
    except Exception:  # noqa: BLE001
        # A parse failure is NOT evidence of an attack. Benign values break
        # SQL syntax constantly (an unbalanced quote in free text). Treating
        # failures as attacks would be a large false-positive source.
        return
    if not statements:
        return

    # --- stacked statements -------------------------------------------
    if len(statements) > base_statements:
        kinds = ", ".join(type(s).__name__ for s in statements[base_statements:])
        verdict.add(SqlFinding(
            "stacked_statement", 5.0,
            f"value opened {len(statements) - base_statements} additional "
            f"statement(s): {kinds}",
            context, dialect))

    # ---------------------------------------------------------------
    # ONE walk of the tree, not ten.
    #
    # Profiling showed AST traversal costing more than parsing itself:
    # 874k walk() calls, 2.1s of a 3.9s run, because each marker below used
    # its own find_all() and every find_all is a full breadth-first walk.
    # Collecting every node class in a single pass is the single largest
    # latency win available in this module.
    # ---------------------------------------------------------------
    unions: list[exp.Expression] = []
    writes: list[exp.Expression] = []
    predicates: list[exp.Expression] = []
    ors: list[exp.Expression] = []
    funcs: list[exp.Func] = []
    subqueries: list[exp.Expression] = []
    literals: list[exp.Expression] = []
    where_nodes: list[exp.Expression] = []
    node_count = 0

    for statement in statements:
        for node in statement.walk():
            node_count += 1
            if isinstance(node, exp.Union):
                unions.append(node)
            elif isinstance(node, WRITE_STATEMENTS):
                writes.append(node)
            elif isinstance(node, COMPARISON_PREDICATES):
                predicates.append(node)
            elif isinstance(node, exp.Or):
                ors.append(node)
            elif isinstance(node, exp.Subquery):
                subqueries.append(node)
            elif isinstance(node, exp.Where):
                where_nodes.append(node)
            elif isinstance(node, exp.Literal):
                literals.append(node)
            if isinstance(node, exp.Func):
                funcs.append(node)

    if unions:
        verdict.add(SqlFinding(
            "union", 5.0,
            "value introduced a UNION, merging an attacker-chosen result set",
            context, dialect))

    if writes:
        verdict.add(SqlFinding(
            "write_statement", 5.0,
            f"value introduced a {type(writes[0]).__name__.upper()} statement",
            context, dialect))

    for predicate in predicates:
        operands = _predicate_operands(predicate)
        if operands is None:
            continue
        rendered = " ".join(str(o.this) for o in operands)
        verdict.add(SqlFinding(
            "constant_predicate", 4.0,
            f"{type(predicate).__name__.upper()} between constants only "
            f"({rendered}), so it evaluates the same for every row and "
            f"cannot belong to the query the application meant to run",
            context, dialect))
        break

    # An OR only matters inside a WHERE clause: a benign leaf cannot add a
    # boolean operator to the query's filter.
    if ors and where_nodes:
        in_where = [o for o in ors
                    if any(o is w or o in set(w.find_all(exp.Or))
                           for w in where_nodes)]
        if in_where:
            verdict.add(SqlFinding(
                "injected_or", 3.0,
                f"value added {len(in_where)} OR term(s) to the WHERE clause, "
                "widening what the query matches",
                context, dialect))

    for func in funcs:
        name = _function_name(func)
        if name in DANGEROUS_FUNCTIONS:
            verdict.add(SqlFinding(
                "dangerous_function", 5.0,
                f"value called {name}, which reads files, executes "
                "commands, or acts as a timing oracle",
                context, dialect))
            break

    if subqueries:
        verdict.add(SqlFinding(
            "injected_subquery", 4.0,
            f"value introduced {len(subqueries)} subquery/subqueries",
            context, dialect))

    # --- comment truncation ------------------------------------------
    # The sentinel clause follows the injection point in every template. If
    # it is gone from the parsed output, the value terminated the rest of the
    # query. In a real query that discarded remainder is the password check,
    # the tenant filter, or the LIMIT.
    # Checked STRUCTURALLY, not textually. sqlglot preserves commented-out
    # text when it renders SQL back, so `WHERE c = 'admin' /* ... SENTINEL */`
    # still *contains* the sentinel string while the clause is dead. We
    # therefore look for a live Literal node, which is what the database
    # would actually evaluate.
    sentinel_alive = any(str(lit.this) == SENTINEL for lit in literals)
    if not sentinel_alive and context in QUOTED_CONTEXTS:
        verdict.add(SqlFinding(
            "comment_truncation", 5.0,
            "value terminated the query early, discarding everything after "
            "the injection point (the classic admin'-- auth bypass)",
            context, dialect))

    # --- gross structural growth ------------------------------------------
    # Caught last and weighted low: it is the catch-all for shapes the named
    # markers missed, and on its own it is weak evidence.
    if node_count > base_nodes * 2 and not verdict.findings:
        verdict.add(SqlFinding(
            "structural_growth", 2.0,
            f"parse tree grew from {base_nodes} to {node_count} nodes without "
            "a named marker",
            context, dialect))


def _backend_tolerant_views(value: str) -> list[str]:
    """The distinct strings a lenient backend might parse, most-faithful first.

    A measured parser differential (Phase 8): an attacker ends a payload with
    an UNTERMINATED ``/*``. sqlglot — hence S2 — fails to parse the dangling
    comment and sees nothing, scoring 0. A tolerant backend (sqlite, and MySQL
    for ``/*`` that reaches end of input) treats ``/*`` as a comment running to
    the end, so the attack before it executes. ``x' UNION SELECT NULL,NULL/*``
    evaded S2 this way while sqlite still ran the UNION.

    The fix mirrors the traversal analyser: do not pick one reading, analyse
    each one an attacker could be relying on. The extra view is only produced
    when a dangling ``/*`` is actually present, so the common path is unchanged.
    """
    views = [value]
    idx = value.find("/*")
    while idx != -1:
        if "*/" not in value[idx + 2:]:
            # A tolerant backend comments from the dangling /* to end of input,
            # swallowing not just the rest of the value but the rest of the
            # query the application appends after it. A line comment reproduces
            # exactly that effect, so substituting one turns the evasion back
            # into the shape S2 already detects -- the sentinel after the
            # injection point is discarded and comment_truncation/UNION fire.
            # Truncating instead would leave the application's closing quote
            # unbalanced and the parse would fail, which is the bug this fixes.
            rewritten = value[:idx] + "-- "
            if rewritten != value:
                views.append(rewritten)
            break
        idx = value.find("/*", idx + 2)
    return views


def _analyze_views(value: str, verdict: SqlVerdict) -> None:
    """Run the two-pass dialect probe over `value` and merge into `verdict`."""
    numeric_plausible = bool(_NUMERIC_START.match(value))
    contexts = [c for c in CONTEXTS
                if not c[0].startswith("numeric") or numeric_plausible]

    primary = DIALECTS[0]
    for context, template, _inert in contexts:
        _analyze_one(value, context, template, primary, verdict)

    # Widen to the other dialects when the first pass found something, OR
    # when the value carries injection syntax that the primary dialect may
    # simply not accept. Without the second condition the optimisation was a
    # REGRESSION: `1'; EXEC xp_cmdshell('dir')-- ` parses only under T-SQL,
    # found nothing in MySQL, and so was never escalated.
    if verdict.findings or _DIALECT_HINT.search(value):
        for context, template, _inert in contexts:
            for dialect in DIALECTS[1:]:
                _analyze_one(value, context, template, dialect, verdict)


def analyze_sql(value: str) -> SqlVerdict:
    """Analyse a candidate value for SQL injection structure.

    Returns a verdict whose score is the sum of named structural findings.
    A score of zero means the value parsed as a leaf in every probed context —
    it behaves like data, not syntax.
    """
    verdict = SqlVerdict()
    if len(value) < _MIN_LENGTH:
        return verdict
    if not (_STRUCTURAL_CHARS.search(value) or _STRUCTURAL_KEYWORDS.search(value)):
        return verdict

    # The value is inserted into a template, so an unescaped closing quote is
    # how most injections work. We do not escape it — that is the point.
    #
    # Each backend-tolerant reading of the value is probed. Normally that is
    # just the value itself; a dangling /* comment adds one more (see
    # _backend_tolerant_views). Two-pass dialect probing inside keeps cost
    # bounded — the second and third dialects run only on escalation.
    for view in _backend_tolerant_views(value):
        _analyze_views(view, verdict)

    # The same payload firing in several dialects, contexts, or views should
    # not be counted repeatedly. Collapse to the strongest finding per marker.
    if verdict.findings:
        best: dict[str, SqlFinding] = {}
        for finding in verdict.findings:
            current = best.get(finding.marker)
            if current is None or finding.weight > current.weight:
                best[finding.marker] = finding
        verdict.findings = sorted(best.values(), key=lambda f: -f.weight)
        verdict.score = sum(f.weight for f in verdict.findings)

    return verdict


def dialect_coverage() -> dict[str, Any]:
    """Report which (context, dialect) baselines resolved.

    ADR-0003 flagged dialect coverage gaps as a risk to measure rather than
    assume. This makes the actual coverage inspectable at runtime.
    """
    return {
        "dialects": list(DIALECTS),
        "contexts": [c[0] for c in CONTEXTS],
        "baselines_resolved": len(_BASELINES),
        "baselines_expected": len(CONTEXTS) * len(DIALECTS),
        "missing": [f"{c}/{d}" for c, _, _ in CONTEXTS for d in DIALECTS
                    if (c, d) not in _BASELINES],
    }
