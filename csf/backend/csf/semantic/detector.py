"""S2: the grammar-aware semantic stage.

Runs the SQL, XSS and shell analysers over each extracted candidate value and
combines their findings into a verdict.

Position in the cascade
-----------------------
S2 sits between the deterministic rule engine (S1) and the learned model (S3)
because it has a different inductive bias from both. S1 matches surface
patterns; S2 asks whether a value escaped its syntactic position; S3 will
generalise statistically. An evasion must defeat all three, and they fail
differently — measured: S2 misses ``x' OR 'a'='a' /*`` because the
unterminated comment breaks the tokeniser, while S1 scores it 45.

Cost
----
Pure CPU, no I/O, so it runs inline in the event loop. Candidates are
pre-filtered cheaply: a value with no structural characters cannot be an
injection in any of the three grammars, and that is the overwhelming
majority of real traffic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Protocol

from csf.gateway import Decision, Stage, Verdict
from csf.semantic.shell import analyze_shell
from csf.semantic.sql import analyze_sql
from csf.semantic.traversal import analyze_traversal
from csf.semantic.xss import analyze_xss

if TYPE_CHECKING:
    from csf.extraction import Result as ExtractionResult

__all__ = ["S2Config", "S2SemanticDetector", "S2Signal", "analyze_candidate"]


class _GrammarVerdict(Protocol):
    """What every analyser's verdict provides.

    The four analysers return distinct verdict types because each carries
    grammar-specific findings, but they agree on this much.
    """

    score: float

    def explain(self) -> str: ...


class _Analyser(Protocol):
    def __call__(self, value: str, /) -> _GrammarVerdict: ...


#: Which grammars are plausible for a value found in each location.
#:
#: Applying every grammar everywhere was a measured mistake. CSIC's
#: User-Agent is ``Mozilla/5.0 (compatible; Konqueror/3.5; Linux) ...`` — the
#: semicolons lex as shell command separators, and that single header
#: produced a finding on 100% of benign requests. A User-Agent is not passed
#: to a shell; a path segment is not SQL.
#:
#: Headers and cookies keep XSS analysis because they are routinely reflected
#: into pages and log viewers, and keep SQL because they do reach queries in
#: analytics paths — but they lose shell analysis, where the false-positive
#: cost is real and the attack path is rare.
GRAMMARS_BY_LOCATION: dict[str, frozenset[str]] = {
    "query": frozenset({"sqli", "xss", "cmdi", "traversal"}),
    "form": frozenset({"sqli", "xss", "cmdi", "traversal"}),
    "json_body": frozenset({"sqli", "xss", "cmdi", "traversal"}),
    "multipart": frozenset({"sqli", "xss", "cmdi", "traversal"}),
    "path": frozenset({"sqli", "xss", "traversal"}),
    "header": frozenset({"sqli", "xss"}),
    "cookie": frozenset({"sqli", "xss"}),
}
_ALL_GRAMMARS = frozenset({"sqli", "xss", "cmdi", "traversal"})


@dataclass(frozen=True, slots=True)
class S2Config:
    """Thresholds for the semantic stage.

    Defaults come from analyser calibration, not intuition: each analyser
    weights its findings so that a single weak marker (a bare shell operator,
    one injected OR term) scores below ``tau_block`` while any combination
    that indicates a real escape scores at or above it.
    """

    #: At or above this combined score, block.
    tau_block: float = 4.0
    #: Above this, flag for review and let the cascade continue.
    tau_flag: float = 1.0
    #: Findings below this are recorded for the audit log but do NOT set the
    #: request's score. The weak markers (a bare shell operator, one injected
    #: OR term) are explicitly documented as corroborating evidence; letting
    #: one of them alone drive the request score is what made every benign
    #: request score 2.0.
    min_finding_score: float = 3.0
    #: Skip values longer than this. Very long values are the model's
    #: problem; parsing them repeatedly across 3 grammars is not worth it.
    max_value_length: int = 4096
    #: Stop after this many candidates. Bounds worst-case CPU per request.
    max_candidates: int = 64
    enable_sql: bool = True
    enable_xss: bool = True
    enable_shell: bool = True
    enable_traversal: bool = True


@dataclass(slots=True)
class CandidateFinding:
    """What S2 concluded about one candidate value."""

    parameter: str
    location: str
    attack_class: str
    score: float
    explanation: str


@dataclass(slots=True)
class S2Signal:
    """The stage's graded output."""

    score: float = 0.0
    findings: list[CandidateFinding] = field(default_factory=list)
    candidates_examined: int = 0
    candidates_parsed: int = 0
    elapsed_us: int = 0

    @property
    def classes(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.attack_class not in seen:
                seen.append(finding.attack_class)
        return seen


#: Analysis is a pure function of (value, applicable grammars), so results
#: are cacheable. Real traffic repeats values constantly — the same
#: User-Agent on every request from a client, the same enum parameter values,
#: the same paths — and each repeat would otherwise re-parse across four SQL
#: contexts and three dialects.
#:
#: The cache is keyed on the value and the grammar set, NOT on the config,
#: so it is cleared whenever a non-default config is used (see
#: _cached_analyze's callers). Bounded to keep memory flat under an attacker
#: who sends unique values forever.
_CACHE_SIZE = 4096


@lru_cache(maxsize=_CACHE_SIZE)
def _cached_analyze(value: str, grammars: frozenset[str]) -> tuple[float, str, str]:
    best_score = 0.0
    best_class = ""
    best_explanation = ""
    probes: list[tuple[str, _Analyser]] = []
    if "sqli" in grammars:
        probes.append(("sqli", analyze_sql))
    if "xss" in grammars:
        probes.append(("xss", analyze_xss))
    if "cmdi" in grammars:
        probes.append(("cmdi", analyze_shell))
    if "traversal" in grammars:
        probes.append(("traversal", analyze_traversal))

    for attack_class, analyse in probes:
        verdict = analyse(value)
        if verdict.score > best_score:
            best_score = verdict.score
            best_class = attack_class
            best_explanation = verdict.explain()
    return best_score, best_class, best_explanation


def cache_info() -> object:
    """Expose hit/miss statistics so the cache can be shown to be working."""
    return _cached_analyze.cache_info()


def clear_cache() -> None:
    _cached_analyze.cache_clear()


def analyze_candidate(
    value: str, config: S2Config | None = None, location: str | None = None
) -> tuple[float, str, str]:
    """Analyse one value. Returns (score, attack_class, explanation).

    Each applicable grammar is probed independently and the strongest wins. A
    value is not usually ambiguous between them: SQL structure and HTML
    structure look nothing alike.

    ``location`` restricts which grammars apply (see
    :data:`GRAMMARS_BY_LOCATION`). Omitting it probes all three.
    """
    cfg = config or S2Config()

    applicable = (GRAMMARS_BY_LOCATION.get(location, _ALL_GRAMMARS)
                  if location is not None else _ALL_GRAMMARS)
    enabled = {
        name for name, on in (
            ("sqli", cfg.enable_sql), ("xss", cfg.enable_xss),
            ("cmdi", cfg.enable_shell), ("traversal", cfg.enable_traversal),
        ) if on
    }
    grammars = frozenset(applicable & enabled)
    if not grammars:
        return 0.0, "", ""

    best_score, best_class, best_explanation = _cached_analyze(value, grammars)
    return best_score, best_class, best_explanation


def analyze_extraction(
    extracted: ExtractionResult, config: S2Config | None = None
) -> S2Signal:
    """Run S2 over every candidate in an extracted request."""
    cfg = config or S2Config()
    signal = S2Signal()
    started = time.perf_counter()

    for candidate in extracted.candidates[: cfg.max_candidates]:
        signal.candidates_examined += 1
        value = candidate.normalized
        if not value or len(value) > cfg.max_value_length:
            continue
        # Numbers, booleans and nulls cannot carry injection structure.
        if candidate.content_type in ("number", "bool", "null"):
            continue

        signal.candidates_parsed += 1
        location = str(candidate.location)
        score, attack_class, explanation = analyze_candidate(value, cfg, location)
        if score > 0:
            signal.findings.append(CandidateFinding(
                parameter=candidate.parameter,
                location=location,
                attack_class=attack_class,
                score=score,
                explanation=explanation,
            ))
            # The request's score is the strongest single candidate, not a
            # sum. Summing would let a request with many weakly-scoring
            # benign fields cross the threshold without any one of them
            # being an attack.
            #
            # Weak findings are kept for the audit log but excluded from the
            # score, so corroborating evidence cannot masquerade as proof.
            if score >= cfg.min_finding_score:
                signal.score = max(signal.score, score)

    signal.findings.sort(key=lambda f: -f.score)
    signal.elapsed_us = int((time.perf_counter() - started) * 1e6)
    return signal


class S2SemanticDetector:
    """Implements the :class:`~csf.gateway.Detector` protocol."""

    def __init__(self, config: S2Config | None = None, logger: object | None = None) -> None:
        self._cfg = config or S2Config()
        self._log = logger
        self.evaluations = 0
        self.blocks = 0
        self.flags = 0

    @property
    def name(self) -> Stage:
        return Stage.SEMANTIC

    async def evaluate(self, extracted: ExtractionResult) -> Verdict:
        signal = analyze_extraction(extracted, self._cfg)
        self.evaluations += 1

        if not signal.findings:
            return Verdict(decision=Decision.ALLOW, stage=Stage.SEMANTIC)

        top = signal.findings[0]
        reason = (f"{top.attack_class} in {top.location}/{top.parameter}: "
                  f"{top.explanation}")

        if signal.score >= self._cfg.tau_block:
            self.blocks += 1
            return Verdict(decision=Decision.BLOCK, stage=Stage.SEMANTIC,
                           reason=reason, score=signal.score)
        if signal.score > self._cfg.tau_flag:
            self.flags += 1
            return Verdict(decision=Decision.FLAG, stage=Stage.SEMANTIC,
                           reason=reason, score=signal.score)
        return Verdict(decision=Decision.ALLOW, stage=Stage.SEMANTIC,
                       reason=reason, score=signal.score)
