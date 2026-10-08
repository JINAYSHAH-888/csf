"""S1: the deterministic rule stage, backed by OWASP CRS via the Coraza sidecar.

Why a sidecar rather than in-process
-------------------------------------
Coraza is the mature CRS-compatible engine and it is a Go library. The Python
binding for libmodsecurity does not build on our platform — measured, see
ADR-0007 — so in-process CRS is not available to a Python gateway. A small Go
sidecar keeps the mature engine at the cost of one IPC hop over a Unix domain
socket, which Phase 3 measured rather than assumed.

Why this stage returns a score, not a verdict
----------------------------------------------
ADR-0004. S1 is a cheap prefilter and a *graded signal*. Published figures put
CRS at roughly 70–82% detection with a 17–18% false-positive rate at paranoia
level 1, and GenSQLi found 89% of validated GPT-4o SQLi payloads bypassed
ModSecurity with current rules. Treating that as a detector would be a
mistake; treating it as a cheap triage signal is exactly right.

Two scores come back and they are different things:

``blocking_score``
    What a classic CRS deployment would have blocked on, accumulated only up
    to ``blocking_paranoia_level``.
``detection_score``
    The full signal across every evaluated paranoia level.

Measured on real payloads: a SQLi tautology scored 5 blocking / 40 detection.
We threshold on the detection score because it is the richer signal, and we
report the blocking score so a classic deployment can be compared against.

Failure policy
--------------
If the sidecar is unreachable or slow, S1 **does not fail the request**. It
returns an ``unavailable`` verdict and the cascade continues to S2/S3 with a
recorded degradation. A rules engine outage must not become an application
outage, and it must not silently become a security hole either — the
degradation is counted and alertable (threat model T5).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from csf.extraction import Result as ExtractionResult
from csf.gateway import Decision, Stage, Verdict

__all__ = ["S1Config", "S1RulesDetector", "S1Signal"]


@dataclass(frozen=True, slots=True)
class S1Config:
    """Thresholds and transport for the rules stage.

    ``tau_low`` and ``tau_high`` must come from a MEASURED detection-vs-FPR
    curve on representative traffic, never from intuition. See
    ``docs/benchmarks/`` and ``scripts/measure_s1_curve.py``. The defaults
    below are the Phase 3 measured values and are expected to be re-derived
    per deployment.
    """

    socket_path: str = "/tmp/csf-s1.sock"  # noqa: S108 - operator-configured
    base_url: str = "http://s1"
    timeout_seconds: float = 0.050
    #: Which score to threshold against: "attack" (default) uses the
    #: protocol-excluded attack score; "anomaly" uses the full CRS anomaly
    #: score. CSF's S0 owns HTTP-protocol correctness (framing.py), so CRS's
    #: PROTOCOL-ENFORCEMENT/ATTACK rules double-count a concern another stage
    #: handles AND are the dominant cross-corpus false-positive source. Scoring
    #: on attack rules only is what makes S1 transferable across applications.
    #: See ADR-0015 and docs/benchmarks/cross-corpus-attack-score.json.
    score_field: str = "attack"
    #: Below this score, forward without escalating.
    tau_low: float = 4.0
    #: At or above this score (on `score_field`), block outright.
    #:
    #: Re-derived from the cross-corpus measurement (ADR-0015), replacing the
    #: Phase 3 provisional 8 (full-anomaly). On the attack score, 11 -- roughly
    #: two independent critical attack signatures -- gives a cascade that is
    #: USABLE on an unseen application (ECML 4.71% FPR) where the old operating
    #: point was not (67% FPR), while CSIC performance is unchanged. The result
    #: is robust: 11 and 15 give the same cross-corpus FPR.
    tau_high: float = 11.0
    #: Behaviour when the sidecar is unreachable.
    #:
    #: ``True`` (default): the cascade continues to S2/S3 and the degradation
    #: is recorded. A rules-engine outage does not become an application
    #: outage. The real consequence, verified end-to-end: while the sidecar
    #: is down in enforce mode, attacks that only S1 would have caught DO
    #: reach the backend.
    #:
    #: ``False``: requests are blocked while S1 is unavailable. Appropriate
    #: for high-risk routes where serving without CRS is unacceptable, at the
    #: cost of turning a sidecar outage into an application outage.
    #:
    #: Neither is universally right, which is exactly why it is configuration
    #: and not a default buried in code (threat model T5).
    fail_open: bool = True
    max_body_bytes: int = 128 * 1024


@dataclass(slots=True)
class S1Signal:
    """The graded output of the rules stage."""

    detection_score: int = 0
    #: Anomaly score with PROTOCOL-ENFORCEMENT/ATTACK rules removed; S1's
    #: transferable application-layer attack signal (ADR-0015).
    attack_score: int = 0
    blocking_score: int = 0
    score_by_pl: dict[str, int] = field(default_factory=dict)
    matched_rule_ids: list[int] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    total_rules_fired: int = 0
    elapsed_us: int = 0
    available: bool = True
    error: str = ""


class S1RulesDetector:
    """Evaluates requests against CRS via the sidecar.

    Implements the :class:`~csf.gateway.Detector` protocol.
    """

    def __init__(self, config: S1Config, logger: Any | None = None) -> None:
        self._cfg = config
        self._log = logger
        # AsyncClient, not Client. A synchronous call here would block the
        # ASGI event loop for the full ~1.4 ms S1 round trip and serialise
        # every concurrent request behind it.
        transport = httpx.AsyncHTTPTransport(uds=config.socket_path)
        self._client = httpx.AsyncClient(
            transport=transport,
            base_url=config.base_url,
            timeout=config.timeout_seconds,
        )
        self.evaluations = 0
        self.unavailable_count = 0
        self.escalations = 0
        self.blocks = 0

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def name(self) -> Stage:
        return Stage.RULES

    async def healthcheck(self) -> bool:
        """Whether the sidecar is reachable. Called at startup so an operator
        learns about a missing sidecar then, not from a silent drop in the
        block rate."""
        try:
            response = await self._client.get("/healthz")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def evaluate(self, extracted: ExtractionResult) -> Verdict:
        signal = await self.evaluate_signal(extracted)
        self.evaluations += 1

        if not signal.available:
            self.unavailable_count += 1
            if self._cfg.fail_open:
                # Degrade, do not fail. The cascade continues to S2/S3 and
                # the degradation is recorded for alerting.
                return Verdict(
                    decision=Decision.ALLOW,
                    stage=Stage.RULES,
                    reason=f"s1_unavailable:{signal.error}",
                    score=0.0,
                )
            self.blocks += 1
            return Verdict(
                decision=Decision.BLOCK,
                stage=Stage.RULES,
                reason=f"s1_unavailable_fail_closed:{signal.error}",
                score=0.0,
            )

        score = float(signal.attack_score if self._cfg.score_field == "attack"
                      else signal.detection_score)
        rules = ",".join(str(r) for r in signal.matched_rule_ids[:8])
        categories = ",".join(signal.categories)
        # Both scores in the audit so an operator sees what protocol rules
        # contributed even though they do not drive the decision.
        scores = f"attack={signal.attack_score} anomaly={signal.detection_score}"

        if score >= self._cfg.tau_high:
            self.blocks += 1
            return Verdict(
                decision=Decision.BLOCK,
                stage=Stage.RULES,
                reason=f"crs {scores} cats={categories} rules={rules}",
                score=score,
            )
        if score > self._cfg.tau_low:
            # The ambiguity band. Allow here so the cascade continues; the
            # gateway's policy engine sees the score via the audit log and
            # S2/S3 get their turn. This is the escalation the whole design
            # exists for.
            self.escalations += 1
            return Verdict(
                decision=Decision.ALLOW,
                stage=Stage.RULES,
                reason=f"escalate crs {scores} cats={categories}",
                score=score,
            )
        return Verdict(decision=Decision.ALLOW, stage=Stage.RULES, score=score)

    async def evaluate_signal(self, extracted: ExtractionResult) -> S1Signal:
        """Call the sidecar and return the raw graded signal.

        Exposed separately from :meth:`evaluate` so the measurement harness
        can collect scores without going through threshold logic.
        """
        payload = self._build_payload(extracted)
        started = time.perf_counter()
        try:
            response = await self._client.post("/eval", json=payload)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            if self._log is not None:
                self._log.error(
                    "s1 sidecar unavailable",
                    extra={"fields": {"error": str(exc)}},
                )
            return S1Signal(
                available=False,
                error=type(exc).__name__,
                elapsed_us=int((time.perf_counter() - started) * 1e6),
            )

        return S1Signal(
            detection_score=int(data.get("anomaly_score", 0)),
            attack_score=int(data.get("attack_score", data.get("anomaly_score", 0))),
            blocking_score=int(data.get("blocking_score", 0)),
            score_by_pl=data.get("score_by_pl") or {},
            matched_rule_ids=[r["id"] for r in (data.get("matched_rules") or [])],
            categories=data.get("categories") or [],
            total_rules_fired=int(data.get("total_rules_fired", 0)),
            elapsed_us=int((time.perf_counter() - started) * 1e6),
        )

    def _build_payload(self, extracted: ExtractionResult) -> dict[str, Any]:
        """Reconstruct the request for CRS from what S0 already parsed.

        Deliberately rebuilt from extraction output rather than re-parsing raw
        HTTP in the sidecar: a second HTTP parser would be a second
        interpretation to disagree with (threat model T3).
        """
        meta = extracted.request_meta
        body = extracted.body[: self._cfg.max_body_bytes].decode(
            "utf-8", errors="replace"
        )
        return {
            "id": meta.get("request_id", ""),
            "method": meta.get("method", "GET"),
            "path": meta.get("path", "/"),
            "query": meta.get("query", ""),
            "headers": meta.get("headers", {}),
            "body": body,
        }
