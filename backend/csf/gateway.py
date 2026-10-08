"""The CSF inline gateway: an ASGI application implementing S0 and the
detection cascade.

Stage order is cost-ordered (see ``docs/architecture/system-overview.md``):

    S0a framing -> S0b auth -> S0c extraction -> S1 -> S2 -> S3 -> policy

Detectors are reached only when the preceding stage could not resolve the
request. The escalation policy, not the classifier's benchmark accuracy, is
the engineering substance of this design.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from csf import framing
from csf.decision import DecisionConfig, DecisionEngine, StageEvidence
from csf.extraction import ExtractionLimits, extract
from csf.extraction import Result as ExtractionResult
from csf.framing import FramingLimits
from csf.jwtverify import VerificationError, Verifier
from csf.resilience import CircuitBreaker, CircuitBreakerConfig, RateLimitConfig, RateLimiter
from csf.telemetry import Mode
from csf.verdict import Decision, Stage, Verdict

__all__ = ["Decision", "Detector", "Gateway", "GatewayOptions", "Stage", "Verdict"]


class Detector(Protocol):
    """Interface every detection stage implements.

    Keeping stages behind this protocol is what makes ADR-0006's reversal
    strategy real: porting the data plane to another runtime means writing a
    new transport, not rewriting detection.

    ``evaluate`` is **async**. S1 talks to the Coraza sidecar over a socket
    (~1.4 ms measured) and S3 will do inference; doing either synchronously
    inside this ASGI app would block the event loop for the whole duration
    and serialise every concurrent request behind it. A purely CPU-bound
    stage such as S2 may still be written as an ``async def`` that does its
    work inline, provided it stays short.
    """

    @property
    def name(self) -> Stage: ...

    async def evaluate(self, extracted: ExtractionResult) -> Verdict:
        """Return a verdict. A detector that cannot decide returns
        ``Verdict()`` (allow / Stage.NONE) so the cascade continues."""
        ...


@dataclass(slots=True)
class Stats:
    """Process-lifetime counters. Prometheus metrics arrive in Phase 9; these
    exist so /statusz and tests have something to assert on."""

    total: int = 0
    allowed: int = 0
    blocked: int = 0
    flagged: int = 0
    framing_rejected: int = 0
    auth_rejected: int = 0
    shadow_would_block: int = 0
    rate_limited: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "total": self.total,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "flagged": self.flagged,
            "framing_rejected": self.framing_rejected,
            "auth_rejected": self.auth_rejected,
            "shadow_would_block": self.shadow_would_block,
            "rate_limited": self.rate_limited,
        }


@dataclass(slots=True)
class GatewayOptions:
    upstream: str
    mode: Mode = Mode.SHADOW
    framing_limits: FramingLimits = field(default_factory=FramingLimits)
    extraction_limits: ExtractionLimits = field(default_factory=ExtractionLimits)
    verifier: Verifier | None = None
    auth_enabled: bool = False
    protected_prefixes: tuple[str, ...] = ()
    auth_fail_closed: bool = True
    upstream_timeout: float = 30.0
    detectors: tuple[Detector, ...] = ()
    version: str = "dev"
    #: JWKS resolvers by issuer, for readiness reporting and rotation-driven
    #: refresh. Empty for static-key deployments.
    key_resolvers: dict[str, Any] = field(default_factory=dict)
    #: How stage verdicts become one action (ADR-0011). Defaults are applied
    #: by the Gateway so existing callers keep working.
    decision: DecisionConfig | None = None
    #: S0 admission control and resilience (ADR-0013). Defaults keep rate
    #: limiting off and the breaker on, matching the config defaults.
    rate_limit: RateLimitConfig | None = None
    circuit_breaker: CircuitBreakerConfig | None = None
    #: When extraction hits a resource cap, the score attributed to that
    #: signal. Below tau to FLAG by default; an operator who wants cap-hits to
    #: block raises it. T4: cap-exceeded is a signal, not silently dropped.
    cap_signal_score: float = 2.0


#: Headers that must never be forwarded upstream or echoed downstream.
_HOP_BY_HOP = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade",
    }
)

#: Identity headers the gateway asserts. Any client-supplied copy is stripped
#: before ours is added, so a client cannot forge the identity we assert.
_IDENTITY_HEADERS = frozenset({"x-csf-subject", "x-csf-token-hash"})

#: A cap-exceeded signal scored at or above this blocks; below it flags. 4.0
#: matches S2's tau_block so the two scales read the same to an operator.
_CAP_BLOCK_AT = 4.0


class Gateway:
    """ASGI application."""

    def __init__(self, options: GatewayOptions, logger: Any) -> None:
        self._opts = options
        self._log = logger
        self.stats = Stats()
        self.decision_engine = DecisionEngine(options.decision)
        self._decision = self.decision_engine
        self.rate_limiter = RateLimiter(options.rate_limit or RateLimitConfig())
        self.circuit_breaker = CircuitBreaker(
            options.circuit_breaker or CircuitBreakerConfig())
        self._refresh_tasks: set[asyncio.Task[Any]] = set()
        self._client = httpx.AsyncClient(
            base_url=options.upstream,
            timeout=options.upstream_timeout,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
        for detector in self._opts.detectors:
            closer = getattr(detector, "aclose", None)
            if closer is not None:
                await closer()

    # -- helpers ---------------------------------------------------------

    def _readiness_problems(self) -> list[str]:
        problems: list[str] = []
        if self._opts.auth_enabled:
            if self._opts.verifier is None:
                problems.append("auth enabled but no verifier configured")
            for name, resolver in self._opts.key_resolvers.items():
                if not resolver.healthy:
                    problems.append(f"no verification keys available for issuer {name}")
        # A configuration whose observed block rate is far above the budget is
        # not ready to enforce: the thresholds do not fit this application's
        # traffic. Reported, never self-applied -- see
        # DecisionEngine.enforcement_blockers for why automatic de-escalation
        # would be an attacker-triggerable off switch.
        problems.extend(self._decision.enforcement_blockers())
        if self.circuit_breaker.tripped():
            snap = self.circuit_breaker.snapshot()
            problems.append(
                f"circuit breaker tripped: detector unavailable on "
                f"{snap['unavailable_rate_pct']}% of recent requests; running "
                f"degraded (learned stage skipped)")
        return problems

    def _is_protected(self, path: str) -> bool:
        return any(path.startswith(p) for p in self._opts.protected_prefixes)

    def _enforcing(self) -> bool:
        """Whether a block decision actually blocks in this mode.

        In shadow and monitor mode the gateway evaluates fully and logs what
        it WOULD have done, then forwards. This is the deployment discipline
        the research mandates: never go to blocking mode on day one, because
        the false-positive distribution of real traffic is never what the
        benchmark predicted.
        """
        return self._opts.mode in (Mode.ENFORCE, Mode.EMERGENCY)

    def _audit(
        self,
        request_id: str,
        method: str,
        path: str,
        decision: Decision,
        stage: Stage,
        reason: str,
        score: float,
        started: float,
        enforced: bool,
    ) -> None:
        self._log.info(
            "decision",
            extra={
                "fields": {
                    "request_id": request_id,
                    "mode": str(self._opts.mode),
                    "method": method,
                    "path": path,
                    "decision": str(decision),
                    "enforced": enforced,
                    "stage": str(stage),
                    "reason": reason,
                    "score": score,
                    "latency_us": int((time.perf_counter() - started) * 1e6),
                }
            },
        )

    # -- ASGI ------------------------------------------------------------

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            raise RuntimeError("csf gateway handles http scopes only")

        started = time.perf_counter()
        request_id = secrets.token_hex(8)
        method: str = scope["method"]
        path: str = scope["path"]
        raw_headers: list[tuple[bytes, bytes]] = list(scope["headers"])
        self.stats.total += 1

        if path == "/healthz":
            # Liveness: the process is running. Deliberately does NOT depend
            # on JWKS, or a JWKS outage would trigger pod restarts that cannot
            # possibly help.
            await _respond(send, 200, b"ok", request_id)
            return
        if path == "/readyz":
            # Readiness: can this instance actually serve? If auth is enabled
            # and no verification key is available, every protected request
            # would fail closed, so we must not be in the load-balancer pool.
            problems = self._readiness_problems()
            if problems:
                await _respond(send, 503,
                               json.dumps({"ready": False, "problems": problems}).encode(),
                               request_id, "application/json")
                return
            await _respond(send, 200, b"ready", request_id)
            return
        if path == "/statusz":
            body = json.dumps(
                {
                    "version": self._opts.version,
                    "mode": str(self._opts.mode),
                    "upstream": self._opts.upstream,
                    "detectors_enabled": len(self._opts.detectors),
                    **self.stats.snapshot(),
                    # The observed block rate is the only signal that tells an
                    # operator their thresholds do not fit this application's
                    # traffic. It belongs where they will look for it.
                    "decision": self._decision.snapshot(),
                    "enforcement_blockers": self._decision.enforcement_blockers(),
                    "rate_limit": self.rate_limiter.snapshot(),
                    "circuit_breaker": self.circuit_breaker.snapshot(),
                }
            ).encode()
            await _respond(send, 200, body, request_id, "application/json")
            return

        # ---- S0 admission: rate limit ------------------------------------
        # The cheapest possible gate: no parse, no detectors. Bounds how much
        # work one principal (client IP here) can force (threat model T4/A6).
        client = scope.get("client") or ("", 0)
        principal = client[0] if isinstance(client, (list, tuple)) and client else ""
        if not self.rate_limiter.allow(principal or "unknown"):
            self.stats.rate_limited += 1
            # A 429 is an action, so it is withheld in shadow like any block.
            if self._enforcing():
                self._audit(request_id, method, path, Decision.RATE_LIMIT,
                            Stage.LIMITS, f"rate_limit:{principal}", 0.0,
                            started, True)
                await _respond(send, 429, b"too many requests", request_id)
                return
            self._audit(request_id, method, path, Decision.RATE_LIMIT,
                        Stage.LIMITS, f"rate_limit_would_apply:{principal}",
                        0.0, started, False)

        # ---- S0a: framing ------------------------------------------------
        # Rejected in EVERY mode, including shadow. Framing violations are not
        # detection verdicts subject to false positives; they are protocol
        # ambiguities that void every downstream guarantee. Forwarding a
        # smuggling primitive in order to "observe" it would forward the attack.
        rejection = framing.check_framing(
            method, path, raw_headers, self._opts.framing_limits
        )
        if rejection is not framing.Rejection.OK:
            self.stats.framing_rejected += 1
            self.stats.blocked += 1
            self._audit(request_id, method, path, Decision.BLOCK,
                        Stage.FRAMING, str(rejection), 0.0, started, True)
            await _respond(send, 400, b"malformed request", request_id)
            return

        header_map = {k.decode("latin-1").lower(): v.decode("latin-1")
                      for k, v in raw_headers}

        # ---- S0b: authentication -----------------------------------------
        token_hash = subject = ""
        if self._opts.auth_enabled and self._is_protected(path):
            auth_failure = self._authenticate(header_map)
            if auth_failure is not None:
                reason = auth_failure
                if reason in ("kid_not_in_allowlist", "no_verification_keys_available",
                              "key_unavailable"):
                    # A genuine key rotation looks exactly like this. Ask the
                    # resolvers to refresh; maybe_refresh() enforces the rate
                    # limit, so unknown-kid floods cost nothing outbound.
                    self._schedule_key_refresh(reason)
                self.stats.auth_rejected += 1
                self.stats.blocked += 1
                # Authentication is enforced in every mode. Shadow exists to
                # tune DETECTION false positives, not to forward tokens we
                # already know are forged.
                self._audit(request_id, method, path, Decision.BLOCK,
                            Stage.AUTH, reason, 0.0, started, True)
                await _respond(send, 401, b"unauthorized", request_id)
                return
            # _authenticate returned None, so the verifier exists and the
            # token verified. Re-verify to obtain the result; the cost is one
            # cached signature check and it avoids threading state through.
            verifier = self._opts.verifier
            if verifier is None:  # pragma: no cover - guarded by _authenticate
                raise RuntimeError("verifier disappeared between checks")
            result = verifier.verify(_bearer(header_map))
            token_hash, subject = result.token_hash, result.subject

        # ---- S0c: extraction ---------------------------------------------
        body = await _read_body(receive, self._opts.extraction_limits.max_body_bytes)
        extracted = extract(
            method, path, scope.get("query_string", b""), raw_headers, body,
            self._opts.extraction_limits,
        )
        extracted.request_meta["request_id"] = request_id

        # ---- S1..S3: detection cascade -----------------------------------
        # Evidence from every stage consulted, not just the first to object.
        # The engine decides; this loop only gathers and knows when to stop.
        evidence: list[StageEvidence] = []
        # A resource cap that fired is a signal, not a silent truncation (T4).
        # An attacker who pads a request to blow the candidate/body/depth cap
        # also hides payload past the cap; recording it lets the decision
        # engine weigh that. Scored below tau by default (FLAG), raisable.
        if extracted.truncation.any:
            evidence.append(StageEvidence(
                stage=Stage.LIMITS,
                decision=(Decision.BLOCK if self._opts.cap_signal_score >= _CAP_BLOCK_AT
                          else Decision.FLAG),
                score=self._opts.cap_signal_score,
                reason=f"resource_cap_exceeded:{extracted.truncation.describe()}",
            ))
        # When the breaker is tripped, the declared degraded posture is
        # "skip the learned stage" -- S3 is the expensive, stall-prone one
        # (T5). Detection by S1/S2 is unchanged; only cost is shed.
        skipped: tuple[Stage, ...] = ()
        degraded = self.circuit_breaker.tripped()
        any_unavailable = False
        for index, detector in enumerate(self._opts.detectors):
            if degraded and detector.name is Stage.MODEL:
                self._log.warning("circuit breaker degraded: skipping model stage",
                                  extra={"fields": {"request_id": request_id}})
                continue
            try:
                candidate_verdict = await detector.evaluate(extracted)
            except Exception as exc:  # noqa: BLE001
                # A failing detector must not fail the request. It degrades
                # the cascade and is recorded; the policy for that degradation
                # is a configuration choice, never an accident (T5).
                self._log.error(
                    "detector error",
                    extra={"fields": {"request_id": request_id,
                                      "stage": str(detector.name),
                                      "error": str(exc)}},
                )
                any_unavailable = True
                continue
            if "unavailable" in candidate_verdict.reason:
                any_unavailable = True
            evidence.append(StageEvidence(
                stage=detector.name,
                decision=candidate_verdict.decision,
                score=candidate_verdict.score,
                reason=candidate_verdict.reason,
            ))
            # Deferral is the engine's call, not this loop's. A FLAG used to
            # end the cascade here, which allowed the request having consulted
            # exactly one stage.
            if not self._decision.defers(candidate_verdict):
                skipped = tuple(d.name for d in self._opts.detectors[index + 1:])
                break

        self.circuit_breaker.record(any_unavailable)
        outcome = self._decision.decide(evidence, skipped)
        self._decision.observe(outcome)
        verdict = Verdict(decision=outcome.decision, stage=outcome.stage,
                          reason=outcome.reason, score=outcome.score)

        blocking = verdict.decision is Decision.BLOCK
        if blocking and not self._enforcing():
            self.stats.shadow_would_block += 1
            self._audit(request_id, method, path, Decision.BLOCK, verdict.stage,
                        verdict.reason, verdict.score, started, False)
        elif blocking:
            self.stats.blocked += 1
            self._audit(request_id, method, path, Decision.BLOCK, verdict.stage,
                        verdict.reason, verdict.score, started, True)
            await _respond(send, 403, b"forbidden", request_id)
            return
        else:
            if verdict.decision is Decision.FLAG:
                self.stats.flagged += 1
            self._audit(request_id, method, path, verdict.decision, verdict.stage,
                        verdict.reason, verdict.score, started, False)

        self.stats.allowed += 1
        await self._forward(scope, extracted.body, header_map, send,
                            request_id, subject, token_hash)

    def _schedule_key_refresh(self, reason: str) -> None:
        for resolver in self._opts.key_resolvers.values():
            maybe = getattr(resolver, "maybe_refresh", None)
            if maybe is None:
                continue
            try:
                task = asyncio.create_task(maybe(reason=reason))
                self._refresh_tasks.add(task)
                task.add_done_callback(self._refresh_tasks.discard)
            except RuntimeError:  # pragma: no cover - no running loop
                pass

    def _authenticate(self, header_map: dict[str, str]) -> str | None:
        """Return a rejection reason on failure, ``None`` on success."""
        if self._opts.verifier is None:
            # Misconfiguration: auth required but no verifier. Fail closed.
            return "verifier_unavailable"
        raw = _bearer(header_map)
        if not raw:
            return "missing_token"
        try:
            self._opts.verifier.verify(raw)
        except VerificationError as exc:
            return str(exc.reason)
        return None

    async def _forward(
        self, scope: dict[str, Any], body: bytes, header_map: dict[str, str], send: Any,
        request_id: str, subject: str, token_hash: str,
    ) -> None:
        outbound = {
            k: v for k, v in header_map.items()
            if k not in _HOP_BY_HOP and k not in _IDENTITY_HEADERS and k != "host"
        }
        if subject:
            outbound["x-csf-subject"] = subject
        if token_hash:
            outbound["x-csf-token-hash"] = token_hash

        query = scope.get("query_string", b"").decode("latin-1")
        url = scope["path"] + (f"?{query}" if query else "")

        try:
            upstream = await self._client.request(
                scope["method"], url, headers=outbound,
                content=body if body else None,
            )
        except httpx.HTTPError as exc:
            self._log.error(
                "upstream error",
                extra={"fields": {"request_id": request_id, "error": str(exc)}},
            )
            # Never leak transport detail to the client.
            await _respond(send, 502, b"upstream unavailable", request_id)
            return

        resp_headers = [
            (k.encode("latin-1"), v.encode("latin-1"))
            for k, v in upstream.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
        ]
        resp_headers.append((b"x-csf-request-id", request_id.encode()))
        resp_headers.append((b"content-length", str(len(upstream.content)).encode()))

        await send({"type": "http.response.start",
                    "status": upstream.status_code, "headers": resp_headers})
        await send({"type": "http.response.body", "body": upstream.content})


def _bearer(header_map: dict[str, str]) -> str:
    value = header_map.get("authorization", "")
    prefix = "bearer "
    if value.lower().startswith(prefix):
        return value[len(prefix):].strip()
    return ""


async def _read_body(receive: Any, max_bytes: int) -> bytes:
    """Read the request body, bounded.

    Reading without a bound is a memory-exhaustion vector (T4). We stop at the
    cap; extraction records that truncation occurred.
    """
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        if chunk:
            size += len(chunk)
            if size > max_bytes:
                chunks.append(chunk[: max_bytes - (size - len(chunk))])
                break
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _respond(
    send: Any, status: int, body: bytes, request_id: str,
    content_type: str = "text/plain",
) -> None:
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", content_type.encode()),
            (b"content-length", str(len(body)).encode()),
            (b"x-csf-request-id", request_id.encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})
