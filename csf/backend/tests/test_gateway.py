"""Gateway integration tests driven through a real ASGI transport."""

from __future__ import annotations

import logging
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from csf.extraction import Result as ExtractionResult
from csf.gateway import Decision, Gateway, GatewayOptions, Stage, Verdict
from csf.jwtverify import Config, IssuerConfig, Verifier
from csf.telemetry import Mode

ISSUER = "https://auth.csf.test"
AUDIENCE = "csf-api"
KID = "k1"


class Upstream:
    """Records what the backend actually received."""

    def __init__(self) -> None:
        self.hits = 0
        self.body = b""
        self.headers: dict[str, str] = {}

    async def __call__(self, scope, receive, send):
        self.hits += 1
        chunks = []
        while True:
            msg = await receive()
            chunks.append(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        self.body = b"".join(chunks)
        self.headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        body = b"upstream-ok"
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class FixedDetector:
    def __init__(self, name: Stage, verdict: Verdict, raises: bool = False) -> None:
        self._name = name
        self._verdict = verdict
        self._raises = raises
        self.calls = 0

    @property
    def name(self) -> Stage:
        return self._name

    async def evaluate(self, extracted: ExtractionResult) -> Verdict:
        self.calls += 1
        if self._raises:
            raise RuntimeError("detector exploded")
        return self._verdict


@pytest.fixture
def upstream():
    return Upstream()


def make_gateway(upstream: Upstream, **overrides) -> Gateway:
    logger = logging.getLogger("csf.test")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    overrides.setdefault("mode", Mode.ENFORCE)
    opts = GatewayOptions(upstream="http://upstream.local", **overrides)
    gw = Gateway(opts, logger)
    # Route the gateway's outbound client at the in-process upstream app.
    gw._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream), base_url="http://upstream.local"
    )
    return gw


def client_for(gw: Gateway) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gw), base_url="http://gateway.local"
    )


async def test_forwards_benign_request(upstream):
    gw = make_gateway(upstream)
    async with client_for(gw) as c:
        r = await c.get("/api/items?q=lamp")
    assert r.status_code == 200
    assert upstream.hits == 1
    assert r.headers.get("x-csf-request-id")


async def test_body_survives_extraction_and_reaches_upstream(upstream):
    """Extraction consumes the receive stream; if the body is not preserved,
    every POST silently reaches the backend empty."""
    gw = make_gateway(upstream)
    payload = b'{"name":"alice","note":"hello"}'
    async with client_for(gw) as c:
        r = await c.post("/api/users", content=payload,
                         headers={"content-type": "application/json"})
    assert r.status_code == 200
    assert upstream.body == payload


@pytest.mark.parametrize("mode", [Mode.SHADOW, Mode.MONITOR, Mode.ENFORCE, Mode.EMERGENCY])
async def test_framing_rejected_in_every_mode(upstream, mode):
    gw = make_gateway(upstream, mode=mode)
    async with client_for(gw) as c:
        r = await c.post("/api/x", content=b"x",
                         headers=[("content-length", "1"),
                                  ("transfer-encoding", "chunked")])
    assert r.status_code == 400, f"mode={mode}"
    assert upstream.hits == 0, "smuggling primitive reached upstream"


async def test_shadow_mode_forwards_but_records_would_block(upstream):
    det = FixedDetector(Stage.RULES, Verdict(Decision.BLOCK, Stage.RULES, "test_rule", 10.0))
    gw = make_gateway(upstream, mode=Mode.SHADOW, detectors=(det,))
    async with client_for(gw) as c:
        r = await c.get("/api/x?q=evil")
    assert r.status_code == 200, "shadow mode must forward"
    assert upstream.hits == 1
    assert gw.stats.shadow_would_block == 1
    assert gw.stats.blocked == 0


async def test_enforce_mode_blocks(upstream):
    det = FixedDetector(Stage.SEMANTIC, Verdict(Decision.BLOCK, Stage.SEMANTIC, "sqli_shape"))
    gw = make_gateway(upstream, mode=Mode.ENFORCE, detectors=(det,))
    async with client_for(gw) as c:
        r = await c.get("/api/x?q=evil")
    assert r.status_code == 403
    assert upstream.hits == 0


async def test_cascade_short_circuits_on_first_block(upstream):
    """Running expensive stages after a decision is the cost this design avoids."""
    first = FixedDetector(Stage.RULES, Verdict(Decision.BLOCK, Stage.RULES, "crs_high"))
    second = FixedDetector(Stage.MODEL, Verdict())
    gw = make_gateway(upstream, detectors=(first, second))
    async with client_for(gw) as c:
        await c.get("/?q=x")
    assert first.calls == 1
    assert second.calls == 0, "expensive stage ran after a block"


async def test_detector_error_does_not_fail_the_request(upstream):
    broken = FixedDetector(Stage.MODEL, Verdict(), raises=True)
    gw = make_gateway(upstream, detectors=(broken,))
    async with client_for(gw) as c:
        r = await c.get("/api/x")
    assert r.status_code == 200, "a broken detector must not break the request"
    assert upstream.hits == 1


# -- authentication ------------------------------------------------------


@pytest.fixture
def auth_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(issuer=ISSUER, audience=AUDIENCE,
                             allowed_algs=("RS256",),
                             keys={KID: key.public_key()})
    }))
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return verifier, priv


def sign(priv, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "exp": now + 3600}
    claims.update(overrides)
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": KID})


async def test_protected_route_accepts_valid_token(upstream, auth_pair):
    verifier, priv = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",))
    async with client_for(gw) as c:
        r = await c.get("/admin/users", headers={"authorization": f"Bearer {sign(priv)}"})
    assert r.status_code == 200
    assert upstream.headers.get("x-csf-subject") == "user-1"


async def test_protected_route_rejects_missing_token(upstream, auth_pair):
    verifier, _ = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",))
    async with client_for(gw) as c:
        r = await c.get("/admin/users")
    assert r.status_code == 401
    assert upstream.hits == 0


async def test_protected_route_rejects_alg_none(upstream, auth_pair):
    verifier, _ = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",))
    forged = ("eyJhbGciOiJub25lIiwia2lkIjoiazEifQ."
              "eyJpc3MiOiJodHRwczovL2F1dGguY3NmLnRlc3QiLCJzdWIiOiJhZG1pbiJ9.")
    async with client_for(gw) as c:
        r = await c.get("/admin/users", headers={"authorization": f"Bearer {forged}"})
    assert r.status_code == 401
    assert upstream.hits == 0


async def test_unprotected_route_needs_no_token(upstream, auth_pair):
    verifier, _ = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",))
    async with client_for(gw) as c:
        r = await c.get("/public/health")
    assert r.status_code == 200


async def test_auth_enforced_even_in_shadow_mode(upstream, auth_pair):
    """Shadow exists to tune detection false positives, not to forward tokens
    we already know are forged."""
    verifier, _ = auth_pair
    gw = make_gateway(upstream, mode=Mode.SHADOW, auth_enabled=True,
                      verifier=verifier, protected_prefixes=("/admin",))
    async with client_for(gw) as c:
        r = await c.get("/admin/x")
    assert r.status_code == 401
    assert upstream.hits == 0


async def test_missing_verifier_fails_closed(upstream):
    gw = make_gateway(upstream, auth_enabled=True, verifier=None,
                      protected_prefixes=("/admin",))
    async with client_for(gw) as c:
        r = await c.get("/admin/x")
    assert r.status_code == 401
    assert upstream.hits == 0


async def test_client_supplied_identity_headers_are_stripped(upstream):
    gw = make_gateway(upstream)
    async with client_for(gw) as c:
        await c.get("/api/x", headers={"x-csf-subject": "admin",
                                       "x-csf-token-hash": "deadbeef"})
    assert upstream.headers.get("x-csf-subject") is None
    assert upstream.headers.get("x-csf-token-hash") is None


async def test_upstream_failure_does_not_leak_internals(upstream):
    gw = make_gateway(upstream)
    gw._client = httpx.AsyncClient(base_url="http://127.0.0.1:1", timeout=1.0)
    async with client_for(gw) as c:
        r = await c.get("/")
    assert r.status_code == 502
    text = r.text.lower()
    for leak in ("127.0.0.1", "connect", "refused", "traceback"):
        assert leak not in text, f"response leaks {leak!r}: {text}"


async def test_statusz_reports_counters(upstream):
    gw = make_gateway(upstream)
    async with client_for(gw) as c:
        await c.get("/api/a")
        await c.get("/api/b")
        r = await c.get("/statusz")
    data = r.json()
    assert data["mode"] == "enforce"
    assert data["allowed"] >= 2
    assert data["detectors_enabled"] == 0


async def test_health_endpoints(upstream):
    gw = make_gateway(upstream)
    async with client_for(gw) as c:
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 200
    assert upstream.hits == 0, "health checks must not hit the upstream"


# -- readiness -----------------------------------------------------------


class FakeResolver:
    def __init__(self, healthy: bool) -> None:
        self._healthy = healthy
        self.refresh_calls = 0

    @property
    def healthy(self) -> bool:
        return self._healthy

    def resolve(self, kid): return None

    @property
    def key_ids(self): return frozenset()

    async def maybe_refresh(self, *, reason: str = "") -> bool:
        self.refresh_calls += 1
        return False


async def test_readyz_fails_when_jwks_has_no_keys(upstream, auth_pair):
    """If auth is enabled and no key is available, every protected request
    fails closed — this instance must leave the load-balancer pool."""
    verifier, _ = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",),
                      key_resolvers={"iss": FakeResolver(healthy=False)})
    async with client_for(gw) as c:
        r = await c.get("/readyz")
    assert r.status_code == 503
    assert "no verification keys" in r.json()["problems"][0]


async def test_healthz_stays_up_during_jwks_outage(upstream, auth_pair):
    """Liveness must not depend on JWKS: restarting the pod cannot fix a
    remote outage, so a failing /healthz would just cause a restart loop."""
    verifier, _ = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",),
                      key_resolvers={"iss": FakeResolver(healthy=False)})
    async with client_for(gw) as c:
        assert (await c.get("/healthz")).status_code == 200


async def test_readyz_ok_when_keys_available(upstream, auth_pair):
    verifier, _ = auth_pair
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",),
                      key_resolvers={"iss": FakeResolver(healthy=True)})
    async with client_for(gw) as c:
        assert (await c.get("/readyz")).status_code == 200


async def test_unknown_kid_schedules_rate_limited_refresh(upstream, auth_pair):
    """A genuine rotation looks like an unknown kid, so we must react — but
    maybe_refresh() enforces the rate limit so floods cost nothing outbound."""
    import asyncio

    verifier, priv = auth_pair
    resolver = FakeResolver(healthy=True)
    gw = make_gateway(upstream, auth_enabled=True, verifier=verifier,
                      protected_prefixes=("/admin",),
                      key_resolvers={"iss": resolver})
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u", "exp": int(time.time()) + 60},
        priv, algorithm="RS256", headers={"kid": "rotated-key"})
    async with client_for(gw) as c:
        r = await c.get("/admin/x", headers={"authorization": f"Bearer {token}"})
    assert r.status_code == 401
    await asyncio.sleep(0)
    assert resolver.refresh_calls == 1


# -- S4 decision engine integration (Phase 7) -----------------------------


async def test_flag_does_not_suppress_later_stages(upstream):
    """The defect the decision engine was built to fix.

    The cascade used to stop at the first verdict that was not ALLOW. A FLAG
    means "allow and record", so a weak signal from a cheap stage silently
    prevented every later stage from running and the request was allowed
    having been seen by one detector. Measured on the corpora in hand: 2 of
    421 claimed attacks on CSIC reached only S1 this way.
    """
    s1 = FixedDetector(Stage.RULES, Verdict(Decision.FLAG, Stage.RULES, "weak", 3.0))
    s2 = FixedDetector(Stage.SEMANTIC,
                       Verdict(Decision.BLOCK, Stage.SEMANTIC, "sqli", 7.0))
    gw = make_gateway(upstream, detectors=(s1, s2))
    async with client_for(gw) as c:
        r = await c.get("/?q=x")
    assert s2.calls == 1, "a FLAG from an earlier stage suppressed a later one"
    assert r.status_code == 403, "the request should have been blocked by S2"


async def test_block_still_short_circuits(upstream):
    """Deferring on FLAG must not cost the cost-ordering that justifies a cascade."""
    s1 = FixedDetector(Stage.RULES, Verdict(Decision.BLOCK, Stage.RULES, "crs", 12.0))
    s2 = FixedDetector(Stage.SEMANTIC, Verdict())
    gw = make_gateway(upstream, detectors=(s1, s2))
    async with client_for(gw) as c:
        await c.get("/?q=x")
    assert s2.calls == 0


async def test_strongest_stage_is_reported_not_the_first(upstream):
    s1 = FixedDetector(Stage.RULES, Verdict(Decision.FLAG, Stage.RULES, "weak", 3.0))
    s2 = FixedDetector(Stage.SEMANTIC,
                       Verdict(Decision.BLOCK, Stage.SEMANTIC, "grammar", 9.0))
    gw = make_gateway(upstream, detectors=(s1, s2))
    async with client_for(gw) as c:
        await c.get("/?q=x")
    snap = gw.decision_engine.snapshot()
    assert snap["blocks"] == 1


async def test_block_rate_budget_is_observed_through_the_gateway(upstream):
    """A configuration that blocks most traffic must be visible as such."""
    from csf.decision import DecisionConfig

    s1 = FixedDetector(Stage.RULES, Verdict(Decision.BLOCK, Stage.RULES, "crs", 12.0))
    gw = make_gateway(upstream, detectors=(s1,), mode=Mode.SHADOW,
                      decision=DecisionConfig(max_block_rate_pct=5.0,
                                              budget_min_samples=5))
    async with client_for(gw) as c:
        for _ in range(10):
            await c.get("/?q=x")
    assert gw.decision_engine.budget().over_budget
    assert gw._readiness_problems(), (
        "an out-of-budget block rate must surface in readiness, so enabling "
        "enforcement is gated by an observation rather than by hope"
    )


# -- S0 admission control and resilience (Phase 9/10) ----------------------


async def test_rate_limit_returns_429_in_enforce(upstream):
    from csf.resilience import RateLimitConfig

    gw = make_gateway(upstream, mode=Mode.ENFORCE,
                      rate_limit=RateLimitConfig(enabled=True, rate_per_second=1,
                                                 burst=2))
    async with client_for(gw) as c:
        codes = [(await c.get("/?q=x")).status_code for _ in range(5)]
    assert 429 in codes, "a principal over budget must be rate-limited"
    assert codes.count(429) == 3, "burst=2 should let 2 through, limit the next 3"
    assert gw.stats.rate_limited == 3


async def test_rate_limit_is_withheld_in_shadow(upstream):
    """A 429 is an action; shadow mode records it but does not apply it."""
    from csf.resilience import RateLimitConfig

    gw = make_gateway(upstream, mode=Mode.SHADOW,
                      rate_limit=RateLimitConfig(enabled=True, rate_per_second=1,
                                                 burst=1))
    async with client_for(gw) as c:
        codes = [(await c.get("/?q=x")).status_code for _ in range(4)]
    assert 429 not in codes, "shadow mode must not actually rate-limit"
    assert gw.stats.rate_limited >= 1, "but it must record that it would have"


async def test_cap_exceeded_becomes_a_signal(upstream):
    """A request that blows the candidate cap is recorded as a signal (T4),
    not silently truncated and forgotten."""
    from csf.extraction import ExtractionLimits

    # cap_signal_score >= 4.0 makes a cap-hit block.
    limits = ExtractionLimits(max_candidates=3)
    gw = make_gateway(upstream, mode=Mode.ENFORCE, extraction_limits=limits,
                      cap_signal_score=5.0)
    async with client_for(gw) as c:
        r = await c.get("/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8")
    assert r.status_code == 403, "a cap-exceeded request scored to block should block"


async def test_cap_exceeded_flags_by_default(upstream):
    from csf.extraction import ExtractionLimits

    limits = ExtractionLimits(max_candidates=3)
    gw = make_gateway(upstream, mode=Mode.ENFORCE, extraction_limits=limits)
    async with client_for(gw) as c:
        r = await c.get("/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8")
    # Default cap_signal_score=2.0 < 4.0 → FLAG, request still forwarded.
    assert r.status_code == 200
    assert gw.stats.flagged == 1


async def test_breaker_degrades_by_skipping_the_model_stage(upstream):
    """When tripped, the learned stage is skipped; S1/S2 detection is unchanged."""
    from csf.resilience import CircuitBreakerConfig

    # A model stage that always errors, to drive the breaker.
    model = FixedDetector(Stage.MODEL, Verdict(), raises=True)
    gw = make_gateway(upstream, mode=Mode.ENFORCE, detectors=(model,),
                      circuit_breaker=CircuitBreakerConfig(
                          trip_threshold_pct=25, min_samples=10, window=500,
                          cooldown_seconds=100))
    async with client_for(gw) as c:
        for _ in range(20):
            await c.get("/?q=x")
        # Breaker should now be tripped; the model stage stops being called.
        calls_before = model.calls
        for _ in range(5):
            await c.get("/?q=x")
    assert gw.circuit_breaker.tripped()
    assert model.calls == calls_before, "a tripped breaker must stop calling the model"
    assert gw._readiness_problems(), "a tripped breaker must show in readiness"


# -- Prometheus /metrics (production observability) ------------------------


async def test_metrics_endpoint_exposes_prometheus(upstream):
    gw = make_gateway(upstream, mode=Mode.ENFORCE,
                      detectors=(FixedDetector(Stage.RULES,
                                 Verdict(Decision.BLOCK, Stage.RULES, "crs", 12.0)),))
    async with client_for(gw) as c:
        await c.get("/?q=attack")        # one blocked request
        await c.get("/healthz")          # admin endpoint: must NOT be counted
        r = await c.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "# TYPE csf_request_duration_seconds histogram" in body
    assert 'csf_requests_total{decision="block"} 1' in body
    assert "csf_up 1" in body
    # The admin endpoints (healthz/metrics) do not go through _audit, so they
    # must not inflate the request metrics: no "allow" was recorded.
    allow_lines = [ln for ln in body.splitlines()
                   if ln.startswith('csf_requests_total{decision="allow"}')]
    assert all(ln.endswith(" 0") for ln in allow_lines)


async def test_metrics_records_latency_and_stage_blocks(upstream):
    gw = make_gateway(upstream, mode=Mode.ENFORCE,
                      detectors=(FixedDetector(Stage.SEMANTIC,
                                 Verdict(Decision.BLOCK, Stage.SEMANTIC, "sqli", 7.0)),))
    async with client_for(gw) as c:
        for _ in range(3):
            await c.get("/?q=x")
        r = await c.get("/metrics")
    body = r.text
    assert 'csf_stage_blocks_total{stage="s2_semantic"} 3' in body
    assert "csf_request_duration_seconds_count 3" in body


async def test_metrics_breaker_gauge_reflects_state(upstream):
    from csf.resilience import CircuitBreakerConfig

    model = FixedDetector(Stage.MODEL, Verdict(), raises=True)
    gw = make_gateway(upstream, mode=Mode.ENFORCE, detectors=(model,),
                      circuit_breaker=CircuitBreakerConfig(
                          trip_threshold_pct=25, min_samples=10, window=500,
                          cooldown_seconds=100))
    async with client_for(gw) as c:
        for _ in range(20):
            await c.get("/?q=x")
        r = await c.get("/metrics")
    assert "csf_circuit_breaker_tripped 1" in r.text
