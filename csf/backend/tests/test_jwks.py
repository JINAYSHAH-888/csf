"""JWKS resolution: rotation, caching, rate limiting, and fail-closed."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from csf.jwks import JWKSConfig, JWKSError, JWKSResolver, StaticKeyResolver
from csf.jwtverify import Config, IssuerConfig, Rejection, VerificationError, Verifier

ISSUER = "https://auth.csf.test"
AUDIENCE = "csf-api"
JWKS_URL = "https://auth.csf.test/.well-known/jwks.json"


# ---------------------------------------------------------------------------
# Helpers: build real JWKS documents from real keys
# ---------------------------------------------------------------------------


def rsa_jwk(key: rsa.RSAPrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    pub = key.public_key()
    blob = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(pub))
    blob.update({"kid": kid, "use": "sig", "alg": "RS256"})
    blob.update(extra)
    return blob


def ec_jwk(key: ec.EllipticCurvePrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    blob = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    blob.update({"kid": kid, "use": "sig", "alg": "ES256"})
    blob.update(extra)
    return blob


def pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def sign(key: rsa.RSAPrivateKey, kid: str, **overrides: Any) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "exp": now + 3600}
    claims.update(overrides)
    return jwt.encode(claims, pem(key), algorithm="RS256", headers={"kid": kid})


class FakeJWKSEndpoint:
    """A controllable JWKS server. Counts requests so the rate limit and
    amplification guard can be asserted on."""

    def __init__(self, document: dict[str, Any] | None = None) -> None:
        self.document = document or {"keys": []}
        self.requests = 0
        self.status = 200
        self.raise_error: Exception | None = None
        self.raw_body: bytes | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.raise_error is not None:
            raise self.raise_error
        if self.raw_body is not None:
            return httpx.Response(self.status, content=self.raw_body)
        return httpx.Response(self.status, json=self.document)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def make_resolver(
    endpoint: FakeJWKSEndpoint, **cfg_overrides: Any
) -> JWKSResolver:
    cfg = JWKSConfig(url=JWKS_URL, **cfg_overrides)
    return JWKSResolver(cfg, client=endpoint.client())


# ---------------------------------------------------------------------------
# Configuration safety
# ---------------------------------------------------------------------------


def test_plaintext_http_jwks_is_refused_for_remote_hosts():
    """A JWKS fetched over http can be substituted by anyone on the path,
    which is a complete authentication bypass."""
    with pytest.raises(ValueError, match="plaintext http"):
        JWKSConfig(url="http://auth.example/jwks.json").validate()


def test_plaintext_http_allowed_for_loopback():
    """Local development must remain possible without inventing TLS."""
    JWKSConfig(url="http://127.0.0.1:8080/jwks.json").validate()
    JWKSConfig(url="http://localhost:8080/jwks.json").validate()


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"url": "ftp://x/jwks"}, "http"),
        ({"min_refresh_interval_seconds": 0}, "min_refresh_interval"),
        ({"ttl_seconds": 0}, "ttl_seconds"),
        ({"max_keys": 0}, "max_keys"),
    ],
)
def test_invalid_jwks_config_rejected(overrides, match):
    base = {"url": JWKS_URL}
    base.update(overrides)
    with pytest.raises(ValueError, match=match):
        JWKSConfig(**base).validate()


# ---------------------------------------------------------------------------
# Fetching and parsing
# ---------------------------------------------------------------------------


async def test_fetches_and_resolves_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint)

    assert not resolver.healthy, "must start unhealthy before any fetch"
    await resolver.refresh()

    assert resolver.healthy
    assert resolver.key_ids == frozenset({"k1"})
    assert resolver.resolve("k1") is not None
    assert resolver.resolve("nope") is None
    await resolver.aclose()


async def test_supports_ec_keys():
    key = ec.generate_private_key(ec.SECP256R1())
    endpoint = FakeJWKSEndpoint({"keys": [ec_jwk(key, "ec1")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()
    assert resolver.resolve("ec1") is not None
    await resolver.aclose()


@pytest.mark.parametrize(
    ("name", "entry_overrides", "reason"),
    [
        ("missing_kid", {"kid": None}, "a key with no kid cannot be selected"),
        ("unsupported_kty", {"kty": "oct"}, "symmetric keys must not enter an RSA issuer"),
        ("use_is_enc", {"use": "enc"}, "an encryption key must not verify signatures"),
    ],
)
async def test_unusable_keys_are_skipped(name, entry_overrides, reason):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good = rsa_jwk(key, "good")
    bad = rsa_jwk(key, "bad")
    for k, v in entry_overrides.items():
        if v is None:
            bad.pop(k, None)
        else:
            bad[k] = v

    endpoint = FakeJWKSEndpoint({"keys": [good, bad]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()

    assert resolver.key_ids == frozenset({"good"}), reason
    await resolver.aclose()


async def test_key_with_disallowed_alg_is_skipped():
    """A provider publishing a key for an algorithm this issuer does not
    accept must not introduce it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint(
        {"keys": [rsa_jwk(key, "ok", alg="RS256"), rsa_jwk(key, "weak", alg="RS1")]}
    )
    resolver = make_resolver(endpoint, allowed_algs=("RS256",))
    await resolver.refresh()
    assert resolver.key_ids == frozenset({"ok"})
    await resolver.aclose()


async def test_oversized_response_rejected():
    endpoint = FakeJWKSEndpoint()
    endpoint.raw_body = b'{"keys":[' + b" " * 300_000 + b"]}"
    resolver = make_resolver(endpoint, max_response_bytes=1024)
    with pytest.raises(JWKSError, match="exceeds"):
        await resolver.refresh()
    await resolver.aclose()


async def test_too_many_keys_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, f"k{i}") for i in range(40)]})
    resolver = make_resolver(endpoint, max_keys=10)
    with pytest.raises(JWKSError, match="max is"):
        await resolver.refresh()
    await resolver.aclose()


@pytest.mark.parametrize(
    ("name", "setup", "match"),
    [
        ("not_json", lambda e: setattr(e, "raw_body", b"<html>nope</html>"), "not valid JSON"),
        ("no_keys_array", lambda e: setattr(e, "document", {"foo": 1}), "missing 'keys'"),
        ("empty_keys", lambda e: setattr(e, "document", {"keys": []}), "no usable keys"),
        ("http_500", lambda e: setattr(e, "status", 500), "fetch failed"),
    ],
)
async def test_malformed_documents_rejected(name, setup, match):
    endpoint = FakeJWKSEndpoint()
    setup(endpoint)
    resolver = make_resolver(endpoint)
    with pytest.raises(JWKSError, match=match):
        await resolver.refresh()
    await resolver.aclose()


async def test_network_failure_raises_but_keeps_previous_snapshot():
    """A transient outage must not disarm the gateway, and an attacker who can
    make the JWKS endpoint fail must not cause an outage of all auth traffic."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()
    assert resolver.healthy

    endpoint.raise_error = httpx.ConnectError("boom")
    with pytest.raises(JWKSError):
        await resolver.refresh()

    assert resolver.healthy, "previous snapshot must survive a failed refresh"
    assert resolver.resolve("k1") is not None
    assert resolver.fetch_failures == 1
    await resolver.aclose()


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


async def test_rotation_installs_new_key_and_drops_old():
    old = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(old, "old")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()
    assert resolver.key_ids == frozenset({"old"})

    endpoint.document = {"keys": [rsa_jwk(new, "new")]}
    await resolver.refresh()

    assert resolver.key_ids == frozenset({"new"})
    assert resolver.resolve("old") is None, "retired key must stop verifying"
    await resolver.aclose()


async def test_overlapping_rotation_window():
    """Providers publish both keys during a rotation; both must verify."""
    old = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint(
        {"keys": [rsa_jwk(old, "old"), rsa_jwk(new, "new")]}
    )
    resolver = make_resolver(endpoint)
    await resolver.refresh()
    assert resolver.key_ids == frozenset({"old", "new"})
    await resolver.aclose()


async def test_negative_cache_cleared_on_refresh():
    """A rotation can introduce a kid previously cached as absent."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()

    resolver.note_absent("k2")
    assert resolver.is_known_absent("k2")

    endpoint.document = {"keys": [rsa_jwk(key, "k1"), rsa_jwk(key, "k2")]}
    await resolver.refresh()
    assert not resolver.is_known_absent("k2")
    await resolver.aclose()


# ---------------------------------------------------------------------------
# The amplification guard. This is the security control, not an optimisation.
# ---------------------------------------------------------------------------


async def test_refresh_is_rate_limited():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint, min_refresh_interval_seconds=60.0)

    await resolver.refresh()
    assert endpoint.requests == 1

    for _ in range(50):
        assert await resolver.maybe_refresh(reason="unknown_kid") is False

    assert endpoint.requests == 1, (
        "unknown-kid traffic triggered outbound fetches; this is an "
        "amplification vector against the identity provider"
    )
    assert resolver.rate_limited_count == 50
    await resolver.aclose()


async def test_unknown_kid_flood_makes_at_most_one_outbound_request():
    """Simulates the attack directly: a stream of random kid values."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint, min_refresh_interval_seconds=30.0)
    await resolver.refresh()
    baseline = endpoint.requests

    for i in range(500):
        kid = f"attacker-kid-{i}"
        if resolver.resolve(kid) is None and not resolver.is_known_absent(kid):
            await resolver.maybe_refresh(reason="unknown_kid")
            resolver.note_absent(kid)

    assert endpoint.requests == baseline, (
        f"500 unknown kids produced {endpoint.requests - baseline} outbound "
        "fetches; must produce none within the rate-limit window"
    )
    await resolver.aclose()


async def test_rate_limit_expires_and_allows_refresh():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint, min_refresh_interval_seconds=0.05)
    await resolver.refresh()
    assert await resolver.maybe_refresh() is False

    time.sleep(0.06)
    assert await resolver.maybe_refresh() is True
    assert endpoint.requests == 2
    await resolver.aclose()


async def test_failed_refresh_does_not_propagate_into_request_path():
    endpoint = FakeJWKSEndpoint()
    endpoint.raise_error = httpx.ConnectError("down")
    resolver = make_resolver(endpoint, min_refresh_interval_seconds=0.0001)
    # maybe_refresh swallows JWKSError; the request path must not see it.
    assert await resolver.maybe_refresh() is False
    await resolver.aclose()


async def test_staleness_is_reported():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint, ttl_seconds=0.05)
    await resolver.refresh()
    assert not resolver.stale
    time.sleep(0.06)
    assert resolver.stale
    await resolver.aclose()


# ---------------------------------------------------------------------------
# Integration with the verifier
# ---------------------------------------------------------------------------


async def test_verifier_accepts_token_signed_by_jwks_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()

    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(ISSUER, AUDIENCE, ("RS256",), resolver)
    }))
    result = verifier.verify(sign(key, "k1"))
    assert result.subject == "user-1"
    assert result.key_id == "k1"
    await resolver.aclose()


async def test_verifier_fails_closed_when_jwks_never_fetched():
    """No keys at all is an operational failure and must be distinguishable
    from an unknown kid, because they need different alerts."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint)  # deliberately not refreshed

    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(ISSUER, AUDIENCE, ("RS256",), resolver)
    }))
    with pytest.raises(VerificationError) as exc:
        verifier.verify(sign(key, "k1"))
    assert exc.value.reason is Rejection.KEY_UNAVAILABLE
    await resolver.aclose()


async def test_verifier_rejects_retired_key_after_rotation():
    old = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(old, "old")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()

    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(ISSUER, AUDIENCE, ("RS256",), resolver)
    }))
    assert verifier.verify(sign(old, "old")).key_id == "old"

    endpoint.document = {"keys": [rsa_jwk(new, "new")]}
    await resolver.refresh()

    with pytest.raises(VerificationError) as exc:
        verifier.verify(sign(old, "old"))
    assert exc.value.reason is Rejection.KID_UNKNOWN
    assert verifier.verify(sign(new, "new")).key_id == "new"
    await resolver.aclose()


async def test_jwks_resolver_does_not_weaken_the_attack_suite():
    """Every S0 guarantee must hold identically with a JWKS-backed resolver.
    A new key source must not become a bypass."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(key, "k1")]})
    resolver = make_resolver(endpoint)
    await resolver.refresh()

    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(ISSUER, AUDIENCE, ("RS256",), resolver)
    }))
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    import base64
    import hashlib
    import hmac

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "admin",
              "exp": int(time.time()) + 3600}
    header = b64(json.dumps({"alg": "HS256", "kid": "k1"}).encode())
    payload = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(pub_pem, header + b"." + payload, hashlib.sha256).digest())
    confusion = (header + b"." + payload + b"." + sig).decode()

    cases = [
        ("alg_none", f"{b64(json.dumps({'alg': 'none', 'kid': 'k1'}).encode()).decode()}"
                     f".{payload.decode()}.", Rejection.ALG_NONE),
        ("key_confusion", confusion, Rejection.ALG_CONFUSION),
        ("jku", f"{b64(json.dumps({'alg': 'RS256', 'kid': 'k1', 'jku': 'https://evil/'}).encode()).decode()}"
                f".{payload.decode()}.x", Rejection.JKU_PRESENT),
        ("kid_traversal", f"{b64(json.dumps({'alg': 'RS256', 'kid': '../../etc/passwd'}).encode()).decode()}"
                          f".{payload.decode()}.x", Rejection.KID_SUSPICIOUS),
        ("expired", sign(key, "k1", exp=int(time.time()) - 10), Rejection.EXPIRED),
    ]
    for name, token, want in cases:
        with pytest.raises(VerificationError) as exc:
            verifier.verify(token)
        assert exc.value.reason is want, f"{name}: got {exc.value.reason}"
    await resolver.aclose()


def test_static_resolver_still_works():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resolver = StaticKeyResolver({"k1": key.public_key()})
    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(ISSUER, AUDIENCE, ("RS256",), resolver)
    }))
    assert verifier.verify(sign(key, "k1")).key_id == "k1"


# ---------------------------------------------------------------------------
# Revocation latency. Measured in an end-to-end run, pinned here so the
# property is known rather than discovered during an incident.
# ---------------------------------------------------------------------------


async def test_retired_key_keeps_verifying_until_ttl_expires():
    """A key removed from the JWKS keeps verifying for up to ``ttl_seconds``.

    This is inherent to TTL caching, not a defect, but it is a REVOCATION
    PROPERTY and must be stated: **revocation latency equals ttl_seconds**
    (default 600 s). Nothing drives a refresh while tokens keep verifying,
    because only an unknown kid or TTL expiry triggers one.

    Operators who need faster revocation must lower ``ttl_seconds`` and accept
    the extra load on the identity provider. Compromised-key revocation inside
    the TTL window requires removing the issuer or restarting, and CSF does
    not currently offer a push/invalidate mechanism.
    """
    old = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = FakeJWKSEndpoint({"keys": [rsa_jwk(old, "old"), rsa_jwk(new, "new")]})
    resolver = make_resolver(endpoint, ttl_seconds=0.05,
                             min_refresh_interval_seconds=0.001)
    await resolver.refresh()

    verifier = Verifier(Config(issuers={
        ISSUER: IssuerConfig(ISSUER, AUDIENCE, ("RS256",), resolver)
    }))
    assert verifier.verify(sign(old, "old")).key_id == "old"

    # Provider retires "old".
    endpoint.document = {"keys": [rsa_jwk(new, "new")]}

    # Still accepted: the snapshot is unchanged and nothing has forced a
    # refresh, because the token verifies fine against the cached key.
    assert verifier.verify(sign(old, "old")).key_id == "old", (
        "documents the revocation window; if this starts failing, the cache "
        "semantics changed and the docs must be updated"
    )

    # Once the TTL lapses and a refresh runs, the retired key stops working.
    time.sleep(0.06)
    assert resolver.stale
    await resolver.refresh(reason="ttl_expired")
    with pytest.raises(VerificationError) as exc:
        verifier.verify(sign(old, "old"))
    assert exc.value.reason is Rejection.KID_UNKNOWN
    await resolver.aclose()
