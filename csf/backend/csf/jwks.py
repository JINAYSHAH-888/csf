"""JWKS key resolution with rotation, caching, and fail-closed semantics.

What this module is for
-----------------------
Static key configuration does not survive contact with a real identity
provider: keys rotate, and a gateway that cannot follow a rotation fails every
request until someone redeploys it. This module fetches a JWKS document from a
**pre-configured** endpoint and keeps a verified key snapshot that
:mod:`csf.jwtverify` reads synchronously.

Security properties
-------------------
The endpoint is configuration, never input. A token's ``jku``/``x5u`` headers
are rejected outright by :mod:`csf.jwtverify` and never reach this module.
``kid`` is only ever used to look up a key in the snapshot.

**Refresh is rate-limited, and that is a security control, not an
optimisation.** The obvious implementation — "unknown kid, so refetch the
JWKS" — hands an attacker an amplification primitive: a stream of requests
bearing random ``kid`` values becomes a stream of outbound fetches against the
identity provider. We therefore enforce a minimum interval between refreshes
and keep a negative cache of ``kid`` values already known to be absent. Under
attack the gateway serves from its existing snapshot and refuses the unknown
``kid`` without making any outbound request (threat model T4, T6).

**Fail-closed is the default.** If no usable snapshot exists, verification
fails. Failing open on authentication converts a transient network problem
into an authentication bypass.

Bounds applied to the fetched document: response size, key count, allowed key
types, and TLS verification (always on, not configurable).

Revocation latency — know this before deploying
------------------------------------------------
**A key removed from the JWKS keeps verifying for up to ``ttl_seconds``**
(default 600 s). Nothing forces a refresh while tokens still verify against
the cached snapshot; only an unknown ``kid`` or TTL expiry triggers one. This
is inherent to TTL caching rather than a defect, but it is a security-relevant
property:

* Normal rotation is unaffected — providers publish the new key before
  retiring the old one, and the overlap window covers it.
* **Emergency revocation of a compromised key is NOT immediate.** Lower
  ``ttl_seconds`` to shorten the window (at the cost of load on the identity
  provider), or remove the issuer and restart. There is currently no
  push/invalidate mechanism.

Pinned by ``test_retired_key_keeps_verifying_until_ttl_expires``.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx
import jwt

__all__ = [
    "JWKSConfig",
    "JWKSError",
    "JWKSResolver",
    "KeyResolver",
    "StaticKeyResolver",
]


class JWKSError(Exception):
    """Raised when a JWKS document cannot be fetched or is unusable."""


@runtime_checkable
class KeyResolver(Protocol):
    """Resolves a ``kid`` to a verification key.

    Implementations must be safe to call from the synchronous verification
    path and must never perform I/O there.
    """

    def resolve(self, kid: str) -> Any | None:
        """Return the key for ``kid``, or ``None`` if not available."""
        ...

    @property
    def key_ids(self) -> frozenset[str]:
        """Currently known key ids. Used for startup validation and
        diagnostics, never for authorisation decisions."""
        ...


@dataclass(frozen=True, slots=True)
class StaticKeyResolver:
    """A fixed key allowlist. Suitable for tests and pinned-key deployments."""

    keys: dict[str, Any]

    def resolve(self, kid: str) -> Any | None:
        return self.keys.get(kid)

    @property
    def key_ids(self) -> frozenset[str]:
        return frozenset(self.keys)


#: Key types we will import. Anything else in the document is skipped with a
#: warning rather than causing the whole fetch to fail — a provider adding an
#: exotic key must not break verification for the keys we do understand.
_SUPPORTED_KTY = frozenset({"RSA", "EC"})


@dataclass(slots=True)
class JWKSConfig:
    """Configuration for one issuer's JWKS endpoint."""

    url: str
    #: How long a snapshot is considered fresh.
    ttl_seconds: float = 600.0
    #: Minimum interval between any two outbound fetches. This is the
    #: rate limit that stops unknown-kid traffic becoming an amplification
    #: vector. Must be > 0.
    min_refresh_interval_seconds: float = 30.0
    #: How long a kid known to be absent stays negatively cached.
    negative_cache_seconds: float = 60.0
    request_timeout_seconds: float = 5.0
    max_response_bytes: int = 256 * 1024
    max_keys: int = 32
    #: Algorithms this issuer accepts. Keys declaring a different ``alg`` are
    #: skipped, so a provider publishing an HMAC key cannot introduce one into
    #: an RSA-only issuer.
    allowed_algs: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise ValueError(f"jwks: url must be http(s), got {self.url!r}")
        if self.url.startswith("http://") and not _is_loopback(self.url):
            raise ValueError(
                f"jwks: refusing plaintext http for a non-loopback endpoint: "
                f"{self.url!r}. A JWKS fetched over http can be substituted by "
                "anyone on the path, which is a complete authentication bypass."
            )
        if self.min_refresh_interval_seconds <= 0:
            raise ValueError(
                "jwks: min_refresh_interval_seconds must be > 0; without it, "
                "unknown-kid traffic becomes an outbound amplification vector"
            )
        if self.ttl_seconds <= 0:
            raise ValueError("jwks: ttl_seconds must be > 0")
        if self.max_keys <= 0:
            raise ValueError("jwks: max_keys must be > 0")


def _is_loopback(url: str) -> bool:
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


@dataclass(slots=True)
class _Snapshot:
    keys: dict[str, Any] = field(default_factory=dict)
    fetched_at: float = 0.0

    @property
    def empty(self) -> bool:
        return not self.keys


class JWKSResolver:
    """Fetches and caches a JWKS document for one issuer.

    :meth:`resolve` is synchronous and never performs I/O: it reads the
    current snapshot. Refreshes happen via :meth:`refresh` (called at startup
    and by a background task) and via :meth:`maybe_refresh`, which honours the
    rate limit.
    """

    def __init__(self, config: JWKSConfig, client: httpx.AsyncClient | None = None,
                 logger: Any | None = None) -> None:
        config.validate()
        self._cfg = config
        self._log = logger
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=config.request_timeout_seconds,
            # TLS verification is always on and deliberately not configurable.
            verify=True,
            follow_redirects=False,
        )
        self._snapshot = _Snapshot()
        self._negative: dict[str, float] = {}
        self._last_attempt = 0.0
        self._lock = asyncio.Lock()
        self.fetch_failures = 0
        self.refresh_count = 0
        self.rate_limited_count = 0

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- synchronous read path -------------------------------------------

    def resolve(self, kid: str) -> Any | None:
        """Return the key for ``kid`` from the current snapshot.

        Never performs I/O. A ``kid`` absent from the snapshot returns
        ``None``, and the caller fails the request — fail-closed.
        """
        return self._snapshot.keys.get(kid)

    @property
    def key_ids(self) -> frozenset[str]:
        return frozenset(self._snapshot.keys)

    @property
    def stale(self) -> bool:
        if self._snapshot.empty:
            return True
        return (time.monotonic() - self._snapshot.fetched_at) > self._cfg.ttl_seconds

    @property
    def healthy(self) -> bool:
        """Whether verification can proceed at all."""
        return not self._snapshot.empty

    def is_known_absent(self, kid: str) -> bool:
        """Whether ``kid`` is negatively cached.

        Lets the caller distinguish "we checked recently and this key does not
        exist" from "we have never looked", without making a request.
        """
        expiry = self._negative.get(kid)
        if expiry is None:
            return False
        if time.monotonic() > expiry:
            del self._negative[kid]
            return False
        return True

    def note_absent(self, kid: str) -> None:
        """Record that ``kid`` is not in the current snapshot."""
        self._negative[kid] = time.monotonic() + self._cfg.negative_cache_seconds

    # -- refresh path ------------------------------------------------------

    async def maybe_refresh(self, *, reason: str = "scheduled") -> bool:
        """Refresh if the rate limit allows. Returns whether a fetch ran.

        This is the amplification guard. An attacker sending unknown ``kid``
        values can call into this path arbitrarily often; it must make at most
        one outbound request per ``min_refresh_interval_seconds``.
        """
        now = time.monotonic()
        if now - self._last_attempt < self._cfg.min_refresh_interval_seconds:
            self.rate_limited_count += 1
            return False
        try:
            await self.refresh(reason=reason)
        except JWKSError:
            # Already counted and logged in refresh(); a failed refresh must
            # not propagate into the request path.
            return False
        return True

    async def refresh(self, *, reason: str = "manual") -> None:
        """Fetch and install a new snapshot.

        Raises :class:`JWKSError` on failure. **The existing snapshot is
        retained on failure** — a transient outage must not disarm the
        gateway, and an attacker who can make the JWKS endpoint fail must not
        thereby cause an outage of all authenticated traffic.
        """
        async with self._lock:
            self._last_attempt = time.monotonic()
            try:
                response = await self._client.get(
                    self._cfg.url, headers={"accept": "application/json"}
                )
                response.raise_for_status()
            except httpx.HTTPError as exc:
                self.fetch_failures += 1
                self._warn("jwks fetch failed", url=self._cfg.url, error=str(exc))
                raise JWKSError(f"jwks fetch failed: {exc}") from exc

            raw = response.content
            if len(raw) > self._cfg.max_response_bytes:
                self.fetch_failures += 1
                raise JWKSError(
                    f"jwks response exceeds {self._cfg.max_response_bytes} bytes"
                )

            try:
                document = json.loads(raw)
            except json.JSONDecodeError as exc:
                self.fetch_failures += 1
                raise JWKSError("jwks response is not valid JSON") from exc

            keys = self._parse(document)
            if not keys:
                self.fetch_failures += 1
                raise JWKSError("jwks document contained no usable keys")

            self._snapshot = _Snapshot(keys=keys, fetched_at=time.monotonic())
            self.refresh_count += 1
            # A rotation can introduce a kid we previously cached as absent.
            self._negative.clear()
            self._info("jwks refreshed", url=self._cfg.url,
                       key_count=len(keys), reason=reason)

    def _parse(self, document: Any) -> dict[str, Any]:
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise JWKSError("jwks document missing 'keys' array")

        entries = document["keys"]
        if len(entries) > self._cfg.max_keys:
            raise JWKSError(
                f"jwks document has {len(entries)} keys, max is {self._cfg.max_keys}"
            )

        keys: dict[str, Any] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid:
                # A key with no kid cannot be selected unambiguously.
                self._warn("jwks key skipped: missing kid")
                continue
            kty = entry.get("kty")
            if kty not in _SUPPORTED_KTY:
                self._warn("jwks key skipped: unsupported kty", kid=kid, kty=str(kty))
                continue
            use = entry.get("use")
            if use is not None and use != "sig":
                # An encryption key must never be used to verify a signature.
                self._warn("jwks key skipped: use is not 'sig'", kid=kid, use=str(use))
                continue
            alg = entry.get("alg")
            if (
                self._cfg.allowed_algs
                and isinstance(alg, str)
                and alg not in self._cfg.allowed_algs
            ):
                self._warn("jwks key skipped: alg not allowed for issuer",
                           kid=kid, alg=alg)
                continue
            try:
                keys[kid] = _import_jwk(entry)
            except Exception as exc:  # noqa: BLE001 - provider data is untrusted
                self._warn("jwks key skipped: import failed", kid=kid, error=str(exc))
        return keys

    def _info(self, message: str, **fields: Any) -> None:
        if self._log is not None:
            self._log.info(message, extra={"fields": fields})

    def _warn(self, message: str, **fields: Any) -> None:
        if self._log is not None:
            self._log.warning(message, extra={"fields": fields})


def _import_jwk(entry: dict[str, Any]) -> Any:
    """Convert one JWK into a cryptography public key object.

    Delegates to PyJWT's algorithm implementations rather than hand-rolling
    JWK parsing, which is a well-known source of bugs.
    """
    kty = entry["kty"]
    blob = json.dumps(entry)
    if kty == "RSA":
        return jwt.algorithms.RSAAlgorithm.from_jwk(blob)
    if kty == "EC":
        return jwt.algorithms.ECAlgorithm.from_jwk(blob)
    raise JWKSError(f"unsupported kty {kty!r}")
