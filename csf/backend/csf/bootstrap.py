"""Builds a verifier and its key resolvers from configuration.

Startup ordering is a security decision here. With ``fail_closed`` set (the
default), a JWKS endpoint that cannot be reached at startup **fails the
process** rather than letting the gateway come up unable to verify anything.
An instance that starts but rejects every authenticated request is worse than
one that never starts: the former looks healthy to an orchestrator and quietly
takes traffic.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from csf.config import AuthConfig, IssuerSettings
from csf.jwks import JWKSConfig, JWKSError, JWKSResolver, StaticKeyResolver
from csf.jwtverify import Config, IssuerConfig, Verifier

__all__ = ["BuiltAuth", "build_auth", "run_refresh_loop"]


class BuiltAuth:
    """The verifier plus the resolvers backing it."""

    def __init__(self, verifier: Verifier, resolvers: dict[str, JWKSResolver]) -> None:
        self.verifier = verifier
        self.resolvers = resolvers

    async def aclose(self) -> None:
        for resolver in self.resolvers.values():
            await resolver.aclose()


def _load_static_keys(settings: IssuerSettings) -> dict[str, Any]:
    keys: dict[str, Any] = {}
    for kid, path in settings.static_keys.items():
        pem = Path(path).read_bytes()
        keys[kid] = serialization.load_pem_public_key(pem)
    return keys


async def build_auth(auth: AuthConfig, logger: Any) -> BuiltAuth | None:
    """Construct the verifier, fetching JWKS documents up front."""
    if not auth.enabled:
        return None

    resolvers: dict[str, JWKSResolver] = {}
    issuers: dict[str, IssuerConfig] = {}

    for settings in auth.issuers:
        settings.validate()
        if settings.jwks_url:
            resolver = JWKSResolver(
                JWKSConfig(
                    url=settings.jwks_url,
                    ttl_seconds=settings.jwks_ttl_seconds,
                    min_refresh_interval_seconds=settings.jwks_min_refresh_interval_seconds,
                    allowed_algs=settings.allowed_algs,
                ),
                logger=logger,
            )
            try:
                await resolver.refresh(reason="startup")
            except JWKSError as exc:
                if auth.fail_closed:
                    await resolver.aclose()
                    raise RuntimeError(
                        f"startup: JWKS fetch failed for issuer "
                        f"{settings.issuer!r} ({exc}). Refusing to start: with "
                        "fail_closed set, this instance could not verify any "
                        "token, and starting anyway would place an instance "
                        "that rejects all authenticated traffic into service."
                    ) from exc
                logger.error(
                    "jwks startup fetch failed; continuing because "
                    "fail_closed is disabled",
                    extra={"fields": {"issuer": settings.issuer, "error": str(exc)}},
                )
            resolvers[settings.issuer] = resolver
            keys: Any = resolver
        else:
            keys = StaticKeyResolver(_load_static_keys(settings))

        issuers[settings.issuer] = IssuerConfig(
            issuer=settings.issuer,
            audience=settings.audience,
            allowed_algs=settings.allowed_algs,
            keys=keys,
            leeway_seconds=settings.leeway_seconds,
        )

    verifier = Verifier(Config(issuers=issuers))
    logger.info(
        "auth configured",
        extra={"fields": {
            "issuers": list(issuers),
            "jwks_backed": list(resolvers),
            "fail_closed": auth.fail_closed,
        }},
    )
    return BuiltAuth(verifier, resolvers)


async def run_refresh_loop(
    resolvers: dict[str, JWKSResolver], logger: Any, interval: float = 60.0
) -> None:
    """Periodically refresh stale JWKS documents.

    Refreshing proactively on a timer means a rotation is picked up without
    waiting for a request bearing the new ``kid`` to arrive and fail first.
    """
    while True:
        await asyncio.sleep(interval)
        for name, resolver in resolvers.items():
            if not resolver.stale:
                continue
            try:
                await resolver.refresh(reason="ttl_expired")
            except JWKSError as exc:
                # The previous snapshot survives; keep serving and alert.
                logger.warning(
                    "scheduled jwks refresh failed; serving previous snapshot",
                    extra={"fields": {"issuer": name, "error": str(exc)}},
                )
