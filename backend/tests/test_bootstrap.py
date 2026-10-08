"""Startup wiring: fail-closed JWKS, static keys, and the refresh loop."""

from __future__ import annotations

import json
import logging

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from csf.bootstrap import build_auth
from csf.config import AuthConfig, IssuerSettings
from csf.jwks import JWKSConfig, JWKSResolver

ISSUER = "https://auth.csf.test"
AUDIENCE = "csf-api"


@pytest.fixture
def log():
    logger = logging.getLogger("csf.test.bootstrap")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    return logger


def rsa_jwk(key, kid):
    blob = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    blob.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return blob


def issuer_settings(**overrides):
    base = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "allowed_algs": ("RS256",),
        "jwks_url": "https://auth.csf.test/.well-known/jwks.json",
    }
    base.update(overrides)
    return IssuerSettings(**base)


async def test_disabled_auth_builds_nothing(log):
    assert await build_auth(AuthConfig(enabled=False), log) is None


async def test_static_keys_are_loaded_from_pem(log, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_path = tmp_path / "pub.pem"
    pem_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    auth = AuthConfig(
        enabled=True, protected_prefixes=("/admin",),
        issuers=(issuer_settings(jwks_url="", static_keys={"k1": str(pem_path)}),),
    )
    built = await build_auth(auth, log)
    assert built is not None
    assert not built.resolvers, "static keys need no JWKS resolver"

    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "u",
                        "exp": 9999999999}, priv, algorithm="RS256",
                       headers={"kid": "k1"})
    assert built.verifier.verify(token).subject == "u"
    await built.aclose()


async def test_fail_closed_refuses_to_start_when_jwks_unreachable(log, monkeypatch):
    """An instance that starts but rejects every authenticated request is
    worse than one that never starts: it looks healthy and takes traffic."""

    def exploding_transport(self, cfg, client=None, logger=None):
        raise AssertionError("unused")

    original_init = JWKSResolver.__init__

    def patched_init(self, config: JWKSConfig, client=None, logger=None):
        transport = httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(httpx.ConnectError("unreachable"))
        )
        original_init(self, config, client=httpx.AsyncClient(transport=transport),
                      logger=logger)

    monkeypatch.setattr(JWKSResolver, "__init__", patched_init)

    auth = AuthConfig(enabled=True, protected_prefixes=("/admin",),
                      fail_closed=True, issuers=(issuer_settings(),))
    with pytest.raises(RuntimeError, match="Refusing to start"):
        await build_auth(auth, log)


async def test_fail_open_starts_degraded_when_configured(log, monkeypatch):
    """fail_closed=False is a deliberate operator choice; it must work, and
    the instance must report itself unready."""
    original_init = JWKSResolver.__init__

    def patched_init(self, config: JWKSConfig, client=None, logger=None):
        transport = httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(httpx.ConnectError("unreachable"))
        )
        original_init(self, config, client=httpx.AsyncClient(transport=transport),
                      logger=logger)

    monkeypatch.setattr(JWKSResolver, "__init__", patched_init)

    auth = AuthConfig(enabled=True, protected_prefixes=("/admin",),
                      fail_closed=False, issuers=(issuer_settings(),))
    built = await build_auth(auth, log)
    assert built is not None
    resolver = built.resolvers[ISSUER]
    assert not resolver.healthy, "a degraded start must report unhealthy"
    await built.aclose()


async def test_successful_jwks_startup(log, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    document = {"keys": [rsa_jwk(key, "k1")]}
    original_init = JWKSResolver.__init__

    def patched_init(self, config: JWKSConfig, client=None, logger=None):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json=document)
        )
        original_init(self, config, client=httpx.AsyncClient(transport=transport),
                      logger=logger)

    monkeypatch.setattr(JWKSResolver, "__init__", patched_init)

    auth = AuthConfig(enabled=True, protected_prefixes=("/admin",),
                      issuers=(issuer_settings(),))
    built = await build_auth(auth, log)
    assert built is not None
    assert built.resolvers[ISSUER].healthy

    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "u",
                        "exp": 9999999999}, priv, algorithm="RS256",
                       headers={"kid": "k1"})
    assert built.verifier.verify(token).key_id == "k1"
    await built.aclose()
