"""Phase 2 exit gate: the JWT attack suite.

Every case here must be blocked, with the correct classification. These are
known, enumerated, deterministically testable failures, so partial credit is
not meaningful.

Note on forging: PyJWT's ``encode`` refuses to build some of these tokens (it
will not use an asymmetric key as an HMAC secret). An attacker does not use
PyJWT. Where needed we assemble and sign tokens by hand, exactly as an
attacker would — see ``forge_hs256_with_public_key``.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from csf.jwtverify import (
    Config,
    IssuerConfig,
    Rejection,
    VerificationError,
    Verifier,
)

ISSUER = "https://auth.csf.test"
AUDIENCE = "csf-api"
KID = "key-2026-01"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class Fixture:
    def __init__(self) -> None:
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.rsa_priv_pem = self.rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        #: Exactly what a JWKS or /pubkey endpoint publishes. Public by
        #: construction — this is the material an RS256->HS256 attack uses.
        self.rsa_pub_pem = self.rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.verifier = Verifier(
            Config(
                issuers={
                    ISSUER: IssuerConfig(
                        issuer=ISSUER,
                        audience=AUDIENCE,
                        allowed_algs=("RS256",),
                        keys={KID: self.rsa_key.public_key()},
                    )
                }
            )
        )

    def claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        base: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-1",
            "exp": now + 3600,
            "nbf": now - 60,
            "iat": now - 60,
        }
        for k, v in overrides.items():
            if v is _DELETE:
                base.pop(k, None)
            else:
                base[k] = v
        return base

    def sign_rs256(self, claims: dict[str, Any], kid: str | None = KID) -> str:
        headers = {"kid": kid} if kid else {}
        return jwt.encode(
            claims, self.rsa_priv_pem, algorithm="RS256", headers=headers
        )


class _Delete:
    pass


_DELETE = _Delete()


@pytest.fixture
def fx() -> Fixture:
    return Fixture()


def forge(header: dict[str, Any], claims: dict[str, Any], signature: str = "") -> str:
    """Assemble a token from arbitrary parts. What an attacker does."""
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(claims).encode())
    return f"{h.decode()}.{p.decode()}.{signature}"


def forge_hs256_with_public_key(pub_pem: bytes, claims: dict[str, Any], kid: str) -> str:
    """The canonical RS256->HS256 key-confusion forgery.

    HMAC-SHA256 over the signing input using the server's PUBLIC KEY BYTES as
    the shared secret. PyJWT's ``encode`` refuses to do this, so we do it by
    hand with ``hmac`` — which is precisely what an attacker does.
    """
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    payload = _b64(json.dumps(claims).encode())
    signing_input = header + b"." + payload
    sig = _b64(hmac.new(pub_pem, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()


# ---------------------------------------------------------------------------
# Positive control. A suite that rejects everything would pass every attack
# test and be worthless.
# ---------------------------------------------------------------------------


def test_valid_token_is_accepted(fx: Fixture) -> None:
    token = fx.sign_rs256(fx.claims())
    result = fx.verifier.verify(token)

    assert result.subject == "user-1"
    assert result.algorithm == "RS256"
    assert result.key_id == KID
    assert result.token_hash, "token_hash must be populated for audit correlation"
    assert token not in result.token_hash


# ---------------------------------------------------------------------------
# The attack suite
# ---------------------------------------------------------------------------


def _attack_cases(fx: Fixture) -> list[tuple[str, str, Rejection, str]]:
    """(name, token, expected rejection, reference)."""
    now = int(time.time())
    return [
        (
            "alg_none_lowercase",
            forge({"alg": "none", "typ": "JWT", "kid": KID}, fx.claims(sub="admin")),
            Rejection.ALG_NONE,
            "RFC 8725 §3.2",
        ),
        (
            "alg_none_mixed_case",
            forge({"alg": "NoNe", "typ": "JWT", "kid": KID}, fx.claims(sub="admin")),
            Rejection.ALG_NONE,
            "RFC 8725 §3.2",
        ),
        (
            "alg_none_with_garbage_signature",
            forge({"alg": "none", "kid": KID}, fx.claims(), "bm90LWEtc2ln"),
            Rejection.ALG_NONE,
            "RFC 8725 §3.2",
        ),
        (
            "alg_empty_string",
            forge({"alg": "", "kid": KID}, fx.claims()),
            Rejection.ALG_NONE,
            "RFC 8725 §3.1",
        ),
        (
            "alg_header_absent",
            forge({"kid": KID}, fx.claims()),
            Rejection.ALG_NONE,
            "RFC 8725 §3.1",
        ),
        (
            "rs256_to_hs256_key_confusion",
            forge_hs256_with_public_key(fx.rsa_pub_pem, fx.claims(sub="admin"), KID),
            Rejection.ALG_CONFUSION,
            "CVE-2026-22817; RFC 8725 §3.1",
        ),
        (
            "hs512_confusion_variant",
            forge(
                {"alg": "HS512", "kid": KID},
                fx.claims(),
                _b64(
                    hmac.new(
                        fx.rsa_pub_pem,
                        _b64(json.dumps({"alg": "HS512", "kid": KID}).encode())
                        + b"."
                        + _b64(json.dumps(fx.claims()).encode()),
                        hashlib.sha512,
                    ).digest()
                ).decode(),
            ),
            Rejection.ALG_CONFUSION,
            "RFC 8725 §3.1",
        ),
        (
            "wrong_asymmetric_algorithm_es256",
            jwt.encode(
                fx.claims(),
                fx.ec_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                algorithm="ES256",
                headers={"kid": KID},
            ),
            Rejection.ALG_NOT_ALLOWED,
            "RFC 8725 §3.1",
        ),
        (
            "wrong_signing_key",
            jwt.encode(
                fx.claims(),
                rsa.generate_private_key(public_exponent=65537, key_size=2048)
                .private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                algorithm="RS256",
                headers={"kid": KID},
            ),
            Rejection.BAD_SIGNATURE,
            "T2",
        ),
        (
            "signature_stripped",
            ".".join(fx.sign_rs256(fx.claims()).split(".")[:2]) + ".",
            Rejection.BAD_SIGNATURE,
            "T2",
        ),
        (
            "payload_tampered_after_signing",
            (
                lambda parts: parts[0]
                + "."
                + _b64(json.dumps(fx.claims(sub="admin", role="superuser")).encode()).decode()
                + "."
                + parts[2]
            )(fx.sign_rs256(fx.claims()).split(".")),
            Rejection.BAD_SIGNATURE,
            "T2",
        ),
        (
            "expired_token",
            fx.sign_rs256(fx.claims(exp=now - 3600)),
            Rejection.EXPIRED,
            "RFC 8725 §3.9",
        ),
        (
            "missing_exp_claim",
            fx.sign_rs256(fx.claims(exp=_DELETE)),
            Rejection.MISSING_CLAIM,
            "RFC 8725 §3.9 (PyJWT does NOT require exp by default)",
        ),
        (
            "nbf_in_the_future",
            fx.sign_rs256(fx.claims(nbf=now + 3600)),
            Rejection.NOT_YET_VALID,
            "RFC 8725 §3.9",
        ),
        (
            "wrong_issuer",
            fx.sign_rs256(fx.claims(iss="https://evil.example")),
            Rejection.UNKNOWN_ISSUER,
            "RFC 8725 §3.8",
        ),
        (
            "missing_issuer",
            fx.sign_rs256(fx.claims(iss=_DELETE)),
            Rejection.MISSING_CLAIM,
            "RFC 8725 §3.8 (PyJWT does NOT verify iss unless issuer= passed)",
        ),
        (
            "wrong_audience",
            fx.sign_rs256(fx.claims(aud="some-other-service")),
            Rejection.AUDIENCE_MISMATCH,
            "RFC 8725 §3.9",
        ),
        (
            "missing_audience",
            fx.sign_rs256(fx.claims(aud=_DELETE)),
            Rejection.MISSING_CLAIM,
            "RFC 8725 §3.9",
        ),
        (
            "missing_subject",
            fx.sign_rs256(fx.claims(sub=_DELETE)),
            Rejection.MISSING_CLAIM,
            "T2",
        ),
        (
            "jku_header_injection",
            forge(
                {
                    "alg": "RS256",
                    "kid": KID,
                    "jku": "https://attacker.example/.well-known/jwks.json",
                },
                fx.claims(),
                "c2ln",
            ),
            Rejection.JKU_PRESENT,
            "RFC 8725 §3.8",
        ),
        (
            "x5u_header_injection",
            forge(
                {"alg": "RS256", "kid": KID, "x5u": "https://attacker.example/c.pem"},
                fx.claims(),
                "c2ln",
            ),
            Rejection.X5U_PRESENT,
            "RFC 8725 §3.8",
        ),
        (
            "kid_path_traversal",
            forge({"alg": "RS256", "kid": "../../../../dev/null"}, fx.claims(), "c2ln"),
            Rejection.KID_SUSPICIOUS,
            "T2 kid traversal",
        ),
        (
            "kid_absolute_path",
            forge({"alg": "RS256", "kid": "/etc/passwd"}, fx.claims(), "c2ln"),
            Rejection.KID_SUSPICIOUS,
            "T2 kid traversal",
        ),
        (
            "kid_sql_injection",
            forge(
                {"alg": "RS256", "kid": "x' UNION SELECT 'secret'--"},
                fx.claims(),
                "c2ln",
            ),
            Rejection.KID_SUSPICIOUS,
            "T2 kid SQLi — injection inside the authentication layer",
        ),
        (
            "kid_unknown_but_clean",
            fx.sign_rs256(fx.claims(), kid="key-does-not-exist"),
            Rejection.KID_UNKNOWN,
            "T2",
        ),
        (
            "kid_missing",
            fx.sign_rs256(fx.claims(), kid=None),
            Rejection.KID_UNKNOWN,
            "T2",
        ),
        (
            "malformed_two_part_token",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9",
            Rejection.MALFORMED,
            "T2",
        ),
        ("malformed_not_base64", "!!!.???.###", Rejection.MALFORMED, "T2"),
        (
            "malformed_header_not_json",
            _b64(b"not json").decode() + ".e30.sig",
            Rejection.MALFORMED,
            "T2",
        ),
        (
            "header_is_json_array_not_object",
            _b64(b'["alg","none"]').decode() + ".e30.sig",
            Rejection.MALFORMED,
            "T2",
        ),
        ("empty_token", "", Rejection.MALFORMED, "T2"),
        ("oversized_token", "A" * 9000 + ".e30.sig", Rejection.OVERSIZED, "T4"),
    ]


def test_jwt_attack_suite(fx: Fixture) -> None:
    cases = _attack_cases(fx)
    failures: list[str] = []
    blocked = 0

    for name, token, want, ref in cases:
        try:
            result = fx.verifier.verify(token)
        except VerificationError as exc:
            blocked += 1
            if exc.reason is not want:
                # A block for the wrong reason is still a block, but the audit
                # log and metrics would misclassify it.
                failures.append(
                    f"{name}: blocked as {exc.reason!r}, want {want!r} (ref={ref})"
                )
            if len(token) > 16 and token[:16] in str(exc):
                failures.append(f"{name}: error message leaks token content")
        except Exception as exc:  # noqa: BLE001
            failures.append(
                f"{name}: raised {type(exc).__name__} instead of VerificationError: {exc}"
            )
        else:
            failures.append(
                f"SECURITY FAILURE: {name} was ACCEPTED (sub={result.subject!r}, ref={ref})"
            )

    print(f"\nJWT attack suite: {blocked}/{len(cases)} cases blocked")
    assert not failures, "\n".join(failures)
    assert blocked == len(cases), (
        f"PHASE 2 EXIT GATE FAILED: {blocked}/{len(cases)} blocked, require 100%"
    )


# ---------------------------------------------------------------------------
# Configuration safety. Unsafe config must fail at startup, not at request time.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "overrides", "why"),
    [
        ("empty_allowlist", {"allowed_algs": ()}, "an empty allowlist is the vulnerability"),
        ("none_in_allowlist", {"allowed_algs": ("none",)}, "'none' must never be configurable"),
        (
            "mixed_sym_asym",
            {"allowed_algs": ("RS256", "HS256")},
            "mixing families is what makes key confusion exploitable",
        ),
        ("no_audience", {"audience": ""}, "audience validation is mandatory"),
        ("no_keys", {"keys": {}}, "no keys means nothing can verify"),
        ("unsupported_alg", {"allowed_algs": ("RS1",)}, "unknown algorithms must not pass"),
        ("empty_issuer", {"issuer": ""}, "an empty iss cannot be matched"),
    ],
)
def test_unsafe_configurations_are_rejected_at_startup(
    fx: Fixture, name: str, overrides: dict[str, Any], why: str
) -> None:
    base = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "allowed_algs": ("RS256",),
        "keys": {KID: fx.rsa_key.public_key()},
    }
    base.update(overrides)
    with pytest.raises(ValueError):
        Verifier(Config(issuers={ISSUER: IssuerConfig(**base)}))  # type: ignore[arg-type]
    assert why


def test_empty_kid_in_allowlist_is_rejected(fx: Fixture) -> None:
    with pytest.raises(ValueError, match="empty kid"):
        Verifier(
            Config(
                issuers={
                    ISSUER: IssuerConfig(
                        issuer=ISSUER,
                        audience=AUDIENCE,
                        allowed_algs=("RS256",),
                        keys={"": fx.rsa_key.public_key()},
                    )
                }
            )
        )


def test_no_issuers_configured_is_rejected() -> None:
    with pytest.raises(ValueError, match="no issuers"):
        Verifier(Config(issuers={}))


# ---------------------------------------------------------------------------
# Structural guarantees. A behavioural test proves today's code is safe; these
# stop a future edit from quietly reintroducing the CVE class on a new path.
# ---------------------------------------------------------------------------


def _module_source() -> tuple[str, ast.Module]:
    path = Path(__file__).parent.parent / "csf" / "jwtverify.py"
    src = path.read_text()
    return src, ast.parse(src)


def test_only_one_jwt_decode_call_site_and_it_pins_everything() -> None:
    src, tree = _module_source()

    decode_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "decode"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "jwt"
    ]

    assert decode_calls, (
        "no jwt.decode call site found; update this test if the verification "
        "mechanism changed"
    )
    assert len(decode_calls) == 1, (
        f"found {len(decode_calls)} jwt.decode call sites; the module must have "
        "exactly one so the algorithm allowlist cannot be omitted on a second path"
    )

    kwargs = {kw.arg for kw in decode_calls[0].keywords}
    for required in ("algorithms", "issuer", "audience", "options"):
        assert required in kwargs, (
            f"jwt.decode is missing {required!r}. PyJWT does not require exp and "
            "does not verify iss unless explicitly told to — omitting these "
            "reintroduces the vulnerability."
        )

    # The require list must be present in source.
    assert '"require"' in src, "options={'require': [...]} must pin mandatory claims"
    for claim in ("exp", "iss", "aud", "sub"):
        assert f'"{claim}"' in src, f"{claim} must be a required claim"


def test_result_never_carries_raw_token(fx: Fixture) -> None:
    token = fx.sign_rs256(fx.claims())
    result = fx.verifier.verify(token)

    blob = json.dumps(
        {
            "issuer": result.issuer,
            "subject": result.subject,
            "algorithm": result.algorithm,
            "key_id": result.key_id,
            "token_hash": result.token_hash,
            "claims": result.claims,
        },
        default=str,
    )
    assert token not in blob
    for part in token.split("."):
        if len(part) > 20:
            assert part not in blob, "serialised result contains a raw token segment"
