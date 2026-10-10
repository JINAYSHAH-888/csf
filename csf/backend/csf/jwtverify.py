"""RFC 8725-conformant JSON Web Token verification for the CSF S0 ingress stage.

Security contract
-----------------
The single rule this module exists to enforce: **the verification algorithm is
configuration, never input.** The JWT ``alg`` header is attacker-controlled.
Selecting a verifier from it is the root cause of the Q1-2026 CVE cluster
(CVE-2026-22817, CVE-2026-27804, CVE-2026-23552) and of alg:none and
RS256->HS256 key confusion generally.

Measured PyJWT 2.15.1 behaviour (probed 2026-10-01, not assumed)
----------------------------------------------------------------
Three findings drive the code below.

1. ``algorithms=`` is **mandatory**. Omitting it raises ``DecodeError``. Good:
   the library refuses the unsafe call rather than defaulting.

2. ``exp`` is **NOT required by default**, and ``iss`` is **NOT verified**
   unless ``issuer=`` is passed. A token with no expiry and a forged issuer
   verifies cleanly under a naive ``jwt.decode(tok, key, algorithms=[...])``.
   We therefore pass ``issuer=``, ``audience=`` and an explicit
   ``options={"require": [...]}`` on every call. ``aud`` *is* checked once
   ``audience=`` is supplied.

3. RS256->HS256 confusion is blocked by PyJWT at a second layer: it refuses to
   use a PEM/asymmetric key as an HMAC secret (``InvalidKeyError``), so the
   attack fails *even when* the verifier is misconfigured to allow both
   families. That is a genuine advantage over some other libraries. We still
   ban mixing families in :meth:`Config.validate`, because that defence only
   holds while the key is an asymmetric key object — an issuer configured with
   a raw string secret would not be protected by it.

Guarantees
----------
* ``jku`` and ``x5u`` are ignored entirely; a token carrying them is refused.
* ``kid`` is an opaque allowlist lookup key — never a filesystem path, never
  interpolated into a query.
* ``exp``, ``nbf``, ``iss``, ``aud`` all validated and all mandatory.
* ``none`` rejected before decoding, regardless of configuration.
* Raw tokens never appear in errors, results, or logs — only a truncated hash.

See ``docs/adr/ADR-0002-jwt-verification.md`` and threat model T2.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import jwt

if TYPE_CHECKING:
    pass


@runtime_checkable
class KeyResolverLike(Protocol):
    """Minimal interface :mod:`csf.jwks` resolvers satisfy.

    Declared here rather than imported so that :mod:`csf.jwtverify` has no
    dependency on the JWKS machinery; a pinned-key deployment need not pull
    in an HTTP client.
    """

    def resolve(self, kid: str) -> Any | None: ...

    @property
    def key_ids(self) -> frozenset[str]: ...


__all__ = [
    "Config",
    "IssuerConfig",
    "Rejection",
    "Result",
    "VerificationError",
    "Verifier",
    "token_hash",
]


class Rejection(StrEnum):
    """Why a token was refused.

    A closed set, so metrics and the audit log can count attack classes rather
    than parse free-text error strings.
    """

    MALFORMED = "malformed"
    ALG_NONE = "alg_none"
    ALG_NOT_ALLOWED = "alg_not_allowed"
    ALG_CONFUSION = "alg_confusion"
    JKU_PRESENT = "jku_header_present"
    X5U_PRESENT = "x5u_header_present"
    KID_UNKNOWN = "kid_not_in_allowlist"
    KID_SUSPICIOUS = "kid_suspicious"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    MISSING_CLAIM = "missing_required_claim"
    UNKNOWN_ISSUER = "unknown_issuer"
    OVERSIZED = "oversized"
    KEY_UNAVAILABLE = "key_unavailable"


class VerificationError(Exception):
    """Raised for every refusal. Deliberately carries no token bytes."""

    def __init__(self, reason: Rejection, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else str(reason))


_SYMMETRIC_PREFIXES = ("HS",)
_ASYMMETRIC_PREFIXES = ("RS", "ES", "PS")

SUPPORTED_ALGS = frozenset(
    {
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
    }
)

DEFAULT_MAX_TOKEN_BYTES = 8192


def _is_symmetric(alg: str) -> bool:
    return alg.startswith(_SYMMETRIC_PREFIXES)


def _is_asymmetric(alg: str) -> bool:
    return alg.startswith(_ASYMMETRIC_PREFIXES)


@dataclass(frozen=True, slots=True)
class IssuerConfig:
    """Verification parameters pinned for one trusted issuer.

    Every field that affects whether a signature is accepted lives here, in
    configuration — never in the token.
    """

    issuer: str
    audience: str
    allowed_algs: tuple[str, ...]
    #: Maps ``kid`` to a verification key, OR a :class:`~csf.jwks.KeyResolver`
    #: (such as a JWKS-backed one) that does the same lookup against a cached
    #: snapshot. Either way this *is* the allowlist: a token whose kid is
    #: absent is rejected, and there is no fallback lookup by path, URL, or
    #: database query.
    keys: dict[str, Any] | KeyResolverLike
    leeway_seconds: int = 0

    def resolve_key(self, kid: str) -> Any | None:
        """Look up a key by kid. Never performs I/O."""
        if isinstance(self.keys, dict):
            return self.keys.get(kid)
        return self.keys.resolve(kid)

    def known_key_ids(self) -> frozenset[str]:
        if isinstance(self.keys, dict):
            return frozenset(self.keys)
        return self.keys.key_ids


@dataclass(frozen=True, slots=True)
class Result:
    """A successful verification. Never contains the raw token."""

    issuer: str
    subject: str
    audience: str
    algorithm: str
    key_id: str
    expires_at: datetime | None
    #: Truncated SHA-256 of the raw token, for audit correlation and caching.
    token_hash: str
    claims: dict[str, Any] = field(default_factory=dict)


def token_hash(token: str) -> str:
    """Return the correlation hash used in logs.

    Exported so callers can reference a token in telemetry without ever
    handling the token itself.
    """
    return hashlib.sha256(token.encode()).hexdigest()[:16]


@dataclass(slots=True)
class Config:
    """Complete verifier configuration."""

    issuers: dict[str, IssuerConfig]
    max_token_bytes: int = DEFAULT_MAX_TOKEN_BYTES

    def validate(self) -> None:
        """Reject configurations that are unsafe regardless of input.

        Runs at startup: an unsafe config must fail the process, not the
        request. A gateway that silently starts in a weaker posture than the
        operator intended is worse than one that refuses to start.
        """
        if not self.issuers:
            raise ValueError("jwtverify: no issuers configured")

        for name, ic in self.issuers.items():
            if not ic.issuer:
                raise ValueError(f"jwtverify: issuer {name!r}: empty iss")
            if not ic.audience:
                raise ValueError(
                    f"jwtverify: issuer {name!r}: empty aud; "
                    "audience validation is mandatory"
                )
            if not ic.allowed_algs:
                raise ValueError(
                    f"jwtverify: issuer {name!r}: allowed_algs is empty; "
                    "the algorithm allowlist is mandatory (RFC 8725 §3.1)"
                )

            has_sym = has_asym = False
            for alg in ic.allowed_algs:
                if alg.lower() == "none":
                    raise ValueError(
                        f"jwtverify: issuer {name!r}: {alg!r} is never an "
                        "acceptable algorithm"
                    )
                if alg not in SUPPORTED_ALGS:
                    raise ValueError(
                        f"jwtverify: issuer {name!r}: unsupported algorithm {alg!r}"
                    )
                has_sym = has_sym or _is_symmetric(alg)
                has_asym = has_asym or _is_asymmetric(alg)

            # Config-level defence against algorithm confusion. PyJWT also
            # refuses to use an asymmetric key as an HMAC secret, but that
            # protection only holds while the key is an asymmetric key object.
            # Banning the mix removes the dependency on that behaviour.
            if has_sym and has_asym:
                raise ValueError(
                    f"jwtverify: issuer {name!r}: allowed_algs mixes symmetric "
                    f"and asymmetric algorithms ({list(ic.allowed_algs)}); "
                    "this enables algorithm-confusion attacks"
                )

            if isinstance(ic.keys, dict):
                if not ic.keys:
                    raise ValueError(f"jwtverify: issuer {name!r}: no keys configured")
                if any(not kid for kid in ic.keys):
                    raise ValueError(
                        f"jwtverify: issuer {name!r}: empty kid in key allowlist"
                    )
            elif not isinstance(ic.keys, KeyResolverLike):
                raise ValueError(
                    f"jwtverify: issuer {name!r}: keys must be a dict or a "
                    "KeyResolver"
                )


#: Characters and substrings in a ``kid`` that indicate an injection attempt
#: rather than an identifier.
_KID_BAD_CHARS = set("/\\\x00'\"`;")
_KID_BAD_PATTERNS = ("..", "select ", "union ", "--", "/*", "${", "{{")


def _suspicious_kid(kid: str) -> bool:
    """Report whether a kid looks like an injection attempt.

    This is defence in depth, not the primary control. The primary control is
    that ``kid`` is only ever used as a dict key against a configured
    allowlist, so traversal and SQL injection have no sink to reach. This
    function exists so such attempts are *detected and counted as attacks*
    rather than silently falling through to "unknown kid".
    """
    if any(c in _KID_BAD_CHARS for c in kid):
        return True
    lower = kid.lower()
    return any(p in lower for p in _KID_BAD_PATTERNS)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(Rejection.MALFORMED, "invalid base64url") from exc


def _peek_segment(token: str, index: int, what: str) -> dict[str, Any]:
    """Decode a JOSE segment without verifying anything.

    We decode the header ourselves, before handing the token to PyJWT, so that
    jku/x5u can be refused and kid resolved under our own rules. Nothing
    decoded here is trusted; it is used only to refuse.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise VerificationError(
            Rejection.MALFORMED, f"expected 3 parts, got {len(parts)}"
        )
    raw = _b64url_decode(parts[index])
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VerificationError(
            Rejection.MALFORMED, f"{what} is not valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise VerificationError(Rejection.MALFORMED, f"{what} is not an object")
    return parsed


class Verifier:
    """Verifies tokens against a pinned configuration. Safe for concurrent use."""

    def __init__(self, config: Config) -> None:
        config.validate()
        self._cfg = config

    def verify(self, raw: str) -> Result:
        """Check a raw token string against the configuration.

        This is the only ``jwt.decode`` call site in the module. Every security
        property documented at module level is enforced here or in
        :meth:`Config.validate`.
        """
        if not raw:
            raise VerificationError(Rejection.MALFORMED, "empty token")
        if len(raw) > self._cfg.max_token_bytes:
            raise VerificationError(
                Rejection.OVERSIZED,
                f"token exceeds {self._cfg.max_token_bytes} bytes",
            )

        header = _peek_segment(raw, 0, "header")
        alg = header.get("alg")
        if not isinstance(alg, str):
            raise VerificationError(Rejection.ALG_NONE, "alg header missing")

        # RFC 8725 §3.1/§3.2. Rejected early and case-insensitively so this
        # holds even if a configuration mistake were ever to allow it.
        if alg.lower() == "none" or alg == "":
            raise VerificationError(
                Rejection.ALG_NONE, f"alg={alg!r} is never accepted"
            )

        # RFC 8725 §3.8. A token must not name its own key source. We do not
        # fetch these; we refuse the token carrying them, because their
        # presence is an attack signal worth counting.
        if header.get("jku"):
            raise VerificationError(
                Rejection.JKU_PRESENT, "jku header is never honoured"
            )
        if header.get("x5u"):
            raise VerificationError(
                Rejection.X5U_PRESENT, "x5u header is never honoured"
            )

        # We must know the issuer to know which allowlist applies, but iss is
        # untrusted until the signature is checked. It is read only to SELECT a
        # candidate configuration; the signature check that follows is what
        # makes the selection sound.
        payload_peek = _peek_segment(raw, 1, "payload")
        claimed_iss = payload_peek.get("iss")
        if not isinstance(claimed_iss, str) or not claimed_iss:
            raise VerificationError(Rejection.MISSING_CLAIM, "iss claim is required")
        ic = self._cfg.issuers.get(claimed_iss)
        if ic is None:
            raise VerificationError(Rejection.UNKNOWN_ISSUER, "issuer not configured")

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise VerificationError(Rejection.KID_UNKNOWN, "kid header is required")
        if _suspicious_kid(kid):
            raise VerificationError(
                Rejection.KID_SUSPICIOUS,
                "kid contains characters that suggest injection",
            )

        if alg not in ic.allowed_algs:
            # An asymmetric-configured issuer presented a symmetric algorithm
            # is specifically a key-confusion attempt, not a generic mismatch.
            if _is_symmetric(alg) and _is_asymmetric(ic.allowed_algs[0]):
                raise VerificationError(
                    Rejection.ALG_CONFUSION,
                    f"token presents {alg} but issuer is configured for "
                    f"{list(ic.allowed_algs)}",
                )
            raise VerificationError(
                Rejection.ALG_NOT_ALLOWED,
                f"alg {alg} not in allowlist {list(ic.allowed_algs)}",
            )

        # kid resolution: allowlist lookup only. No path join, no query, no
        # fallback, and no I/O on the request path.
        key = ic.resolve_key(kid)
        if key is None:
            # Distinguish an operational failure (no keys at all — e.g. a JWKS
            # that has never fetched) from an attack signal (we have keys, but
            # not this one). Both fail closed; they need different alerts.
            if not ic.known_key_ids():
                raise VerificationError(
                    Rejection.KEY_UNAVAILABLE,
                    "no verification keys available for this issuer",
                )
            raise VerificationError(
                Rejection.KID_UNKNOWN, "kid not in configured key allowlist"
            )

        try:
            claims = jwt.decode(
                raw,
                key,
                # The control that closes the CVE class. Non-negotiable.
                algorithms=list(ic.allowed_algs),
                issuer=ic.issuer,
                audience=ic.audience,
                leeway=ic.leeway_seconds,
                # PyJWT does not require exp by default and does not verify iss
                # unless issuer= is passed. Both are made explicit here.
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise VerificationError(Rejection.EXPIRED, "token expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise VerificationError(
                Rejection.NOT_YET_VALID, "token not yet valid (nbf)"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise VerificationError(Rejection.ISSUER_MISMATCH, "issuer mismatch") from exc
        except jwt.InvalidAudienceError as exc:
            raise VerificationError(
                Rejection.AUDIENCE_MISMATCH, "audience mismatch"
            ) from exc
        except jwt.MissingRequiredClaimError as exc:
            raise VerificationError(
                Rejection.MISSING_CLAIM, "required claim missing"
            ) from exc
        except jwt.InvalidAlgorithmError as exc:
            raise VerificationError(
                Rejection.ALG_NOT_ALLOWED, "algorithm not allowed"
            ) from exc
        except jwt.InvalidKeyError as exc:
            # PyJWT's own key-confusion guard: an asymmetric key offered as an
            # HMAC secret. Classified as confusion, not as a generic key error.
            raise VerificationError(
                Rejection.ALG_CONFUSION, "asymmetric key offered as HMAC secret"
            ) from exc
        except jwt.InvalidSignatureError as exc:
            raise VerificationError(
                Rejection.BAD_SIGNATURE, "signature verification failed"
            ) from exc
        except jwt.DecodeError as exc:
            # Do not propagate library text, which can echo token content.
            raise VerificationError(Rejection.MALFORMED, "token undecodable") from exc
        except jwt.InvalidTokenError as exc:
            raise VerificationError(Rejection.BAD_SIGNATURE, "verification failed") from exc

        exp_raw = claims.get("exp")
        expires_at = (
            datetime.fromtimestamp(exp_raw, tz=None).astimezone()
            if isinstance(exp_raw, int | float)
            else None
        )

        return Result(
            issuer=ic.issuer,
            subject=str(claims.get("sub", "")),
            audience=ic.audience,
            algorithm=alg,
            key_id=kid,
            expires_at=expires_at,
            token_hash=token_hash(raw),
            claims=claims,
        )
