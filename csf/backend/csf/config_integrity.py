"""Config integrity: fingerprint, optional signature, audit record (T7).

T7 (policy/configuration tampering) asks for: every config change audited with
actor and diff; signed/validated config; safe-fail on corruption; a rollback
path. This module is the integrity layer wrapped around `config.load`.

The threat is concrete. CSF's config sets the enforcement mode, the thresholds,
the upstream, and the auth issuers. An attacker who can rewrite it on disk can
turn enforcement off or point auth at their own JWKS without touching a line of
code. So loading config is not just parsing: it is a trust decision that must
be recorded, and — when the operator provides a key — cryptographically gated.

Design choices
--------------
* **Fingerprint always.** Every load records the SHA-256 of the exact bytes
  read. Two loads with the same hash loaded the same policy; a changed hash in
  the audit log is the "diff" T7 asks for, at the granularity that matters
  (did the policy change at all?).
* **Signature when a key is configured, not before.** Requiring a signature on
  the config is the real tamper control, but it is opt-in: a dev running
  locally has no key and should not be forced to sign a file. When a key is
  configured a valid signature becomes mandatory and a missing or wrong one is
  a startup failure — opt-in that becomes mandatory the moment a key exists is
  the only honest default, because a signature the system will run without is
  theatre.

  Two schemes, in order of preference:
    - **Ed25519 (asymmetric), preferred.** ``CSF_CONFIG_PUBKEY`` points at a
      public-key PEM. The config is signed OFFLINE with the private key, which
      never touches the server; the running gateway holds only the public key
      and can verify but not forge. This is what you want in production: an
      attacker who reads the gateway's filesystem learns nothing that lets them
      re-sign a tampered config.
    - **HMAC-SHA256 (symmetric), fallback.** ``CSF_CONFIG_HMAC_KEY`` (hex). The
      same secret verifies and signs, so anyone who can verify can also forge;
      it defends against a party WITHOUT the key, not against one who holds it.
      Kept for simple/local setups. If both are set, Ed25519 wins.
* **Safe-fail.** Any problem — unreadable file, bad JSON, failed validation,
  bad signature — raises and the caller refuses to start. A gateway that falls
  back to a default policy when its config is corrupt is a gateway an attacker
  disables by corrupting the config.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ConfigAudit", "ConfigIntegrityError", "fingerprint",
           "load_trusted", "sign", "sign_ed25519"]

HMAC_ENV = "CSF_CONFIG_HMAC_KEY"
PUBKEY_ENV = "CSF_CONFIG_PUBKEY"


class ConfigIntegrityError(Exception):
    """Raised on any integrity failure. Loading must stop, never degrade."""


@dataclass(frozen=True, slots=True)
class ConfigAudit:
    """What was loaded, by whom, and whether it was signed. Goes to the log at
    startup so a later question — "when did the policy change and to what" — is
    answerable from history rather than guesswork."""

    path: str
    sha256: str
    signed: bool
    actor: str
    size_bytes: int
    scheme: str = "none"

    def as_fields(self) -> dict[str, object]:
        return {"config_path": self.path, "config_sha256": self.sha256,
                "config_signed": self.signed, "config_scheme": self.scheme,
                "config_actor": self.actor, "config_bytes": self.size_bytes}


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _actor(path: Path) -> str:
    """Best-effort identity of who owns the config file. Not an authz control —
    an attribution hint for the audit record."""
    try:
        import pwd  # POSIX only

        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (ImportError, KeyError, OSError):
        return f"uid:{path.stat().st_uid}" if path.exists() else "unknown"


def _verify_ed25519(data: bytes, sig_path: Path, pubkey_pem: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    if not sig_path.exists():
        raise ConfigIntegrityError(
            f"{PUBKEY_ENV} is set, so config must be signed, but no signature "
            f"file was found at {sig_path}")
    try:
        key = load_pem_public_key(pubkey_pem)
    except Exception as exc:  # noqa: BLE001 - any key-load failure is fatal
        raise ConfigIntegrityError(
            f"{PUBKEY_ENV} is not a valid public key: {exc}") from exc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigIntegrityError(
            f"{PUBKEY_ENV} must be an Ed25519 public key, got {type(key).__name__}")
    try:
        signature = base64.b64decode(sig_path.read_text().strip())
    except Exception as exc:  # noqa: BLE001
        raise ConfigIntegrityError(
            f"config signature at {sig_path} is not valid base64: {exc}") from exc
    try:
        key.verify(signature, data)
    except InvalidSignature as exc:
        raise ConfigIntegrityError(
            f"config signature at {sig_path} does not verify against the "
            "configured public key; refusing to load a config that is not the "
            "one that was signed") from exc


def _verify_signature(data: bytes, sig_path: Path, key: bytes) -> None:
    if not sig_path.exists():
        raise ConfigIntegrityError(
            f"{HMAC_ENV} is set, so config must be signed, but no signature "
            f"file was found at {sig_path}")
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    provided = sig_path.read_text().strip()
    # Constant-time compare: a signature check that leaks timing is a signature
    # check an attacker can forge byte by byte.
    if not hmac.compare_digest(expected, provided):
        raise ConfigIntegrityError(
            f"config signature at {sig_path} does not match; refusing to load "
            "a config that is not the one that was signed")


def load_trusted(path: str | Path) -> tuple[bytes, ConfigAudit]:
    """Read config bytes with integrity checks. Returns (raw_bytes, audit).

    The caller parses the bytes (``config.load`` does that and validates). This
    function owns only the trust decision: can these bytes be trusted enough to
    become policy? It raises ConfigIntegrityError on any doubt.
    """
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ConfigIntegrityError(f"cannot read config {p}: {exc}") from exc

    # Fail on empty/corrupt JSON here with a clear message, rather than letting
    # a downstream parser emit something opaque.
    try:
        json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigIntegrityError(f"config {p} is not valid JSON: {exc}") from exc

    sig_path = p.with_suffix(p.suffix + ".sig")
    pubkey_path = os.environ.get(PUBKEY_ENV, "").strip()
    key_hex = os.environ.get(HMAC_ENV, "").strip()
    signed = False
    if pubkey_path:
        # Asymmetric wins when both are configured.
        try:
            pubkey_pem = Path(pubkey_path).read_bytes()
        except OSError as exc:
            raise ConfigIntegrityError(
                f"cannot read {PUBKEY_ENV} at {pubkey_path}: {exc}") from exc
        _verify_ed25519(data, sig_path, pubkey_pem)
        signed = True
    elif key_hex:
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise ConfigIntegrityError(
                f"{HMAC_ENV} must be hex-encoded: {exc}") from exc
        _verify_signature(data, sig_path, key)
        signed = True

    scheme = "ed25519" if pubkey_path else ("hmac" if key_hex else "none")
    audit = ConfigAudit(path=str(p), sha256=fingerprint(data), signed=signed,
                        actor=_actor(p), size_bytes=len(data), scheme=scheme)
    return data, audit


def sign(path: str | Path, key_hex: str) -> str:
    """Write an HMAC .sig for `path` and return it. Operator tooling; kept here
    so signing and verifying share one definition and cannot drift."""
    p = Path(path)
    data = p.read_bytes()
    sig = hmac.new(bytes.fromhex(key_hex), data, hashlib.sha256).hexdigest()
    p.with_suffix(p.suffix + ".sig").write_text(sig + "\n")
    return sig


def sign_ed25519(path: str | Path, private_key_pem: bytes) -> str:
    """Write a base64 Ed25519 .sig for `path`. Operator tooling, run OFFLINE
    with the private key; the server never holds it. Shares the signing
    definition with _verify_ed25519 so the two cannot drift."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )
    p = Path(path)
    data = p.read_bytes()
    key = load_pem_private_key(private_key_pem, password=None)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigIntegrityError("private key is not Ed25519")
    sig = base64.b64encode(key.sign(data)).decode()
    p.with_suffix(p.suffix + ".sig").write_text(sig + "\n")
    return sig
