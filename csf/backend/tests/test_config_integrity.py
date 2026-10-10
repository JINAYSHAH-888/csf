"""Config integrity: fingerprint, signature gating, safe-fail (Phase 13, T7)."""

from __future__ import annotations

import json

import pytest

from csf.config_integrity import (
    HMAC_ENV,
    ConfigIntegrityError,
    fingerprint,
    load_trusted,
    sign,
)

GOOD = {"upstream": "http://localhost:3000", "mode": "shadow"}
KEY = "00112233445566778899aabbccddeeff"


def _write(tmp_path, obj):
    p = tmp_path / "gw.json"
    p.write_text(json.dumps(obj))
    return p


def test_fingerprint_is_stable_and_content_addressed():
    assert fingerprint(b"abc") == fingerprint(b"abc")
    assert fingerprint(b"abc") != fingerprint(b"abd")


def test_loads_unsigned_when_no_key(tmp_path, monkeypatch):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    p = _write(tmp_path, GOOD)
    data, audit = load_trusted(p)
    assert json.loads(data)["upstream"] == "http://localhost:3000"
    assert audit.sha256 == fingerprint(p.read_bytes())
    assert audit.signed is False


def test_corrupt_json_is_rejected_not_parsed(tmp_path, monkeypatch):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    p = tmp_path / "gw.json"
    p.write_text("{not valid json")
    with pytest.raises(ConfigIntegrityError, match="not valid JSON"):
        load_trusted(p)


def test_missing_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    with pytest.raises(ConfigIntegrityError, match="cannot read"):
        load_trusted(tmp_path / "nope.json")


def test_signature_required_when_key_set_but_missing(tmp_path, monkeypatch):
    monkeypatch.setenv(HMAC_ENV, KEY)
    p = _write(tmp_path, GOOD)
    with pytest.raises(ConfigIntegrityError, match="must be signed"):
        load_trusted(p)


def test_valid_signature_accepts(tmp_path, monkeypatch):
    monkeypatch.setenv(HMAC_ENV, KEY)
    p = _write(tmp_path, GOOD)
    sign(p, KEY)
    data, audit = load_trusted(p)
    assert audit.signed is True
    assert json.loads(data)["upstream"] == "http://localhost:3000"


def test_tampered_body_fails_signature(tmp_path, monkeypatch):
    monkeypatch.setenv(HMAC_ENV, KEY)
    p = _write(tmp_path, GOOD)
    sign(p, KEY)
    # An attacker flips enforcement on after signing.
    p.write_text(json.dumps({**GOOD, "mode": "enforce"}))
    with pytest.raises(ConfigIntegrityError, match="does not match"):
        load_trusted(p)


def test_wrong_key_fails_signature(tmp_path, monkeypatch):
    p = _write(tmp_path, GOOD)
    sign(p, KEY)
    monkeypatch.setenv(HMAC_ENV, "ffeeddccbbaa99887766554433221100")
    with pytest.raises(ConfigIntegrityError, match="does not match"):
        load_trusted(p)


def test_non_hex_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv(HMAC_ENV, "not-hex")
    p = _write(tmp_path, GOOD)
    with pytest.raises(ConfigIntegrityError, match="hex"):
        load_trusted(p)


def test_audit_records_actor_and_size(tmp_path, monkeypatch):
    monkeypatch.delenv(HMAC_ENV, raising=False)
    p = _write(tmp_path, GOOD)
    _, audit = load_trusted(p)
    assert audit.size_bytes == len(p.read_bytes())
    assert audit.actor  # some non-empty attribution
    assert audit.as_fields()["config_sha256"] == audit.sha256


# -- Ed25519 asymmetric signing (preferred production scheme) --------------

def _ed25519_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def test_ed25519_valid_signature_accepts(tmp_path, monkeypatch):
    from csf.config_integrity import sign_ed25519
    monkeypatch.delenv(HMAC_ENV, raising=False)
    priv_pem, pub_pem = _ed25519_keypair()
    cfg = _write(tmp_path, GOOD)
    (tmp_path / "pub.pem").write_bytes(pub_pem)
    sign_ed25519(cfg, priv_pem)
    monkeypatch.setenv("CSF_CONFIG_PUBKEY", str(tmp_path / "pub.pem"))
    data, audit = load_trusted(cfg)
    assert audit.signed is True and audit.scheme == "ed25519"


def test_ed25519_tampered_body_fails(tmp_path, monkeypatch):
    from csf.config_integrity import sign_ed25519
    priv_pem, pub_pem = _ed25519_keypair()
    cfg = _write(tmp_path, GOOD)
    (tmp_path / "pub.pem").write_bytes(pub_pem)
    sign_ed25519(cfg, priv_pem)
    cfg.write_text(json.dumps({**GOOD, "mode": "enforce"}))  # tamper after signing
    monkeypatch.setenv("CSF_CONFIG_PUBKEY", str(tmp_path / "pub.pem"))
    with pytest.raises(ConfigIntegrityError, match="does not verify"):
        load_trusted(cfg)


def test_ed25519_wrong_key_fails(tmp_path, monkeypatch):
    from csf.config_integrity import sign_ed25519
    priv_pem, _ = _ed25519_keypair()
    _, other_pub = _ed25519_keypair()        # a DIFFERENT keypair's public key
    cfg = _write(tmp_path, GOOD)
    (tmp_path / "pub.pem").write_bytes(other_pub)
    sign_ed25519(cfg, priv_pem)
    monkeypatch.setenv("CSF_CONFIG_PUBKEY", str(tmp_path / "pub.pem"))
    with pytest.raises(ConfigIntegrityError, match="does not verify"):
        load_trusted(cfg)


def test_ed25519_missing_signature_fails(tmp_path, monkeypatch):
    _, pub_pem = _ed25519_keypair()
    cfg = _write(tmp_path, GOOD)
    (tmp_path / "pub.pem").write_bytes(pub_pem)
    monkeypatch.setenv("CSF_CONFIG_PUBKEY", str(tmp_path / "pub.pem"))
    with pytest.raises(ConfigIntegrityError, match="must be signed"):
        load_trusted(cfg)


def test_ed25519_preferred_over_hmac(tmp_path, monkeypatch):
    """When both are configured, the asymmetric scheme is used."""
    from csf.config_integrity import sign_ed25519
    priv_pem, pub_pem = _ed25519_keypair()
    cfg = _write(tmp_path, GOOD)
    (tmp_path / "pub.pem").write_bytes(pub_pem)
    sign_ed25519(cfg, priv_pem)
    monkeypatch.setenv("CSF_CONFIG_PUBKEY", str(tmp_path / "pub.pem"))
    monkeypatch.setenv(HMAC_ENV, KEY)
    _, audit = load_trusted(cfg)
    assert audit.scheme == "ed25519"


def test_verification_needs_only_the_public_key(tmp_path, monkeypatch):
    """The private key must never be required to VERIFY — that is the point of
    asymmetric signing. We verify with only the public key present on disk."""
    from csf.config_integrity import sign_ed25519
    priv_pem, pub_pem = _ed25519_keypair()
    cfg = _write(tmp_path, GOOD)
    sign_ed25519(cfg, priv_pem)
    del priv_pem  # the server never has it
    (tmp_path / "pub.pem").write_bytes(pub_pem)
    monkeypatch.setenv("CSF_CONFIG_PUBKEY", str(tmp_path / "pub.pem"))
    _, audit = load_trusted(cfg)
    assert audit.signed
