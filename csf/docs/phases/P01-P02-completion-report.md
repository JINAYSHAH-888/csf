# Phases 1 & 2 — Completion Report (Python backend)

**Date:** 2026-10-01 · **Status:** Phase 1 COMPLETE. Phase 2 (S0) COMPLETE except JWKS.

Supersedes the Go results in `P02-completion-report.md` (ADR-0006).

## Implemented

| Module | Purpose |
|---|---|
| `csf/jwtverify.py` | RFC 8725 token verification |
| `csf/normalization.py` | Bounded decoding, Unicode folding, comment views |
| `csf/extraction.py` | Candidate extraction with provenance; `model_input()` shared with training |
| `csf/framing.py` | Strict framing admission + parser blind-spot reporting |
| `csf/gateway.py` | ASGI gateway, cascade, shadow/enforce modes, audit log |
| `csf/config.py` | Strict startup validation |
| `csf/telemetry.py` | JSON logging, redaction |
| `csf/main.py` | CLI entrypoint |

## Verification — all measured, nothing assumed

```
162 tests passed
mypy --strict      : Success, 9 source files
ruff               : All checks passed
coverage           : 89% overall
                     extraction 100%, gateway 97%, normalization 97%,
                     framing 95%, jwtverify 95%, config 95%
```

**JWT attack suite: 32/32 blocked**, each with the correct classification
(Go prototype had 29). Covers alg:none ×5, RS256→HS256 confusion forged by
hand with `hmac`, HS512 variant, wrong algorithm, wrong key, stripped
signature, tampered payload, expired, missing exp, future nbf, wrong/missing
issuer, wrong/missing audience, missing sub, jku, x5u, kid traversal, kid
absolute path, kid SQLi, unknown kid, missing kid, malformed ×4, oversized.

**Framing suite: 18 smuggling primitives rejected**, plus end-to-end
verification over raw TCP against both ASGI parsers.

## Measured performance (Apple M5, Python 3.14.6)

| Operation | p50 | p99 |
|---|---|---|
| `check_framing` | 2.83 µs | 3.12 µs |
| `normalize` (benign) | 3.25 µs | 3.88 µs |
| `normalize` (encoded attack) | 7.79 µs | 10.33 µs |
| `extract` (JSON request) | 31.79 µs | 42.12 µs |
| JWT verify RS256 | 63.42 µs | 77.04 µs |
| **S0 total, framing + extraction** | **35.04 µs** | **45.12 µs** |
| **S0 total incl. JWT verify** | **103.58 µs** | **120.46 µs** |

**S0 consumes ~0.12 ms of the 10 ms p99 budget — about 1.2%.** The ADR-0006
concern that Python would struggle on latency does not hold for S0. Go
measured 43 µs for the same JWT verification (~1.5× faster), which is
immaterial at this scale. The budget will be dominated by S1 (CRS, 0.5–10 ms),
exactly as predicted — which is why the S1 integration choice, not the host
language, is the latency decision that matters.

⚠ These are single-threaded component measurements, **not** end-to-end
latency under concurrent load. Phase 10 measures that.

## Security findings from this phase

### 1. PyJWT does not require `exp` and does not verify `iss` by default
Measured, not assumed. A naive `jwt.decode(tok, key, algorithms=[...])`
accepts a token with no expiry and an unverified issuer. We pass `issuer=`,
`audience=` and `options={"require": ["exp","iss","aud","sub"]}` explicitly.
An AST test fails the build if any of those keyword arguments disappears.

### 2. PyJWT blocks RS256→HS256 better than golang-jwt does
PyJWT raises `InvalidKeyError` when an asymmetric key is offered as an HMAC
secret, so the attack fails **even when** the verifier is misconfigured to
allow both families. That is real defence in depth. We still ban mixing
families in `Config.validate`, because the protection only holds while the key
is an asymmetric key object — an issuer configured with a raw string secret
would not be covered.

### 3. ⚠ ASGI parser choice changes the security posture — measured
Raw TCP against uvicorn 0.54.0:

| Request | httptools (default) | h11 (fallback) |
|---|---|---|
| Content-Length + Transfer-Encoding | 400 | **200 OK** |
| Duplicate Content-Length | 400 | 400 |
| Space before colon | 400 | 400 |
| Obsolete line folding | 400 | **200 OK** |
| Unsupported Transfer-Encoding | 400 | 400 |

`uvicorn[standard]` installs httptools; plain `uvicorn` silently gets the
permissive h11. **Our application-level check is therefore not redundant** —
it is the only protection for CL+TE under h11, and end-to-end testing confirms
CL+TE is now rejected under both parsers.

**Residual, stated plainly:** obs-fold under h11 still returns 200. h11 folds
the continuation into a single value before the ASGI scope exists, so the
evidence is destroyed and our check cannot see it. Mitigation is a startup
guard (`framing.parser_warnings()`) that logs a warning naming the blind spot,
plus a test asserting httptools is the installed parser. httptools is the
supported configuration.

### 4. Go's `net/http` destroyed CL+TE evidence; ASGI does not
The Go prototype needed a custom `net.Listener` connection sniffer because
`net/http` strips `Content-Length` on a CL+TE request before any handler runs
(measured: `Header["Content-Length"] == []`, response 200). ASGI's
`scope["headers"]` preserves duplicates, so the Python check is both simpler
and more direct. This was the deciding technical point in ADR-0006.

## Defects found and fixed in our own work

1. **Redaction missed hyphenated names.** `X-Api-Key` lowercases to
   `x-api-key`, matching neither `api_key` nor `apikey` — an API key header
   would have been logged in cleartext. Fixed by stripping `-_. ` before
   comparison. Caught by a test, not by review.
2. **Framing test validated an unreachable path (Go).** The handler-level
   CL+TE check passed only because the test constructed the request
   synthetically with both fields set, which no real client can send. False
   assurance. The lesson carried into Python: every framing control is now
   tested over raw TCP through the real server.
3. **Name shadowing in the gateway** — the auth failure tuple reused the name
   `verdict`, caught by mypy strict. Replaced with a plain `str | None`.
4. **Test harness passed `mode` twice** to `GatewayOptions`.

## Known limitations

- **JWKS is not implemented.** Keys are static config. No rotation, no
  caching, no fail-closed-on-JWKS-unavailable. This is the main Phase 2 gap.
- **S1, S2, S3 do not exist.** `detectors=()`. In enforce mode the gateway
  logs a warning saying only S0 is enforced.
- **No rate limiting**, no `jti` replay handling, no TLS termination
  (deployment concern, Phase 12).
- **No multipart parsing** — `multipart/form-data` bodies fall through to the
  opaque `$body` candidate.
- ⚠ **Not container-verified.** Docker daemon unavailable on the dev host.
- `csf/main.py` has 0% test coverage (entrypoint wiring only).

## Next
Phase 3: S1 integration. Measure all three options from ADR-0006
(pymodsecurity in-process / Coraza sidecar / nginx front tier) and produce the
baseline detection-vs-FPR curve on our own traffic. That curve is the
measurement everything downstream depends on.

---

# Phase 2 addendum — JWKS (gap now closed)

**Date:** 2026-10-01 · **Status:** COMPLETE

## Implemented
`csf/jwks.py` (resolver, cache, rotation) and `csf/bootstrap.py` (startup
wiring). `IssuerConfig.keys` now accepts either a static dict or a
`KeyResolver`, so JWKS and pinned keys are interchangeable and every existing
S0 guarantee applies unchanged to both.

- Pre-configured endpoint only; `jku`/`x5u` still rejected before this module
  is reached.
- **Plaintext `http://` JWKS refused for non-loopback hosts.** A JWKS fetched
  over http can be substituted by anyone on the path — a complete
  authentication bypass. Loopback is allowed for local development.
- TLS verification always on, not configurable.
- Keys skipped (not fatal) when: no `kid`, unsupported `kty`, `use != "sig"`,
  or `alg` outside the issuer's allowlist. A provider publishing an exotic or
  symmetric key cannot introduce it into an RSA-only issuer.
- Bounds: response size, key count, request timeout.
- `KEY_UNAVAILABLE` distinguished from `KID_UNKNOWN` — operational failure vs
  attack signal. They need different alerts.
- `/readyz` returns 503 when auth is enabled and no key is available;
  `/healthz` deliberately does **not** depend on JWKS, since restarting a pod
  cannot fix a remote outage and a failing liveness probe would just cause a
  restart loop.
- Startup is fail-closed: an unreachable JWKS **refuses to start**. An
  instance that starts but rejects every authenticated request looks healthy
  to an orchestrator and quietly takes traffic.
- A failed refresh **retains the previous snapshot**, so a transient outage
  does not disarm the gateway, and an attacker who can break the JWKS endpoint
  cannot cause an outage of all authenticated traffic.

## The amplification guard
The naive implementation — "unknown kid, so refetch" — hands an attacker an
outbound amplification primitive against the identity provider. Mitigated by
`min_refresh_interval_seconds` (default 30 s) plus a negative cache of absent
`kid` values.

**Measured end-to-end:** 200 requests bearing distinct random `kid` values,
with the interval lowered to 0.5 s for the test, produced **15** outbound
fetches over ~7.5 s — i.e. one per interval, independent of request volume.
At the 30 s default the same flood produces ~1. Unit test
`test_unknown_kid_flood_makes_at_most_one_outbound_request` asserts zero
additional fetches inside the window.

## ⚠ Revocation latency — operational property, stated explicitly
**A key removed from the JWKS keeps verifying for up to `ttl_seconds`
(default 600 s).** Found in the end-to-end run: after retiring `k1`, tokens
signed with it continued to verify, because nothing forces a refresh while
tokens still validate against the cached snapshot.

This is inherent to TTL caching and is fine for normal rotation (providers
publish the new key before retiring the old). It is **not** fine for emergency
revocation of a compromised key. Options: lower `ttl_seconds`, or remove the
issuer and restart. There is no push/invalidate mechanism. Pinned by
`test_retired_key_keeps_verifying_until_ttl_expires` and documented at the top
of `csf/jwks.py`.

## Verification
```
209 tests passed (up from 162) · ruff clean · mypy --strict clean
coverage 89%  (jwks 95%, bootstrap 84%)
```
32 JWKS tests covering rotation, overlap windows, retirement, rate limiting,
negative caching, malformed/oversized/too-many-keys documents, network
failure, EC keys, and a re-run of five core attack cases against a
JWKS-backed verifier to confirm the new key source is not a bypass.

End-to-end against a live JWKS server: startup fetch, valid token 200,
missing token 401, unpublished key 401, rotation picked up, overlap window
honoured, public route unaffected, `/readyz` 200.

## Remaining S0 gaps
- No `jti` replay handling.
- No rate limiting (per-principal or global).
- No multipart parsing.
- No TLS termination at the gateway (Phase 12 deployment concern).
- ⚠ Not container-verified; Docker daemon unavailable.
