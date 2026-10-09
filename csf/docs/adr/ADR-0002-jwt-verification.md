# ADR-0002 — JWT verification: algorithm is configuration, never input

**Status:** Accepted (Phase 0) · **Date:** 2026-10-01

## Context
S0 verifies JWTs before any detection stage runs. An attacker with a forged admin token does not need an injection payload, so this stage's correctness dominates everything downstream.

## Problem
JWT's `alg` header is attacker-controlled. Libraries that select the verification algorithm from it are trivially bypassable.

## Evidence this is live, not historical
Q1 2026 produced a cluster of algorithm-confusion CVEs: **CVE-2026-22817** (Hono JWT middleware auth bypass, fixed in 4.11.4 by *requiring an explicit `alg` option*), **CVE-2026-27804**, **CVE-2026-23552**. Same root cause each time. RFC 8725 (JWT Best Current Practices) exists precisely because RFC 7519/7518 permit these configurations.

## Options considered
1. `golang-jwt/jwt/v5` with mandatory `WithValidMethods` allowlist.
2. `go-jose`.
3. Hand-rolled verification.

## Decision
Option 1. Every parse path passes `jwt.WithValidMethods(cfg.AllowedAlgs)`, `jwt.WithExpirationRequired()`, `jwt.WithIssuer(...)`, `jwt.WithAudience(...)`. JWKS via `MicahParks/keyfunc` v3 against a **pre-configured** endpoint.

Hard rules, enforced by test:
- Allowed algorithms come from configuration, per issuer. Never from the token.
- `jku` and `x5u` headers are **ignored entirely** — never fetched.
- `kid` is an opaque key for an allowlist lookup. **No filesystem path interpolation. No SQL interpolation.**
- `exp`, `nbf`, `iss`, `aud` all mandatory.
- Raw JWTs are never logged; token hash only.
- A unit test fails the build if any parse call omits the allowlist.

## Why not option 3
Hand-rolling signature verification for a security gateway is how this CVE class is created. No.

## Security impact
Closes T2 entirely for the enumerated vectors. Gate: **100%** of the JWT attack suite blocked — these are known, enumerated, deterministically testable failures, so partial credit would be meaningless.

## Performance impact
~50–200 µs per ECDSA/RSA verification, amortised by a short-TTL cache keyed on token hash. Verifying first strictly reduces total work: an invalid token short-circuits before S1/S2/S3.

## Operational impact
JWKS fetch needs caching, rotation handling, and a failure policy (fail-closed on JWKS unavailability for authenticated routes).

## Reversal strategy
Verification sits behind a `TokenVerifier` interface; swapping libraries is a single implementation.

## Sources
- RFC 8725 — JSON Web Token Best Current Practices
- RFC 7519 / RFC 7518
- CVE-2026-22817 (NVD), CVE-2026-27804, CVE-2026-23552
- golang-jwt/jwt/v5 docs — `WithValidMethods` documented as the algorithm-confusion mitigation
- JUTIF 7(2) 2026, JWKS penetration-testing methodology — adopted as our test-suite spec
