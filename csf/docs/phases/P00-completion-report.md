# Phase 0 — Completion Report

**Date:** 2026-10-01 · **Status:** COMPLETE

## Implemented
- Monorepo skeleton (`gateway/`, `model/`, `docs/`, `deployment/`, `tests/`, …).
- `docs/research/phase-P00-research.md` — verified versions, literature, production systems, phase decision.
- `docs/security/threat-model.md` — trust boundaries, 6 adversary classes, T1–T8, explicit out-of-scope.
- `docs/architecture/system-overview.md`
- `docs/third-party.md` — license register.
- ADR-0001 (Go proxy + in-process Coraza), ADR-0002 (JWT), ADR-0003 (S2 licensing), ADR-0004 (CRS graded signal), ADR-0005 (quantization).

## Verified facts (not assumed)
| Fact | How verified |
|---|---|
| Go 1.27.1 darwin/arm64 | `go version` after install |
| Coraza v3.8.0, Apache-2.0, 2026-09-30 | current package index |
| golang-jwt/jwt **v5.3.1** resolved | `go.mod` after `go get` |
| keyfunc **v3.8.2**, jwkset v0.11.3 | `go.mod` |
| vitess sqlparser Apache-2.0 | package index |
| SafeLine engine **GPL-3.0** | repository license → ADR-0003 reference-only constraint |
| Docker 29.5.3 installed, **daemon not running** | `docker info` failed |

## New finding
Q1-2026 JWT algorithm-confusion CVE cluster — **CVE-2026-22817** (Hono, fixed 4.11.4 by requiring explicit `alg`), CVE-2026-27804, CVE-2026-23552. Same root cause as alg:none/RS→HS. Makes the Phase 2 suite a test of a live vulnerability class. Translated into a binding implementation rule and an enforcing test.

## Known limitations
- ⚠ Docker daemon down: **no container has been built or run.** Nothing is container-verified.
- ⚠ Whether golang-jwt/jwt v5 is itself affected by the CVE cluster was not established. We rely on the allowlist, not on library defaults.
- ⚠ SafeLine/ModSecurity FPR figures are practitioner benchmarks, not peer-reviewed. To be reproduced in Phase 3.

## Next
Phase 1 (foundation) and Phase 2 (S0 + JWT) — started in this session.
