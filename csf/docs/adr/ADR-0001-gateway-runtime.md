# ADR-0001 — Custom Go reverse proxy with in-process Coraza, not Envoy ext_proc

> **SUPERSEDED by ADR-0006 (2026-10-01).** The project backend is Python. The
> reasoning below about ext_proc and measurement-before-commitment still
> stands; the language choice does not.

**Status:** Accepted (Phase 0) · **Date:** 2026-10-01

## Context
CSF must run inline. S1 (Coraza+CRS) and S2 (grammar parsing) run on every escalated request; S3 runs on a small fraction. The dominant design constraint is p99 added latency ≤10 ms.

## Problem
Where does the detection logic execute — inside a proxy we write, or as an external processor attached to an existing proxy?

## Options considered
1. **Custom Go reverse proxy, Coraza embedded in-process.**
2. **Envoy + `ext_proc` gRPC external processor.**
3. **NGINX + Lua/njs.**
4. **Python proxy (FastAPI/httpx).**

## Decision
Option 1 for Phases 1–7. Option 2 retained as a Phase 10 benchmark comparison and a Phase 12 deployment option.

## Why
- Coraza v3.8.0 is a Go library (Apache-2.0) and embeds directly — no serialization, no IPC, no second process in the fast path.
- `ext_proc` is explicitly documented as out-of-process and therefore adds latency. Accepting that cost *before measuring whether we can afford it* would invert the project's central discipline.
- Option 3 splits the system across two languages and makes in-process Coraza awkward.
- Option 4 is rejected on tail latency and concurrency.

## Security impact
**Positive:** removes an IPC trust boundary; S1/S2 operate on exactly the bytes the proxy parsed, eliminating one parser-differential surface.
**Negative, and significant:** we now own the HTTP parser. Request smuggling, ambiguous framing, and parser differentials against the backend become *our* defects. This is accepted deliberately and discharged by mandatory differential fuzzing in Phase 11 — it is not a residual we can wave at.

## Performance impact
No IPC hop for the stages that run most often. S3 remains the only network hop and is reached by design on a small traffic fraction.

## Operational impact
Single binary for the gateway; separate model service. Two toolchains (Go, Python), two CI lanes.

## Reversal strategy
Detection stages are written behind interfaces (`Stage` with `Evaluate(ctx, *Request) (Verdict, error)`) and must not depend on the proxy type. Porting to an `ext_proc` server means writing a new transport adapter, not rewriting detection. Phase 10 benchmarks decide whether to exercise this.

## Sources
- Coraza v3.8.0, Apache-2.0, 2026-09-30 — pkg.go.dev/github.com/corazawaf/coraza/v3
- Envoy ext_proc documentation (out-of-process, adds latency) — envoyproxy.io
- open-appsec integration patterns (NGINX/Envoy/Kong/APISIX)
