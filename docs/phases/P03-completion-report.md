# Phase 3 — S1 Rules Engine: Completion Report

**Date:** 2026-10-01 · **Status:** COMPLETE, with one gate failed and reported.

## Implemented
- `s1-sidecar/` — Go service embedding Coraza v3.8.0 + CRS v4.21.0, serving a
  graded signal over a Unix domain socket (mode 0600).
- `backend/csf/s1_rules.py` — `S1RulesDetector` implementing the `Detector`
  protocol; degrades rather than fails when the sidecar is unreachable.
- `backend/scripts/measure_s1_curve.py` — the measurement harness.
- `docs/benchmarks/s1-baseline.json` — raw results.
- ADR-0007 — resolves the S1 question ADR-0006 left open.

## The headline result: CRS alone cannot be the detector

Threshold sweep, detection score, 40 benign / 48 attack:

| threshold | detection | FPR | missed | false+ |
|---|---|---|---|---|
| 5 | 100.0% | 12.5% | 0 | 5 |
| **8** | **97.9%** | **0.0%** | 1 | 0 |
| 15 | 93.8% | 0.0% | 3 | 0 |
| 20 | 83.3% | 0.0% | 8 | 0 |
| 30 | 54.2% | 0.0% | 22 | 0 |
| 40 | 14.6% | 0.0% | 41 | 0 |

Per-class detection scores (p50): sqli 30, xss 30, traversal 25, **cmdi 15**.
Command injection scores lowest and is the weakest class — consistent with it
being the least-covered class in the literature, and a direct target for S2.

**Derived thresholds, measured not chosen:** `tau_low = 4`, `tau_high = 8`.

## ⚠ Gate failures and limitations — reported, not hidden

**1. The corpus cannot support the FPR target.** 40 hand-built benign samples
cannot establish an FPR of 0.1%, let alone 0.01%. Zero false positives out of
40 bounds the true FPR at roughly 7% with 95% confidence — two orders of
magnitude away from the project target. **Every number above is provisional.**
Phase 4 replaces this corpus with CSIC 2010, ECML/PKDD 2007 and captured
traffic, and these thresholds must be re-derived before enforce mode.

**2. S3 escalation gate FAILED.** Target is ≤5% of benign traffic escalating.
Measured: **12.5%** (5/40). With the band `4 < score < 8`, one in eight benign
requests would reach S2/S3. On the attack side only 1 of 48 lands in the band,
so the band is doing little work for the cost. Options for Phase 5–7: rely on
S2 to resolve the band cheaply (it is ~10× cheaper than S3), or widen
`tau_low` once a realistic corpus exists. Not resolved here.

**3. Latency.** S1 is now the dominant cost, as predicted.

| | p50 | p95 | p99 |
|---|---|---|---|
| CRS engine | 1050 µs | 1608 µs | 2242 µs |
| End-to-end incl. IPC | 1451 µs | 2050 µs | 3246 µs |
| S0 (for comparison) | 104 µs | — | 120 µs |

S0 + S1 ≈ 3.4 ms p99, leaving ~6.6 ms of the 10 ms budget for S2 and S3.
Workable, but S3 at 5–20 ms p99 will not fit on every request — which is the
entire argument for the cascade, now quantified rather than asserted.

## Defects found and fixed in our own work

**1. JSON bodies were parsed as URL-encoded — a serious false-positive source.**
Every benign JSON body scored above zero. `{"comment":"Great product! 5/5
would buy again."}` matched rule 942340 (*SQL authentication bypass*) and
scored 8. The match data showed why: the entire JSON document had become a
single argument name, `ARGS_NAMES:{"comment":"Great product!...`.

Two distinct causes, both found by reading the match data rather than guessing:

- **No `Content-Length`.** Without it Coraza cannot frame the body and falls
  back to URLENCODED parsing. The gateway has already read and bounded the
  body, so the sidecar now supplies the exact length.
- **A broken regex in our own body-processor rule.**
  `^application/[a-z0-9.+-]+[+]?json` requires at least one character before
  `json`, so it never matched plain `application/json`. The vendor prefix must
  be optional: `^application/(?:[a-z0-9.-]+[+])?json`.

Effect of the fix, same corpus:

| | before | after |
|---|---|---|
| benign mean score | 3.4 | **0.6** |
| benign max score | 31 | **5** |
| FPR at threshold 8 | 15.0% | **0.0%** |
| benign escalation | 25.0% | **12.5%** |

A single configuration error was producing a 15% false-positive rate. This is
a concrete instance of the operational problem the literature describes, and
it is worth stating plainly: **most of CRS's reputation for false positives
may be configuration, not the rules.** We should not claim that in the paper
without testing it properly, but it is now a hypothesis worth testing.

**2. Blocking and detection scores were conflated.** See ADR-0007. Fixed by
reporting both plus the per-paranoia-level breakdown.

**3. Matched-rule noise.** CRS reports ~70 "matched rules" per request, almost
all bookkeeping `SecAction`s with no severity and no tags. Filtered to
actionable rules only (those with an `attack-*` tag): 8 of 73 on one probe.
Without this the audit log is unreadable.

## Verification
```
210 backend tests pass · ruff clean · mypy --strict clean
sidecar builds clean; CRS v4.21.0 (26 rule files) loads
88-sample corpus evaluated end-to-end through the real engine
```

## Known limitations
- Corpus is hand-built and too small (see gate failure 1).
- No adversarial evaluation of S1 yet (WAF-A-MoLE is Phase 8).
- Sidecar has no unit tests of its own; it is exercised through the harness.
- No rule tuning or rule subsetting yet (ModSec-AdvLearn found up to 50% of
  CRS rules discardable — a Phase 10 latency lever).
- The sidecar is not yet wired into the running gateway's detector chain; it
  is driven directly by the harness. Wiring is trivial but unverified.
- ⚠ Not container-verified; Docker daemon unavailable.

## Next
Phase 4 (data engineering): real corpora, leakage-safe splitting, a frozen
evaluation set. Then re-derive these thresholds. Nothing here should reach
enforce mode until that is done.

---

# Phase 3 addendum — S1 wired into the live gateway

**Date:** 2026-10-01

## Implemented
S1 is now in the gateway's detector chain, configured via `s1` in the config
file and built at startup in `csf/main.py`. Verified end-to-end against the
real sidecar, not a mock.

| Case | enforce | shadow |
|---|---|---|
| benign search | 200 → backend | 200 → backend |
| benign "SELECT desk lamp" | 200 → backend | 200 → backend |
| benign "O'Brien" | 200 → backend | 200 → backend |
| SQLi tautology | **403** | 200 (would-block recorded) |
| SQLi union | **403** | 200 (would-block recorded) |
| XSS script tag | **403** | 200 (would-block recorded) |
| command injection | **403** | 200 (would-block recorded) |
| path traversal | **403** | 200 (would-block recorded) |
| obfuscated SQLi | **403** | 200 (would-block recorded) |

Shadow mode recorded `shadow_would_block: 6` while forwarding everything —
the deployment discipline works as designed.

## Correctness fix: the detector protocol is now async
`Detector.evaluate` was synchronous. S1 makes a ~1.4 ms socket round trip, and
calling that synchronously inside the ASGI app would block the event loop for
its full duration, serialising every concurrent request behind it. The
protocol is now `async def`, and S1 uses `httpx.AsyncClient`. A CPU-bound
stage such as S2 may still do its work inline provided it stays short.

## Defect: `fail_open` was dead configuration
`S1Config.fail_open` existed and was never read — the detector always allowed
on failure. Config that implies a capability the code does not have is worse
than no config. Now implemented and tested both ways:

- `fail_open=True` (default): the cascade continues to S2/S3, degradation
  recorded and alertable. **Verified consequence:** with the sidecar stopped
  in enforce mode, SQLi reaches the backend. A rules outage does not become
  an application outage, and that trade is explicit.
- `fail_open=False`: blocks while S1 is unavailable. Turns a sidecar outage
  into an application outage, which is correct for high-risk routes.

A missing sidecar is also logged loudly at startup, so an operator learns
about it then rather than inferring it from a drop in block rate.

## Full-stack latency (Apple M5, single uvicorn worker, benign traffic)

| Config | conc | rps | p50 | p95 | p99 |
|---|---|---|---|---|---|
| S0 only | 1 | 470 | 2.07 ms | 2.39 ms | 2.59 ms |
| S0+S1 | 1 | 264 | 3.68 ms | 4.22 ms | **5.03 ms** |
| S0 only | 8 | 519 | 14.33 ms | 20.82 ms | 22.67 ms |
| S0+S1 | 8 | 367 | 20.93 ms | 23.53 ms | 32.52 ms |
| S0 only | 32 | 464 | 66.07 ms | 68.20 ms | 96.91 ms |
| S0+S1 | 32 | 286 | 102.85 ms | 152.59 ms | 188.36 ms |

**At concurrency 1 the budget holds: 5.03 ms p99 for the whole stack, with S1
contributing ~1.6 ms.**

## ⚠ The concurrency numbers are NOT a valid load test
Two reasons, both stated rather than buried:

1. **First attempt was invalid and discarded.** The test backend was a
   single-threaded `http.server.HTTPServer`, which serialises requests and
   became the bottleneck. The tell was that S0-only p99 (1078 ms) came out
   *worse* than S0+S1 (225 ms), which is impossible. Re-run with
   `ThreadingHTTPServer`; the numbers above are from that run and are
   internally consistent.
2. **The backend still dominates.** Measured bare: 958 rps, p50 28.13 ms at
   concurrency 32. So roughly 28 ms of the 66 ms S0-only figure is the test
   backend, not the gateway.

These are also single-worker numbers on a Python test backend over 400
requests — too short and too confounded to characterise production behaviour.
**Phase 10 needs a real harness**: a fast static backend, multiple uvicorn
workers, a proper load generator, and a sustained run. No claim about
throughput or tail latency under load should be made until then.

## Verification
```
231 tests pass (up from 210) · ruff clean · mypy --strict clean
19 new S1 detector tests: thresholds, degradation (4 failure modes),
fail-open/fail-closed, payload contract, duplicate-header preservation,
empty-band config rejection
```
