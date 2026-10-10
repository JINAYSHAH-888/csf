# Phases 9–10 — Hardening & Resilience — Completion Report

**Date:** 2026-10-08 · **Deliverable:** `csf/resilience.py` + gateway wiring ·
**ADR:** ADR-0013 · **Threats:** T4 (resource exhaustion), T5 (unavailability)

Two phases delivered together: both are about *cost* rather than detection, and
both wire into the same S0/decision path, so splitting them would have meant
touching the request path twice.

## What was missing

The threat model named three mechanisms that did not exist in code:
1. cap-exceeded "treated as a signal" — caps recorded `Truncation`, the gateway
   never read it;
2. a per-principal rate limit — none; `Decision.RATE_LIMIT` had no producer;
3. a circuit breaker degrading to S1+S2 — nothing watched availability.

All three now exist, are configured, observable, and tested.

## Delivered

| mechanism | what it does | gate it answers |
|---|---|---|
| **Rate limiter** | per-IP token bucket before the cascade; bounded, evicting table | T4/A6: bounds work one principal can force |
| **Cap signal** | extraction cap-hit → `s0_limits` evidence to the decision engine | T4: cap-exceeded is a signal, not silent truncation |
| **Circuit breaker** | trips on sustained detector unavailability; skips the learned stage | T5: degraded mode is a declared, observed choice |

## Verification

- **564 tests** across the project (20 added here: 12 resilience unit, 5 gateway integration, 3 config); `ruff` and
  `mypy --strict` clean.
- Rate limiting verified end-to-end in the containerised gateway: burst=3,
  rate=2/s, six rapid requests → 3 pass-through then **3× 429** in enforce
  mode; the same config in shadow records `limited:3` but applies nothing.
- Breaker verified: a model stage that always errors trips the breaker after
  `min_samples`, after which the model stage stops being called and readiness
  reports the degraded posture.
- Cap signal verified: a request over `max_candidates` blocks when
  `cap_signal_score>=4.0`, flags (and forwards) at the default 2.0.

## Design decisions worth their own line (full reasoning in ADR-0013)

- **A 429 is withheld in shadow mode** — it is an action, and shadow tunes
  detection without acting.
- **The breaker never weakens a block** — it only removes the additive learned
  stage; an attacker who trips it by causing errors cannot thereby disable
  detection. Same principle as the decision engine's budget (ADR-0011).
- **Cap-hit defaults to FLAG, not BLOCK** — a large legitimate upload also trips
  caps; the signal is suspicious, not proof.

## Honestly carried forward

- IP is a weak principal behind a proxy; per-subject limiting and safe
  `X-Forwarded-For` handling are not built (a forgeable header as a limit key
  would be an evasion).
- In-process buckets give per-replica limits, not a global one — needs shared
  state for a multi-replica deployment.
- The breaker's degrade target (S3) is disabled by default (Phase 6), so the
  mechanism is built and tested ahead of the stage it protects.
