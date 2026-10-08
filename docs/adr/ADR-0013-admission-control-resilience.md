# ADR-0013 — S0 admission control and cascade resilience

**Status:** Accepted (Phases 9–10) · **Date:** 2026-10-08

## Context

Three threat-model commitments had machinery named but not built:

- **T4 (resource exhaustion, A6):** "per-principal escalation budgets; global
  escalation-rate circuit breaker degrading to S1+S2; cap-exceeded treated as a
  signal." Caps existed and recorded `Truncation`, but the gateway never read
  it. There was no rate limiter and no breaker.
- **T5 (model unavailability):** "circuit breaker; the failure mode is a
  configuration choice, never an accident." Nothing watched availability.
- Phase 7 left `Decision.RATE_LIMIT` in the enum with no producer.

## Decisions

### 1. Rate limiting is S0 admission control, before the cascade
A per-principal token bucket (`csf/resilience.py`) runs *before* framing and
detection — the cheapest possible gate. It is keyed on client IP, the only
principal known that early and the right granularity for an exhaustion rail.
Continuous refill, not fixed windows: fixed windows let an attacker fire
`2*limit` across a boundary instantly; a bucket bounds burst by `capacity` and
sustained rate by `rate`. The bucket table is itself capped and evicts
least-recently-seen, so the limiter cannot be turned into a memory-exhaustion
vector by cycling principals. This is the first producer of `RATE_LIMIT`.

**A 429 is an action, so shadow mode withholds it.** Shadow exists to tune
detection false positives without acting; a rate-limit drop is an action and is
recorded-not-applied there, exactly like a block. Verified end-to-end: the same
config in enforce mode returns 429, in shadow returns the would-apply record.

### 2. Cap-exceeded is a signal, fused by the decision engine
When extraction hits a cap (candidates, JSON depth, body size, unparseable
body), the gateway now contributes `StageEvidence` from a new `s0_limits` stage
to the decision engine, rather than silently truncating. An attacker who pads a
request past the candidate cap also hides payload past it; recording the cap
hit lets the engine weigh that. Scored below `tau_block` by default (FLAG),
raised to block by `cap_signal_score >= 4.0`. The default is FLAG because a
large legitimate upload also trips caps — the signal is suspicious, not proof.

### 3. The circuit breaker sheds cost, never loosens detection
The breaker watches detector unavailability (a stage raised, timed out, or
returned an `unavailable` verdict) over a rolling window. When sustained
unavailability crosses the threshold it trips, and the declared degraded
posture is **skip the learned stage** — S3 is the expensive, stall-prone one.
S1/S2 detection is unchanged; only cost is shed.

Two properties it must have, both for the same reason the decision engine's
budget never de-escalates:
- It needs `min_samples` before it can trip, so a cold start or a few errors
  cannot flip it.
- Once tripped it holds through a cooldown regardless of the instantaneous
  rate, so it does not flap.

It **never weakens a block.** An attacker who could trip it by causing errors
must not thereby disable detection — tripping only removes the learned stage,
which is additive to S1/S2, never subtractive.

## Consequences

- `csf/resilience.py` (`RateLimiter`, `TokenBucket`, `CircuitBreaker`),
  `rate_limit` and `circuit_breaker` config sections, both surfaced in
  `/statusz`; a tripped breaker surfaces in readiness.
- 32 new tests (unit + gateway integration). Rate-limit 429, cap→signal, and
  breaker-degrade verified through the containerised gateway.

## Known limitations

- **IP is a weak principal.** Behind a proxy every client shares one IP unless
  `X-Forwarded-For` is parsed, which is not done (and must not be trusted
  blindly — a forgeable header as a rate-limit key is an evasion). Per-subject
  limiting after auth is the right next step and is not built.
- **In-process buckets only.** A multi-replica deployment has per-replica
  limits, not a global one; that needs shared state (Redis) and is out of scope
  for a single-process gateway.
- **The breaker's degrade is forward-looking.** S3 is disabled by default
  (Phase 6 negative result), so today the breaker almost never has a learned
  stage to skip. It is built and tested now so the mechanism exists when S3 is.
- Cap-signal scoring is global, not per-cap; a body-size trip and a
  candidate-count trip weigh the same.
