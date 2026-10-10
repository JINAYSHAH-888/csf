"""S0 admission control and cascade resilience (threat model T4, T5).

Two mechanisms live here, both about *cost* rather than detection:

* **Rate limiting** — a per-principal token bucket at the front of the request
  path. It is the cheapest possible gate (no parsing, no detectors), so it runs
  before the cascade and is the first producer of the ``RATE_LIMIT`` decision
  that has sat unused in the enum since Phase 7. A6, resource-exhaustion, is
  the adversary; the bucket bounds how much work one principal can force.

* **Circuit breaker** — watches detector unavailability over a rolling window.
  When a stage starts failing or timing out for a sustained fraction of
  requests (S3 inference stalls, the S1 sidecar going away), the breaker trips
  and the gateway degrades to a declared posture rather than paying the failing
  stage's cost on every request. T5 insists the degraded mode is a *choice*,
  observable and configured, never an accident.

Neither mechanism decides whether a request is an attack. They decide whether
the system can afford to keep answering the question, which is a different and
orthogonal control from the S1/S2/S3 cascade.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "BreakerState",
    "CircuitBreaker",
    "RateLimitConfig",
    "RateLimiter",
    "TokenBucket",
]


@dataclass(slots=True)
class TokenBucket:
    """A single principal's bucket. Refills continuously at `rate` per second
    up to `capacity`; each request costs one token.

    Continuous refill (not fixed windows) because fixed windows let an attacker
    fire `2*limit` requests across a window boundary in an instant. A bucket
    smooths that: burst is bounded by `capacity`, sustained rate by `rate`.
    """

    capacity: float
    rate: float
    tokens: float = 0.0
    last: float = 0.0

    def take(self, now: float) -> bool:
        if self.last == 0.0:
            # First sight of this principal: start full, minus this request.
            self.tokens = self.capacity
            self.last = now
        else:
            elapsed = max(0.0, now - self.last)
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Token-bucket parameters.

    Defaults are deliberately generous — this is a safety rail against
    exhaustion, not a business quota. An operator tightens it to their traffic.
    """

    enabled: bool = False
    #: Sustained requests per second per principal.
    rate_per_second: float = 50.0
    #: Burst allowance; the bucket's depth.
    burst: float = 100.0
    #: Cap on the number of per-principal buckets kept, so the limiter itself
    #: cannot be turned into a memory-exhaustion vector by an attacker cycling
    #: through principals (A6 again, one level up).
    max_tracked_principals: int = 100_000

    def validate(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("config: rate.rate_per_second must be positive")
        if self.burst < 1:
            raise ValueError("config: rate.burst must be at least 1")
        if self.max_tracked_principals < 1:
            raise ValueError("config: rate.max_tracked_principals must be positive")


class RateLimiter:
    """Per-principal token-bucket limiter with a bounded table."""

    def __init__(self, config: RateLimitConfig,
                 clock: Callable[[], float] | None = None) -> None:
        self._cfg = config
        self._clock = clock or time.monotonic
        self._buckets: dict[str, TokenBucket] = {}
        self.allowed = 0
        self.limited = 0
        self.evictions = 0

    def allow(self, principal: str) -> bool:
        """True if this request is within budget for `principal`."""
        if not self._cfg.enabled:
            return True
        now = self._clock()
        bucket = self._buckets.get(principal)
        if bucket is None:
            if len(self._buckets) >= self._cfg.max_tracked_principals:
                # Table full. Evict the least-recently-seen bucket rather than
                # growing without bound. An attacker cycling principals pays
                # with their own evictions, not our memory.
                oldest = min(self._buckets, key=lambda k: self._buckets[k].last)
                del self._buckets[oldest]
                self.evictions += 1
            bucket = TokenBucket(capacity=self._cfg.burst,
                                 rate=self._cfg.rate_per_second)
            self._buckets[principal] = bucket
        ok = bucket.take(now)
        if ok:
            self.allowed += 1
        else:
            self.limited += 1
        return ok

    def snapshot(self) -> dict[str, int]:
        return {"allowed": self.allowed, "limited": self.limited,
                "tracked_principals": len(self._buckets),
                "evictions": self.evictions}


@dataclass(slots=True)
class BreakerState:
    tripped: bool = False
    unavailable_rate_pct: float = 0.0
    samples: int = 0
    conclusive: bool = False


@dataclass(frozen=True, slots=True)
class CircuitBreakerConfig:
    enabled: bool = True
    #: Trip when this fraction of recent requests saw a detector unavailable.
    trip_threshold_pct: float = 25.0
    #: Minimum samples before the breaker will trip, so a cold start or a
    #: handful of errors cannot flip it.
    min_samples: int = 50
    #: Rolling window.
    window: int = 500
    #: How long to stay tripped before probing recovery, in seconds.
    cooldown_seconds: float = 30.0

    def validate(self) -> None:
        if not 0.0 < self.trip_threshold_pct <= 100.0:
            raise ValueError("config: breaker.trip_threshold_pct must be in (0,100]")
        if self.window < self.min_samples:
            raise ValueError("config: breaker.window must be >= min_samples")


class CircuitBreaker:
    """Trips when detector unavailability is sustained, degrading cost.

    This does NOT loosen detection. A tripped breaker means "a stage is failing,
    stop paying its cost and run with the stages that still work, loudly." It is
    the T5 discipline: the degraded mode is a declared, observed state, not an
    accident. Like the decision engine's budget, it never *weakens* a block —
    an attacker who could trip it by causing errors must not thereby disable
    detection.
    """

    def __init__(self, config: CircuitBreakerConfig | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self._cfg = config or CircuitBreakerConfig()
        self._clock = clock or time.monotonic
        self._recent: list[bool] = []
        self._tripped_at: float = 0.0
        self.trips = 0

    def record(self, any_unavailable: bool) -> None:
        if not self._cfg.enabled:
            return
        self._recent.append(any_unavailable)
        if len(self._recent) > self._cfg.window:
            self._recent.pop(0)
        state = self._state()
        if state.tripped and self._tripped_at == 0.0:
            self._tripped_at = self._clock()
            self.trips += 1

    def _state(self) -> BreakerState:
        n = len(self._recent)
        if n == 0:
            return BreakerState()
        pct = sum(self._recent) / n * 100
        conclusive = n >= self._cfg.min_samples
        # Once tripped, stay tripped until the cooldown elapses, regardless of
        # the instantaneous rate, so the breaker does not flap.
        if self._tripped_at and (self._clock() - self._tripped_at
                                 < self._cfg.cooldown_seconds):
            return BreakerState(True, pct, n, conclusive)
        tripped = conclusive and pct >= self._cfg.trip_threshold_pct
        return BreakerState(tripped, pct, n, conclusive)

    def tripped(self) -> bool:
        state = self._state()
        if self._tripped_at and not state.tripped:
            # Cooldown elapsed and the rate recovered: reset.
            self._tripped_at = 0.0
        return state.tripped

    def snapshot(self) -> dict[str, float | int | bool]:
        state = self._state()
        return {"tripped": state.tripped,
                "unavailable_rate_pct": round(state.unavailable_rate_pct, 4),
                "samples": state.samples, "conclusive": state.conclusive,
                "trips": self.trips}
