"""S0 admission control and circuit breaker (Phase 9/10, ADR-0013)."""

from __future__ import annotations

import pytest

from csf.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    RateLimitConfig,
    RateLimiter,
)


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


# -- rate limiter ----------------------------------------------------------

def test_disabled_limiter_allows_everything():
    rl = RateLimiter(RateLimitConfig(enabled=False, rate_per_second=1, burst=1))
    assert all(rl.allow("ip") for _ in range(1000))


def test_burst_is_bounded_by_capacity():
    clock = FakeClock()
    rl = RateLimiter(RateLimitConfig(enabled=True, rate_per_second=1, burst=5), clock)
    # No time passes: only `burst` requests get through.
    results = [rl.allow("ip") for _ in range(10)]
    assert results.count(True) == 5
    assert results.count(False) == 5


def test_tokens_refill_over_time():
    clock = FakeClock()
    rl = RateLimiter(RateLimitConfig(enabled=True, rate_per_second=10, burst=2), clock)
    assert rl.allow("ip") and rl.allow("ip")      # drain the burst
    assert not rl.allow("ip")                      # empty
    clock.advance(0.5)                             # 0.5s * 10/s = 5 tokens
    assert rl.allow("ip")


def test_principals_are_independent():
    clock = FakeClock()
    rl = RateLimiter(RateLimitConfig(enabled=True, rate_per_second=1, burst=1), clock)
    assert rl.allow("a")
    assert rl.allow("b"), "one principal exhausting its bucket must not affect another"
    assert not rl.allow("a")


def test_table_is_bounded_and_evicts():
    clock = FakeClock()
    rl = RateLimiter(RateLimitConfig(enabled=True, rate_per_second=1, burst=1,
                                     max_tracked_principals=3), clock)
    for i in range(10):
        clock.advance(1.0)
        rl.allow(f"ip-{i}")
    snap = rl.snapshot()
    assert snap["tracked_principals"] <= 3, "the limiter must not grow without bound"
    assert snap["evictions"] >= 7


@pytest.mark.parametrize("bad", [
    {"rate_per_second": 0}, {"burst": 0}, {"max_tracked_principals": 0},
])
def test_rate_config_validation(bad):
    with pytest.raises(ValueError):
        RateLimitConfig(**bad).validate()


# -- circuit breaker -------------------------------------------------------

def test_breaker_does_not_trip_before_min_samples():
    cb = CircuitBreaker(CircuitBreakerConfig(trip_threshold_pct=10, min_samples=50,
                                             window=500))
    for _ in range(40):
        cb.record(any_unavailable=True)    # 100% unavailable, but n<min
    assert not cb.tripped()


def test_breaker_trips_on_sustained_unavailability():
    cb = CircuitBreaker(CircuitBreakerConfig(trip_threshold_pct=25, min_samples=50,
                                             window=500))
    for _ in range(40):
        cb.record(any_unavailable=True)
    for _ in range(60):
        cb.record(any_unavailable=False)
    # 40/100 = 40% >= 25% with n>=50 → tripped.
    assert cb.tripped()
    assert cb.snapshot()["trips"] == 1


def test_breaker_stays_tripped_through_cooldown_then_resets():
    clock = FakeClock()
    cb = CircuitBreaker(CircuitBreakerConfig(trip_threshold_pct=25, min_samples=10,
                                             window=500, cooldown_seconds=30), clock)
    for _ in range(50):
        cb.record(any_unavailable=True)
    assert cb.tripped()
    # Even if everything recovers instantly, it holds through cooldown (no flap).
    for _ in range(500):
        cb.record(any_unavailable=False)
    assert cb.tripped()
    clock.advance(31)
    assert not cb.tripped(), "after cooldown with a recovered rate it resets"


def test_disabled_breaker_never_trips():
    cb = CircuitBreaker(CircuitBreakerConfig(enabled=False, min_samples=1))
    for _ in range(100):
        cb.record(any_unavailable=True)
    assert not cb.tripped()
