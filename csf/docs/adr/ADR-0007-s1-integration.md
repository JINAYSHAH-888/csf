# ADR-0007 — S1 via a Coraza sidecar over a Unix socket

**Status:** Accepted (Phase 3) · **Date:** 2026-10-01
**Resolves:** the open S1 question left by ADR-0006

## Context
ADR-0006 moved the backend to Python and listed three ways to get CRS
evaluation, explicitly refusing to pick one without measuring:

1. `pymodsecurity` / libmodsecurity bindings, in-process
2. Coraza as a sidecar over a local socket
3. nginx + ModSecurity as a front tier

## Evidence

**Option 1 is not available on our platform — measured.**
`pip install libmodsecurity` fails: PyPI ships manylinux wheels for Python
3.9–3.13 only, and our host is macOS arm64 / Python 3.14. The source build
fails at CMake configuration with `libmodsecurity not found`. The upstream
`pymodsecurity` project also describes itself as alpha with crashes expected.
Not viable now; revisit if a Linux-only deployment target is chosen.

**Option 2 measured.** A ~300-line Go sidecar embedding Coraza v3.8.0 with
CRS v4.21.0, speaking JSON over a Unix domain socket.

| Metric | p50 | p95 | p99 |
|---|---|---|---|
| CRS engine time | 1050 µs | 1608 µs | 2242 µs |
| End-to-end from Python | 1451 µs | 2050 µs | 3246 µs |
| **IPC overhead** | **~422 µs mean (28% of total)** | | |

**Option 3** was not benchmarked. It adds a whole nginx tier for the same
engine and a worse integration story; it remains the fallback if the sidecar
proves operationally awkward.

## Decision
Option 2. A Go sidecar (`s1-sidecar/`) evaluates CRS and returns a **graded
signal**; the Python gateway calls it over a Unix domain socket.

Design points:
- Unix socket, mode 0600. No TCP, no network exposure; filesystem permissions
  are the access control. Anything that can reach the socket can ask the
  engine about arbitrary payloads.
- The sidecar never re-parses raw HTTP. It is handed the request as S0 already
  parsed it, so the gateway and the engine cannot disagree about what the
  request was (threat model T3).
- `SecRuleEngine DetectionOnly`. The sidecar reports; the gateway decides.
- Returns **two** scores (see below).

## The two-score finding
CRS evaluates blocking at `blocking_paranoia_level` and reports that total in
rule 949110, but detection-only rules at higher paranoia levels keep
accumulating afterwards. Measured on one SQLi tautology: **blocking score 5,
detection score 40.** Reporting a single number conflates them.

The sidecar now returns `blocking_score`, `detection_score`, and the per-PL
breakdown. CSF thresholds on the detection score — a 3–8× richer signal —
and reports the blocking score so a classic CRS deployment can be compared
against. This is ADR-0004's thesis confirmed with real numbers.

## Trade-offs
**Cost:** ~422 µs of IPC per request, 28% of S1's total. ADR-0001 rejected
this hop *unmeasured*; measured, it is affordable inside a 10 ms budget.
**Cost:** a second language and a second process to deploy and supervise.
**Gain:** the mature, CRS-compatible engine, with no dependency on an alpha
binding that does not build.

## Reversal strategy
`S1RulesDetector` implements the `Detector` protocol and talks to the sidecar
only through `evaluate_signal()`. Swapping to in-process bindings (if a Linux
target makes them viable) or to an nginx tier means replacing that one method.

## Sources
- Measured `pip install libmodsecurity` failure, 2026-10-01
- Coraza v3.8.0 (Apache-2.0), CRS v4.21.0
- `docs/benchmarks/s1-baseline.json`
