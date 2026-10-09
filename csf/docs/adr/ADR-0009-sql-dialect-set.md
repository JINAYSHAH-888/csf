# ADR-0009 — S2 probes three SQL dialects, not four: Oracle rejected on measurement

**Status:** Accepted (post-Phase 6) · **Date:** 2026-10-07

## Context

`DIALECTS = ("mysql", "postgres", "tsql")`. The Phase 6b report named adding
`oracle` as the next experiment for S2's SQL analyser, on the hypothesis that
Oracle-flavoured payloads in the ECML residual — notably the string-concatenation
shape `'select a '||'from b '||'where c='''||v||''''` — were missed because no
Oracle parser was consulted.

Adding a dialect is not free. `analyze_sql` escalates to every non-primary
dialect whenever the first pass finds something or the value carries injection
syntax, so a fourth dialect adds a full pass over all five contexts.

## Decision

**Do not add `oracle`.** The hypothesis was wrong and the cost is real.

## Measurement

`oracle` was added, all 20 (context × dialect) baselines resolved, and the
suite and both corpora were re-run.

**Detection: identical everywhere.** Not "within noise" — bit-identical.

| | 3 dialects | 4 dialects |
|---|---|---|
| CSIC recall @ `tau_block` | 57.7% | 57.7% |
| ECML recall @ `tau_block` | 56.3% | 56.3% |
| CSIC FPR | 0.00% | 0.00% |
| ECML FPR | 3.43% | 3.43% |
| per-class recall, all 5 classes, both corpora | — | unchanged in every cell |

**Latency: materially worse.** Two runs with oracle, one without:

| | p50 | p95 | p99 |
|---|---|---|---|
| 3 dialects | 2,626µs | 6,001µs | 7,420µs |
| 4 dialects (run 1) | 3,352µs | 8,638µs | 13,475µs |
| 4 dialects (run 2) | 3,217µs | 7,684µs | 9,520µs |

p99 is noisy between the two oracle runs, so the defensible figure is p50:
**+23% to +28%, well outside run-to-run variation.**

## Why it changed nothing

sqlglot's `mysql`, `postgres` and `tsql` parsers already accept Oracle-flavoured
syntax. A hand-built set of ten Oracle-specific payloads — `UTL_INADDR`,
`v$version`, `all_tables`, `DBMS_PIPE`, `ROWNUM`, `FROM dual`,
`BEGIN DBMS_LOCK.SLEEP(5); END;`, `UTL_HTTP.REQUEST` — scores **10/10 blocked
with identical scores** whether or not `oracle` is in `DIALECTS`.

The original hypothesis was also wrong about the payload that motivated it: the
`||`-concatenation value fails to parse in **all four** dialects, oracle
included. It is defeated by quote nesting, not by dialect coverage.

## Consequences

- The dialect set stays at three. `test_dialect_set_is_the_measured_three`
  guards it, so a re-addition has to come with its own measurement.
- `test_oracle_payloads_are_caught_without_an_oracle_dialect` asserts the ten
  payloads above. This pins a property of **sqlglot**, not of CSF: if an
  upstream release tightens those parsers, the test fails and this decision is
  revisited on evidence rather than silently leaving Oracle payloads undetected.
- Generalises: "add another dialect" is not free coverage. Any future dialect
  must show a detection delta on payloads the current three miss, not merely be
  plausible.
