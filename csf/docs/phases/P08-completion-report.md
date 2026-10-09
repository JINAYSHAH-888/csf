# Phase 8 — Adversarial Lab — Completion Report

**Date:** 2026-10-08 · **Deliverables:** `csf/adversarial.py`,
`scripts/measure_adversarial.py`, `tests/test_adversarial.py` · **ADR:** ADR-0012

---

## 1. What the phase was for

Produce the evasion number the threat model (T1) commits to — ≤15% for
black-box mutation (adversary A3, WAF-A-MoLE class) — against our own gateway
on localhost. The job is to measure honestly and to turn any bypass found into
a permanent regression test, not to tune until the gate passes.

## 2. Method, and the oracle mistake that would have faked the result

Seed payloads that CSF blocks are mutated into many variants by
semantics-preserving operators (case, inline/terminating comments, whitespace,
numeric rewrites). A variant **evades** if the stage that blocked the seed no
longer blocks the variant.

The load-bearing question is: did the mutation keep the payload an *attack*? A
variant that evades by no longer being valid SQL is a broken string, and
counting it would inflate the rate with noise.

**The first oracle was built on sqlglot and it was a trap.** sqlglot is the
parser S2 detects with, so an oracle that accepts only mutations sqlglot still
reads as attacks can accept only mutations S2 still blocks. It is structurally
incapable of finding an S2 evasion. The first harness run reported 0% against
both stages — a worthless 0%.

The oracle was rebuilt on **sqlite3 execution**: interpolate the payload into a
query, run it, and compare to the same payload bound as a parameter. Different
outcome ⇒ the payload escaped its data position ⇒ injection, judged by a parser
that shares no code with S2. See ADR-0012.

Three measurement planes, all against our own code: S2 in-process, S1 via the
sidecar socket, and the full cascade over loopback to the containerised gateway
in enforce mode.

## 3. Result

| plane | variants | evasions | rate | gate ≤15% |
|---|---|---|---|---|
| **pre-fix** S2 grammar | 425 | 31 | **7.3%** | PASS |
| **pre-fix** S1 regex | 425 | 0 | 0.0% | PASS |
| **pre-fix** full cascade (enforce) | 425 | 0 | **0.0%** | PASS |

The headline is not the 7.3%, it is the *shape* of the three rows. No single
stage is robust — S2 has a real 7.3% blind spot — but the cascade is 0%,
because the stages fail in opposite directions. The grammar analyser is blind
to exactly the construct the regex layer catches outright. The cascade's
founding thesis, observed under attack.

## 4. The vulnerability

All 31 S2 evasions were one shape: an **unterminated `/*`** at the end of the
payload. sqlglot cannot parse the dangling comment and S2 scores 0; sqlite
treats `/*` as a comment to end-of-input and executes the attack before it.
`x' UNION SELECT NULL,NULL/*` is canonical. This is a parser differential — the
bypass class T3 calls the most likely real one — and S2's own docstring had
suspected it (`x' OR 'a'='a' /*`) since Phase 2 without it being measured.

## 5. The fix

`csf/semantic/sql.py` analyses the backend-tolerant reading of a dangling `/*`
by rewriting it as a line comment (reproducing "comment to end of input") and
re-probing — mirroring the traversal analyser's multi-view design.

| metric | before | after |
|---|---|---|
| S2 mutation evasion (default search) | 7.3% | **0.0%** |
| S2 evasion, deep search (seeds 7, 99) | — | **0/20639, 0/18045** |
| CSIC FPR @ tau_block | 0.00% | 0.00% |
| ECML FPR @ tau_block | 3.43% | 3.43% |
| CSIC / ECML recall @ tau_block | 57.7 / 56.3% | 57.7 / 56.3% |
| S2 p50 latency | 2618µs | 2659µs (+1.6%) |

Corpus recall is unchanged because the corpora contain no dangling-`/*`
payloads — precisely why adversarial testing is a distinct discipline from
corpus evaluation: it closes gaps a labelled corpus cannot show.

## 6. Exit gates

| gate | result |
|---|---|
| Mutation evasion ≤15% (system / cascade) | **PASS** — 0.0% |
| Mutation evasion ≤15% (S2 alone) | **PASS** — 7.3% pre-fix, 0.0% after |
| Evasion rate measured with an oracle independent of the detector | **PASS** — sqlite execution, not sqlglot |
| Every vulnerability found becomes a regression test | **PASS** — 31 evasions + oracle correctness pinned |
| Fix must not cost FPR on either corpus | **PASS** — unchanged |
| Harness attacks our own infrastructure only | **PASS** — loopback-only, enforced in code |
| A4 generative-SQLi ≤20% | **NOT MEASURED** — see §7 |

## 7. Carried forward / not claimed

- **Not unevadability.** 0% is for six operators at bounded depth. A richer or
  gradient-guided adversary is stronger and untested.
- **SQL only.** No mutation operators or execution oracle for XSS, shell,
  traversal yet.
- **A4 generative SQLi (≤20% gate) unmeasured** — needs a generator, not a
  mutator.
- **One backend (sqlite).** Differentials unique to MySQL/Postgres/MSSQL
  leniencies are out of this harness's reach; that is Phase 11 differential
  fuzzing territory.
- Frozen CSIC test holdout still untouched.

## 8. Verification

- 544 tests (503 before; 41 added), `ruff` and `mypy --strict` clean.
- Pre/post-fix evasion measured by the same harness in one session; the
  "fixed" claim rests on the before/after, not a remembered number.
- Full cascade verified end-to-end through the containerised gateway in enforce
  mode (benign passes, every surviving attack variant 403s).
