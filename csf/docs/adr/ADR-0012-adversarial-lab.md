# ADR-0012 — Adversarial evaluation by mutation, with an execution oracle

**Status:** Accepted (Phase 8) · **Date:** 2026-10-08

## Context

The threat model commits (T1) to *measured* evasion rates rather than a claim
of unevadability: ≤15% for black-box mutation (A3, the WAF-A-MoLE class). Phase
8 had to build the instrument that produces that number, against our own
gateway on localhost only.

WAF-A-MoLE itself is a guided mutation fuzzer. Rather than vendor it (and take
on its dependency surface and a licence review for a result we can produce
directly), Phase 8 implements the same idea — semantics-preserving mutation of
seed payloads — as a small in-tree module, `csf/adversarial.py`.

## The decision that makes the number mean something

A mutation is only an evasion if the payload **still attacks**. The first
instinct was to check that with sqlglot — parse the mutated payload, confirm it
still contains an attack construct. That is wrong, and measuring it would have
been self-deception:

> sqlglot is the parser S2 detects with. An oracle built on sqlglot can only
> accept mutations that sqlglot still sees as attacks — which is exactly when
> S2 still blocks them. Such an oracle can never find an S2 evasion. It would
> report 0% and the 0% would be an artifact of the oracle, not a property of
> the firewall.

The first harness run did exactly this and reported 0% evasion against both S1
and S2. That 0% was worthless.

**The oracle must be an independent parser.** Phase 8 uses sqlite3 execution:
the mutated payload is interpolated into a query and run against a throwaway
in-memory database, and compared against the same payload bound as a
*parameter*. If the two outcomes differ, the payload left its data position and
changed the query — the definition of injection — established by a parser
(sqlite) that shares no code with the one under test (sqlglot). A mutation that
evades S2 but still executes in sqlite is a genuine parser differential, the
bypass class T3 names as the most likely real one.

With the honest oracle, the same harness reported **7.3% S2 evasion**, and the
gap was real.

## What it found

31 of 425 surviving mutations evaded S2, all one shape: an **unterminated
`/*`** comment at the end of the payload. sqlglot fails to parse the dangling
comment and S2 scores 0; sqlite (and MySQL, for a `/*` that reaches end of
input) treats it as a comment to end-of-input and runs the attack before it.
`x' UNION SELECT NULL,NULL/*` is the canonical case. S2's own docstring had
flagged `x' OR 'a'='a' /*` as a suspected miss since Phase 2; Phase 8 confirmed
and measured the class.

**S1 (CRS regex) evaded at 0% on the identical variants.** The stages fail in
opposite directions: the grammar analyser is blind to the dangling comment that
the regex layer catches outright. The full cascade, measured end-to-end through
the containerised gateway in enforce mode, evaded at **0%** — S1 covers exactly
S2's blind spot. This is the cascade's central thesis, observed under attack
rather than asserted.

## The fix

`csf/semantic/sql.py` now analyses the **backend-tolerant reading** of a value:
when a dangling `/*` is present, it also probes the value with that comment
rewritten as a line comment, which reproduces the "comment to end of input"
effect the attacker relies on and restores the shape S2 already detects. This
mirrors the traversal analyser's multi-view approach (analyse each decoding an
attacker could rely on, do not pick one).

Measured consequences:
- S2 mutation evasion 7.3% → **0%**, and 0% held under a deeper search of
  **20,639** and **18,045** variants across two seeds.
- FPR on both corpora **unchanged**: CSIC 0.00%, ECML 3.43%.
- Corpus recall unchanged — the corpora contain no dangling-`/*` payloads,
  which is the whole reason adversarial testing exists: it closes a gap no
  labelled corpus reveals.
- Latency +1.6% p50 (the extra view runs only when a `/*` actually dangles).

## Consequences

- `csf/adversarial.py` (mutation operators + sqlite oracle) and
  `scripts/measure_adversarial.py` (three measurement planes: S2 in-process, S1
  via the sidecar, full gateway over loopback) are permanent.
- The harness refuses any non-loopback gateway target. It generates strings; it
  sends them only to 127.0.0.1.
- The 31 evasions became regression tests (`tests/test_adversarial.py`), as did
  the oracle's own correctness — a drifting oracle would make a green suite
  meaningless.

## Known limitations (this does NOT claim unevadability)

- **Six operators, bounded depth.** 0% means this operator set no longer evades,
  not that CSF is unevadable. A richer operator set or a gradient-guided search
  (WAF-A-MoLE proper) is a stronger adversary and is not implemented.
- **SQL only.** XSS, shell and traversal have no mutation operators or execution
  oracle yet. The method extends to them; the work does not exist.
- **sqlite is one backend.** Its leniencies are not MySQL's or Postgres's. A
  differential against a backend sqlite does not model is not found here.
- **A4 (generative SQLi, the GenSQLi ≤20% target) is not measured.** That needs
  a generator, not a mutator, and is carried forward.
- Execution oracle ≠ exploitability: a query whose result changes is an
  injection, but not every injection found is independently weaponisable.
